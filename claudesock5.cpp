#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <mutex>
#include <map>
#include <string>
#include <chrono>
#include <unordered_map>
#include <memory>
#include <fstream>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <cstring>
#include <errno.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

enum class LogLevel { DEBUG, INFO, WARNING, ERROR };
enum class ConnectionState {
    HANDSHAKE,
    AUTHENTICATION,
    REQUEST,
    FORWARDING,
    CLOSING
};

// Logger implementation
class Logger {
private:
    LogLevel min_level_;
    std::string log_file_;
    std::mutex log_mutex_;

public:
    Logger(LogLevel level, const std::string& file)
        : min_level_(level), log_file_(file) {}

    void log(LogLevel level, const std::string& message, const std::string& client_ip = "") {
        if (level < min_level_) return;

        std::lock_guard<std::mutex> lock(log_mutex_);
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);

        std::string level_str;
        switch (level) {
            case LogLevel::DEBUG: level_str = "DEBUG"; break;
            case LogLevel::INFO: level_str = "INFO"; break;
            case LogLevel::WARNING: level_str = "WARNING"; break;
            case LogLevel::ERROR: level_str = "ERROR"; break;
        }

        std::string log_entry = "[" + std::string(std::ctime(&time_t));
        log_entry.pop_back(); // Remove newline
        log_entry += "] [" + level_str + "] ";
        if (!client_ip.empty()) {
            log_entry += "[" + client_ip + "] ";
        }
        log_entry += message + "\n";

        std::cout << log_entry;

        std::ofstream file(log_file_, std::ios::app);
        if (file.is_open()) {
            file << log_entry;
        }
    }
};

struct ProxyStats {
    std::atomic<uint64_t> total_connections{0};
    std::atomic<uint64_t> active_connections{0};
    std::atomic<uint64_t> bytes_transferred{0};
    std::atomic<uint64_t> failed_connections{0};
    std::atomic<uint64_t> successful_connections{0};
};

struct ConnectionInfo {
    int fd;
    ConnectionState state;
    std::string client_ip;
    std::string target_host;
    uint16_t target_port;
    time_t created_at;
    time_t last_activity;
    int target_fd;  // Associated target connection
    bool is_client_socket; // true if this is client socket, false if target socket

    ConnectionInfo() : fd(-1), state(ConnectionState::HANDSHAKE),
                      target_port(0), created_at(0), last_activity(0),
                      target_fd(-1), is_client_socket(true) {}
};

// Utility functions
bool matches_cidr(const std::string& ip, const std::string& cidr) {
    if (cidr == "0.0.0.0/0") return true;

    size_t slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos) {
        return ip == cidr;
    }

    std::string network = cidr.substr(0, slash_pos);
    int prefix_len = std::stoi(cidr.substr(slash_pos + 1));

    // Simple implementation - for production use a proper CIDR library
    if (prefix_len == 0) return true;

    struct sockaddr_in ip_addr, network_addr;
    if (inet_pton(AF_INET, ip.c_str(), &ip_addr.sin_addr) != 1 ||
        inet_pton(AF_INET, network.c_str(), &network_addr.sin_addr) != 1) {
        return ip == network; // Fallback to string comparison
    }

    uint32_t mask = htonl(~((1U << (32 - prefix_len)) - 1));
    return (ip_addr.sin_addr.s_addr & mask) == (network_addr.sin_addr.s_addr & mask);
}

class Socks5Server {
private:
    int epoll_fd_;
    int server_socket_;
    std::atomic<bool> running_{false};
    std::thread epoll_thread_;
    std::mutex rate_limit_mtx_;
    std::mutex acl_mtx_;

    std::unique_ptr<Logger> logger_;
    ProxyStats stats_;

    std::string username_;
    std::string password_;
    bool auth_required_;

    std::vector<std::string> allowed_destinations_;
    std::vector<std::string> blocked_destinations_;

    struct ClientRateInfo {
        std::chrono::steady_clock::time_point last_connection;
        int connection_count;
    };
    std::map<std::string, ClientRateInfo> client_connections_;
    int max_connections_per_minute_;

    std::mutex connections_mutex_;
    std::unordered_map<int, ConnectionInfo> connections_;

public:
    Socks5Server(const std::string& username = "", const std::string& password = "",
                int max_connections = 60)
        : epoll_fd_(-1), server_socket_(-1), username_(username), password_(password),
          max_connections_per_minute_(max_connections) {
        auth_required_ = !username_.empty() || !password_.empty();

        // Default ACL - allow everything
        allowed_destinations_.push_back("0.0.0.0/0");

        logger_ = std::make_unique<Logger>(LogLevel::INFO, "socks5.log");
    }

    ~Socks5Server() {
        stop();
    }

    void set_allowed_destinations(const std::vector<std::string>& destinations) {
        std::lock_guard<std::mutex> lock(acl_mtx_);
        allowed_destinations_ = destinations;
    }

    void set_blocked_destinations(const std::vector<std::string>& destinations) {
        std::lock_guard<std::mutex> lock(acl_mtx_);
        blocked_destinations_ = destinations;
    }

    bool start(int port) {
        server_socket_ = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket_ < 0) {
            logger_->log(LogLevel::ERROR, "Socket creation failed: " + std::string(strerror(errno)));
            return false;
        }

        int opt = 1;
        if (setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            logger_->log(LogLevel::ERROR, "Setsockopt failed: " + std::string(strerror(errno)));
            close(server_socket_);
            return false;
        }

        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(port);

        if (bind(server_socket_, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            logger_->log(LogLevel::ERROR, "Bind failed: " + std::string(strerror(errno)));
            close(server_socket_);
            return false;
        }

        if (listen(server_socket_, 1024) < 0) {
            logger_->log(LogLevel::ERROR, "Listen failed: " + std::string(strerror(errno)));
            close(server_socket_);
            return false;
        }

        epoll_fd_ = epoll_create1(0);
        if (epoll_fd_ < 0) {
            logger_->log(LogLevel::ERROR, "Epoll creation failed: " + std::string(strerror(errno)));
            close(server_socket_);
            return false;
        }

        epoll_event ev{};
        ev.events = EPOLLIN | EPOLLET;
        ev.data.fd = server_socket_;
        if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, server_socket_, &ev) < 0) {
            logger_->log(LogLevel::ERROR, "Epoll_ctl failed: " + std::string(strerror(errno)));
            close(server_socket_);
            close(epoll_fd_);
            return false;
        }

        running_ = true;
        epoll_thread_ = std::thread(&Socks5Server::epoll_loop, this);

        logger_->log(LogLevel::INFO, "SOCKS5 proxy listening on port " + std::to_string(port));
        if (auth_required_) {
            logger_->log(LogLevel::INFO, "Authentication enabled for user: " + username_);
        }

        return true;
    }

    void stop() {
        running_ = false;

        if (server_socket_ >= 0) {
            close(server_socket_);
            server_socket_ = -1;
        }

        if (epoll_fd_ >= 0) {
            close(epoll_fd_);
            epoll_fd_ = -1;
        }

        if (epoll_thread_.joinable()) {
            epoll_thread_.join();
        }

        // Close all connections
        std::lock_guard<std::mutex> lock(connections_mutex_);
        for (auto& [fd, conn] : connections_) {
            if (conn.target_fd >= 0 && conn.target_fd != fd) {
                close(conn.target_fd);
            }
            close(fd);
        }
        connections_.clear();
    }

    ProxyStats get_stats() const {
        return stats_;
    }

private:
    void epoll_loop() {
        const int MAX_EVENTS = 64;
        epoll_event events[MAX_EVENTS];

        while (running_) {
            int nfds = epoll_wait(epoll_fd_, events, MAX_EVENTS, 1000);
            if (nfds < 0) {
                if (errno == EINTR) continue;
                logger_->log(LogLevel::ERROR, "Epoll_wait failed: " + std::string(strerror(errno)));
                break;
            }

            for (int i = 0; i < nfds; ++i) {
                if (events[i].data.fd == server_socket_) {
                    handle_new_connection();
                } else {
                    handle_client_event(events[i]);
                }
            }

            // Periodic cleanup every 10 iterations (roughly every 10 seconds)
            static int cleanup_counter = 0;
            if (++cleanup_counter >= 10) {
                cleanup_old_connections();
                cleanup_counter = 0;
            }
        }
    }

    void handle_new_connection() {
        while (true) {
            sockaddr_in client_addr{};
            socklen_t client_len = sizeof(client_addr);
            int client_socket = accept4(server_socket_, (sockaddr*)&client_addr,
                                      &client_len, SOCK_NONBLOCK);
            if (client_socket < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }
                logger_->log(LogLevel::ERROR, "Accept failed: " + std::string(strerror(errno)));
                break;
            }

            std::string client_ip = inet_ntoa(client_addr.sin_addr);
            if (!check_rate_limit(client_ip)) {
                logger_->log(LogLevel::WARNING, "Rate limit exceeded", client_ip);
                close(client_socket);
                stats_.failed_connections++;
                continue;
            }

            epoll_event event{};
            event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
            event.data.fd = client_socket;
            if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, client_socket, &event) < 0) {
                logger_->log(LogLevel::ERROR, "Failed to add client to epoll: " +
                           std::string(strerror(errno)), client_ip);
                close(client_socket);
                stats_.failed_connections++;
                continue;
            }

            ConnectionInfo conn_info;
            conn_info.fd = client_socket;
            conn_info.state = ConnectionState::HANDSHAKE;
            conn_info.client_ip = client_ip;
            conn_info.created_at = time(nullptr);
            conn_info.last_activity = time(nullptr);
            conn_info.is_client_socket = true;

            {
                std::lock_guard<std::mutex> lock(connections_mutex_);
                connections_[client_socket] = conn_info;
            }

            stats_.total_connections++;
            stats_.active_connections++;
            logger_->log(LogLevel::INFO, "New connection", client_ip);
        }
    }

    void handle_client_event(const epoll_event& event) {
        int fd = event.data.fd;

        std::unique_lock<std::mutex> lock(connections_mutex_);
        auto it = connections_.find(fd);
        if (it == connections_.end()) {
            return;
        }

        ConnectionInfo& conn_info = it->second;
        conn_info.last_activity = time(nullptr);

        if (event.events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)) {
            lock.unlock();
            close_connection(fd, "Connection closed or error");
            return;
        }

        // Handle data forwarding for established connections
        if (conn_info.state == ConnectionState::FORWARDING) {
            lock.unlock();
            handle_forwarding(fd, event.events);
            return;
        }

        lock.unlock();

        // Handle SOCKS5 protocol states
        try {
            switch (conn_info.state) {
                case ConnectionState::HANDSHAKE:
                    handle_handshake(fd);
                    break;
                case ConnectionState::AUTHENTICATION:
                    handle_authentication(fd);
                    break;
                case ConnectionState::REQUEST:
                    handle_request(fd);
                    break;
                case ConnectionState::CLOSING:
                    close_connection(fd, "Closing state");
                    break;
                default:
                    break;
            }
        } catch (const std::exception& e) {
            logger_->log(LogLevel::ERROR, "Error handling connection: " + std::string(e.what()),
                       conn_info.client_ip);
            close_connection(fd, "Exception: " + std::string(e.what()));
        }
    }

    void handle_handshake(int client_socket) {
        unsigned char buffer[256];
        ssize_t bytes_read = recv(client_socket, buffer, 2, 0);
        if (bytes_read != 2 || buffer[0] != 0x05) {
            close_connection(client_socket, "Invalid handshake");
            return;
        }

        uint8_t nmethods = buffer[1];
        if (nmethods == 0) {
            close_connection(client_socket, "No authentication methods");
            return;
        }

        bytes_read = recv(client_socket, buffer, nmethods, 0);
        if (bytes_read != nmethods) {
            close_connection(client_socket, "Failed to read auth methods");
            return;
        }

        bool no_auth_supported = false;
        bool userpass_auth = false;
        for (int i = 0; i < nmethods; ++i) {
            if (buffer[i] == 0x00) {
                no_auth_supported = true;
            } else if (buffer[i] == 0x02) {
                userpass_auth = true;
            }
        }

        uint8_t selected_method;
        ConnectionState next_state;

        if (auth_required_ && userpass_auth) {
            selected_method = 0x02;
            next_state = ConnectionState::AUTHENTICATION;
        } else if (!auth_required_ && no_auth_supported) {
            selected_method = 0x00;
            next_state = ConnectionState::REQUEST;
        } else {
            unsigned char response[] = {0x05, 0xFF};
            send(client_socket, response, sizeof(response), 0);
            close_connection(client_socket, "No supported auth method");
            return;
        }

        unsigned char response[] = {0x05, selected_method};
        if (send(client_socket, response, sizeof(response), 0) != sizeof(response)) {
            close_connection(client_socket, "Failed to send auth response");
            return;
        }

        // Update connection state
        std::lock_guard<std::mutex> lock(connections_mutex_);
        auto it = connections_.find(client_socket);
        if (it != connections_.end()) {
            it->second.state = next_state;
        }
    }

    void handle_authentication(int client_socket) {
        if (!perform_userpass_auth(client_socket)) {
            close_connection(client_socket, "Authentication failed");
            return;
        }

        std::lock_guard<std::mutex> lock(connections_mutex_);
        auto it = connections_.find(client_socket);
        if (it != connections_.end()) {
            it->second.state = ConnectionState::REQUEST;
        }
    }

    void handle_request(int client_socket) {
        unsigned char buffer[256];
        ssize_t bytes_read = recv(client_socket, buffer, 4, 0);
        if (bytes_read != 4 || buffer[0] != 0x05) {
            close_connection(client_socket, "Invalid request header");
            return;
        }

        uint8_t cmd = buffer[1];
        uint8_t atype = buffer[3];

        if (cmd != 0x01) {
            send_reply(client_socket, 0x07);
            close_connection(client_socket, "Command not supported");
            return;
        }

        std::string target_host;
        uint16_t target_port;

        if (atype == 0x01) { // IPv4
            bytes_read = recv(client_socket, buffer, 6, 0);
            if (bytes_read != 6) {
                close_connection(client_socket, "Failed to read IPv4 address");
                return;
            }
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, buffer, ip, sizeof(ip));
            target_host = ip;
            target_port = ntohs(*(uint16_t*)(buffer + 4));
        } else if (atype == 0x03) { // Domain name
            bytes_read = recv(client_socket, buffer, 1, 0);
            if (bytes_read != 1) {
                close_connection(client_socket, "Failed to read domain length");
                return;
            }
            uint8_t domain_len = buffer[0];
            bytes_read = recv(client_socket, buffer, domain_len + 2, 0);
            if (bytes_read != domain_len + 2) {
                close_connection(client_socket, "Failed to read domain");
                return;
            }
            target_host = std::string((char*)buffer, domain_len);
            target_port = ntohs(*(uint16_t*)(buffer + domain_len));
        } else {
            send_reply(client_socket, 0x08);
            close_connection(client_socket, "Address type not supported");
            return;
        }

        if (!check_acl(target_host)) {
            std::string client_ip;
            {
                std::lock_guard<std::mutex> lock(connections_mutex_);
                auto it = connections_.find(client_socket);
                if (it != connections_.end()) {
                    client_ip = it->second.client_ip;
                }
            }
            logger_->log(LogLevel::WARNING,
                        "ACL blocked connection to " + target_host + ":" + std::to_string(target_port),
                        client_ip);
            send_reply(client_socket, 0x02);
            close_connection(client_socket, "ACL denied");
            return;
        }

        int target_socket = connect_to_target(target_host, target_port);
        if (target_socket < 0) {
            send_reply(client_socket, 0x05);
            close_connection(client_socket, "Failed to connect to target");
            stats_.failed_connections++;
            return;
        }

        // Set target socket to non-blocking
        int flags = fcntl(target_socket, F_GETFL, 0);
        fcntl(target_socket, F_SETFL, flags | O_NONBLOCK);

        // Add target socket to epoll
        epoll_event ev{};
        ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
        ev.data.fd = target_socket;
        if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, target_socket, &ev) < 0) {
            close(target_socket);
            send_reply(client_socket, 0x05);
            close_connection(client_socket, "Failed to add target to epoll");
            return;
        }

        // Update connection info
        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            auto it = connections_.find(client_socket);
            if (it != connections_.end()) {
                it->second.target_host = target_host;
                it->second.target_port = target_port;
                it->second.target_fd = target_socket;
                it->second.state = ConnectionState::FORWARDING;
            }

            // Create connection info for target socket
            ConnectionInfo target_conn_info;
            target_conn_info.fd = target_socket;
            target_conn_info.state = ConnectionState::FORWARDING;
            target_conn_info.client_ip = it->second.client_ip;
            target_conn_info.target_host = target_host;
            target_conn_info.target_port = target_port;
            target_conn_info.created_at = time(nullptr);
            target_conn_info.last_activity = time(nullptr);
            target_conn_info.target_fd = client_socket;
            target_conn_info.is_client_socket = false;

            connections_[target_socket] = target_conn_info;
        }

        sockaddr_in local_addr{};
        socklen_t addr_len = sizeof(local_addr);
        getsockname(target_socket, (sockaddr*)&local_addr, &addr_len);
        send_reply(client_socket, 0x00, &local_addr);

        stats_.successful_connections++;

        std::string client_ip;
        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            auto it = connections_.find(client_socket);
            if (it != connections_.end()) {
                client_ip = it->second.client_ip;
            }
        }
        logger_->log(LogLevel::INFO,
                    "Connected to " + target_host + ":" + std::to_string(target_port),
                    client_ip);
    }

    void handle_forwarding(int fd, uint32_t events) {
        if (!(events & EPOLLIN)) {
            return;
        }

        char buffer[8192];
        ssize_t bytes = recv(fd, buffer, sizeof(buffer), 0);
        if (bytes <= 0) {
            if (bytes == 0) {
                close_connection(fd, "Connection closed by peer");
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                close_connection(fd, "Read error: " + std::string(strerror(errno)));
            }
            return;
        }

        int target_fd = -1;
        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            auto it = connections_.find(fd);
            if (it != connections_.end()) {
                target_fd = it->second.target_fd;
            }
        }

        if (target_fd < 0) {
            close_connection(fd, "No target connection");
            return;
        }

        ssize_t sent = 0;
        while (sent < bytes) {
            ssize_t result = send(target_fd, buffer + sent, bytes - sent, MSG_NOSIGNAL);
            if (result < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // Target socket buffer is full, could implement buffering here
                    break;
                } else {
                    close_connection(fd, "Write error: " + std::string(strerror(errno)));
                    return;
                }
            }
            sent += result;
        }

        stats_.bytes_transferred += sent;
    }

    void close_connection(int fd, const std::string& reason) {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        auto it = connections_.find(fd);
        if (it == connections_.end()) {
            return;
        }

        ConnectionInfo& conn_info = it->second;
        logger_->log(LogLevel::DEBUG, "Closing connection: " + reason, conn_info.client_ip);

        // Remove from epoll
        epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);

        // Handle paired connection
        if (conn_info.target_fd >= 0) {
            auto target_it = connections_.find(conn_info.target_fd);
            if (target_it != connections_.end()) {
                epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, conn_info.target_fd, nullptr);
                close(conn_info.target_fd);
                connections_.erase(target_it);
            }
        }

        close(fd);
        connections_.erase(it);

        if (conn_info.is_client_socket) {
            stats_.active_connections--;
        }
    }

    void cleanup_old_connections() {
        std::vector<int> to_close;
        time_t now = time(nullptr);

        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            for (const auto& [fd, conn] : connections_) {
                // Only check client connections for timeout (target connections will be closed with them)
                if (conn.is_client_socket && (now - conn.last_activity > 300)) { // 5 minutes timeout
                    to_close.push_back(fd);
                }
            }
        }

        for (int fd : to_close) {
            close_connection(fd, "Connection timeout");
        }

        // Clean up rate limiting map
        {
            std::lock_guard<std::mutex> lock(rate_limit_mtx_);
            auto now_steady = std::chrono::steady_clock::now();
            auto it = client_connections_.begin();
            while (it != client_connections_.end()) {
                auto time_diff = std::chrono::duration_cast<std::chrono::minutes>(
                    now_steady - it->second.last_connection);
                if (time_diff.count() > 10) { // Clean up entries older than 10 minutes
                    it = client_connections_.erase(it);
                } else {
                    ++it;
                }
            }
        }
    }

    bool check_rate_limit(const std::string& client_ip) {
        std::lock_guard<std::mutex> lock(rate_limit_mtx_);
        auto now = std::chrono::steady_clock::now();

        auto it = client_connections_.find(client_ip);
        if (it == client_connections_.end()) {
            client_connections_[client_ip] = {now, 1};
            return true;
        }

        auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second.last_connection);
        if (time_diff.count() >= 60) {
            it->second = {now, 1};
            return true;
        }

        if (it->second.connection_count < max_connections_per_minute_) {
            it->second.connection_count++;
            it->second.last_connection = now;
            return true;
        }
        return false;
    }

    bool perform_userpass_auth(int client_socket) {
        unsigned char buffer[256];
        ssize_t bytes = recv(client_socket, buffer, 2, 0);
        if (bytes != 2 || buffer[0] != 0x01) {
            return false;
        }

        uint8_t user_len = buffer[1];
        if (user_len == 0 || user_len > 255) {
            return false;
        }

        bytes = recv(client_socket, buffer, user_len, 0);
        if (bytes != user_len) {
            return false;
        }
        std::string username((char*)buffer, user_len);

        bytes = recv(client_socket, buffer, 1, 0);
        if (bytes != 1) {
            return false;
        }
        uint8_t password_len = buffer[0];
        if (password_len == 0 || password_len > 255) {
            return false;
        }

        bytes = recv(client_socket, buffer, password_len, 0);
        if (bytes != password_len) {
            return false;
        }
        std::string password((char*)buffer, password_len);

        bool auth_success = (username == username_ && password == password_);
        unsigned char response[] = {0x01, (unsigned char)(auth_success ? 0x00 : 0x01)};
        bool send_success = send(client_socket, response, sizeof(response), 0) == sizeof(response);

        return send_success && auth_success;
    }

    void send_reply(int client_socket, uint8_t rep, sockaddr_in* bind_addr = nullptr) {
        unsigned char response[10] = {0};
        response[0] = 0x05; // VER
        response[1] = rep;  // REP
        response[2] = 0x00; // RSV
        response[3] = 0x01; // IPv4

        if (rep == 0x00 && bind_addr) {
            memcpy(response + 4, &bind_addr->sin_addr, 4);
            memcpy(response + 8, &bind_addr->sin_port, 2);
        }

        send(client_socket, response, 10, MSG_NOSIGNAL);
    }

    int connect_to_target(const std::string& target_host, uint16_t target_port) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            return -1;
        }

        // Set socket to non-blocking for timeout control
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        sockaddr_in target_addr{};
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(target_port);

        // Try to parse as IP address first
        if (inet_pton(AF_INET, target_host.c_str(), &target_addr.sin_addr) != 1) {
            // Resolve hostname
            hostent* he = gethostbyname(target_host.c_str());
            if (!he) {
                close(sock);
                return -1;
            }
            memcpy(&target_addr.sin_addr, he->h_addr_list[0], he->h_length);
        }

        int result = connect(sock, (sockaddr*)&target_addr, sizeof(target_addr));
        if (result < 0 && errno != EINPROGRESS) {
            close(sock);
            return -1;
        }

        // Wait for connection to complete (if EINPROGRESS)
        if (errno == EINPROGRESS) {
            fd_set writefds;
            FD_ZERO(&writefds);
            FD_SET(sock, &writefds);

            struct timeval timeout = {10, 0}; // 10 second timeout
            int select_result = select(sock + 1, nullptr, &writefds, nullptr, &timeout);
            if (select_result <= 0) {
                close(sock);
                return -1;
            }

            // Check if connection succeeded
            int error = 0;
            socklen_t len = sizeof(error);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
                close(sock);
                return -1;
            }
        }

        return sock;
    }

    bool check_acl(const std::string& destination) {
        std::lock_guard<std::mutex> lock(acl_mtx_);

        // Check blocked list first
        for (const auto& blocked : blocked_destinations_) {
            if (matches_cidr(destination, blocked)) {
                return false;
            }
        }

        // Check allowed list
        for (const auto& allowed : allowed_destinations_) {
            if (matches_cidr(destination, allowed)) {
                return true;
            }
        }

        return false; // Default deny if no explicit allow rule matches
    }
};

int main() {
    std::ifstream config_file("config.json");

    std::string username = "";
    std::string password = "";
    int port = 1080;
    int max_connections_per_minute = 60;
    std::vector<std::string> allowed_destinations = {"0.0.0.0/0"};
    std::vector<std::string> blocked_destinations;

    if (config_file) {
        try {
            json config;
            config_file >> config;
            username = config.value("username", "");
            password = config.value("password", "");
            port = config.value("port", 1080);
            max_connections_per_minute = config.value("max_connections_per_minute", 60);
            allowed_destinations = config.value("allowed_destinations", allowed_destinations);
            blocked_destinations = config.value("blocked_destinations", blocked_destinations);
            std::cout << "Configuration loaded from config.json\n";
        } catch (const std::exception& e) {
            std::cerr << "Error parsing config.json: " << e.what() << "\n";
            std::cerr << "Using default configuration\n";
        }
    } else {
        std::cout << "config.json not found, using default configuration\n";
    }

    Socks5Server server(username, password, max_connections_per_minute);
    server.set_allowed_destinations(allowed_destinations);
    server.set_blocked_destinations(blocked_destinations);

    if (!server.start(port)) {
        std::cerr << "Failed to start SOCKS5 proxy on port " << port << "\n";
        return 1;
    }

    std::cout << "SOCKS5 proxy running on port " << port << std::endl;
    std::cout << "Press Enter to stop..." << std::endl;
    std::cin.get();

    std::cout << "Stopping server..." << std::endl;
    server.stop();

    auto stats = server.get_stats();
    std::cout << "\n=== Final Statistics ===" << std::endl;
    std::cout << "Total connections: " << stats.total_connections << std::endl;
    std::cout << "Successful connections: " << stats.successful_connections << std::endl;
    std::cout << "Failed connections: " << stats.failed_connections << std::endl;
    std::cout << "Bytes transferred: " << stats.bytes_transferred << std::endl;

    return 0;
}
