#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <map>
#include <atomic>
#include <fstream>
#include <cstring>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

class Socks5Proxy {
private:
    int server_socket_;
    int epoll_fd_;
    std::atomic<bool> running_{false};
    std::thread epoll_thread_;

    // Components
    std::unique_ptr<Logger> logger_;
    std::unique_ptr<ConnectionPool> connection_pool_;
    ProxyStats stats_;

    // Configuration
    std::string username_;
    std::string password_;
    bool auth_required_;
    std::vector<std::string> allowed_destinations_;
    std::vector<std::string> blocked_destinations_;
    int max_connections_per_minute_;
    time_t connection_timeout_;

    // Connection tracking
    std::mutex connections_mutex_;
    std::unordered_map<int, ConnectionInfo> connections_;
    std::map<std::string, ClientRateInfo> client_connections_;
    std::mutex rate_limit_mutex_;

public:
    Socks5Proxy(const std::string& username = "", const std::string& password = "",
                int max_connections = 60, time_t timeout = 30)
        : server_socket_(-1), epoll_fd_(-1), username_(username), password_(password),
          max_connections_per_minute_(max_connections), connection_timeout_(timeout) {
        auth_required_ = !username_.empty() || !password_.empty();
        allowed_destinations_.push_back("0.0.0.0/0");

        logger_ = std::make_unique<Logger>(LogLevel::INFO, "socks5_proxy.log");
        connection_pool_ = std::make_unique<ConnectionPool>();
    }

    ~Socks5Proxy() { stop(); }

    void set_allowed_destinations(const std::vector<std::string>& destinations) {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        allowed_destinations_ = destinations;
    }

    void set_blocked_destinations(const std::vector<std::string>& destinations) {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        blocked_destinations_ = destinations;
    }

    ProxyStats get_stats() const {
        return stats_;
    }

    bool start(int port) {
        // Create server socket
        server_socket_ = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (server_socket_ < 0) {
            logger_->log(LogLevel::ERROR, "Socket creation failed: " + std::string(strerror(errno)));
            return false;
        }

        // Set socket options
        int opt = 1;
        if (setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            logger_->log(LogLevel::ERROR, "Setsockopt failed: " + std::string(strerror(errno)));
            close(server_socket_);
            return false;
        }

        // Bind socket
        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(port);

        if (bind(server_socket_, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            logger_->log(LogLevel::ERROR, "Bind failed: " + std::string(strerror(errno)));
            close(server_socket_);
            return false;
        }

        // Listen
        if (listen(server_socket_, 1024) < 0) {
            logger_->log(LogLevel::ERROR, "Listen failed: " + std::string(strerror(errno)));
            close(server_socket_);
            return false;
        }

        // Create epoll instance
        epoll_fd_ = epoll_create1(0);
        if (epoll_fd_ < 0) {
            logger_->log(LogLevel::ERROR, "Epoll creation failed: " + std::string(strerror(errno)));
            close(server_socket_);
            return false;
        }

        // Add server socket to epoll
        epoll_event event{};
        event.events = EPOLLIN | EPOLLET;
        event.data.fd = server_socket_;
        if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, server_socket_, &event) < 0) {
            logger_->log(LogLevel::ERROR, "Epoll_ctl failed: " + std::string(strerror(errno)));
            close(server_socket_);
            close(epoll_fd_);
            return false;
        }

        running_ = true;
        epoll_thread_ = std::thread(&Socks5Proxy::epoll_loop, this);

        logger_->log(LogLevel::INFO, "SOCKS5 proxy listening on port " + std::to_string(port));
        if (auth_required_) {
            logger_->log(LogLevel::INFO, "Authentication enabled: " + username_ + ":" + password_);
        }

        return true;
    }

    void stop() {
        running_ = false;

        if (epoll_thread_.joinable()) {
            epoll_thread_.join();
        }

        if (server_socket_ >= 0) {
            close(server_socket_);
            server_socket_ = -1;
        }

        if (epoll_fd_ >= 0) {
            close(epoll_fd_);
            epoll_fd_ = -1;
        }

        // Close all connections
        std::lock_guard<std::mutex> lock(connections_mutex_);
        for (auto& [fd, conn_info] : connections_) {
            close(fd);
        }
        connections_.clear();

        connection_pool_->clear();

        logger_->log(LogLevel::INFO, "Proxy stopped");
    }

private:
    void epoll_loop() {
        const int MAX_EVENTS = 64;
        epoll_event events[MAX_EVENTS];

        while (running_) {
            int nfds = epoll_wait(epoll_fd_, events, MAX_EVENTS, 1000); // 1s timeout
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

            // Clean up timed out connections
            cleanup_timeout_connections();
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
                    break; // No more connections
                }
                logger_->log(LogLevel::ERROR, "Accept failed: " + std::string(strerror(errno)));
                break;
            }

            std::string client_ip = inet_ntoa(client_addr.sin_addr);

            // Check rate limiting
            if (!check_rate_limit(client_ip)) {
                logger_->log(LogLevel::WARNING, "Rate limit exceeded for " + client_ip, client_ip);
                close(client_socket);
                continue;
            }

            // Add to epoll
            epoll_event event{};
            event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
            event.data.fd = client_socket;
            if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, client_socket, &event) < 0) {
                logger_->log(LogLevel::ERROR, "Failed to add client to epoll: " +
                           std::string(strerror(errno)), client_ip);
                close(client_socket);
                continue;
            }

            // Create connection info
            ConnectionInfo conn_info{};
            conn_info.fd = client_socket;
            conn_info.state = ConnectionState::HANDSHAKE;
            conn_info.client_ip = client_ip;
            conn_info.created_at = time(nullptr);
            conn_info.last_activity = time(nullptr);

            {
                std::lock_guard<std::mutex> lock(connections_mutex_);
                connections_[client_socket] = conn_info;
            }

            stats_.total_connections++;
            stats_.active_connections++;

            logger_->log(LogLevel::INFO, "New connection from " + client_ip, client_ip);
        }
    }

    void handle_client_event(const epoll_event& event) {
        int fd = event.data.fd;

        std::lock_guard<std::mutex> lock(connections_mutex_);
        auto it = connections_.find(fd);
        if (it == connections_.end()) {
            return;
        }

        ConnectionInfo& conn_info = it->second;
        conn_info.last_activity = time(nullptr);

        if (event.events & EPOLLRDHUP || event.events & EPOLLHUP || event.events & EPOLLERR) {
            close_connection(fd, "Connection closed or error");
            return;
        }

        try {
            switch (conn_info.state) {
                case ConnectionState::HANDSHAKE:
                    handle_handshake(fd, conn_info);
                    break;
                case ConnectionState::AUTHENTICATION:
                    handle_authentication(fd, conn_info);
                    break;
                case ConnectionState::REQUEST:
                    handle_request(fd, conn_info);
                    break;
                case ConnectionState::FORWARDING:
                    handle_forwarding(fd, conn_info, event.events);
                    break;
                case ConnectionState::CLOSING:
                    close_connection(fd, "Closing state");
                    break;
            }
        } catch (const std::exception& e) {
            logger_->log(LogLevel::ERROR, "Error handling connection: " + std::string(e.what()),
                       conn_info.client_ip);
            close_connection(fd, "Exception: " + std::string(e.what()));
        }
    }

    void handle_handshake(int fd, ConnectionInfo& conn_info) {
        unsigned char buffer[256];
        ssize_t bytes_read = recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT);

        if (bytes_read <= 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                close_connection(fd, "Handshake read error");
            }
            return;
        }

        // Process handshake (implementation similar to before)
        // ... (handshake logic from previous implementation)

        // After successful handshake, move to next state
        if (auth_required_) {
            conn_info.state = ConnectionState::AUTHENTICATION;
        } else {
            conn_info.state = ConnectionState::REQUEST;
        }
    }

    void handle_authentication(int fd, ConnectionInfo& conn_info) {
        // Authentication logic (similar to before)
        // ... (authentication logic from previous implementation)

        conn_info.state = ConnectionState::REQUEST;
    }

    void handle_request(int fd, ConnectionInfo& conn_info) {
        // Request handling logic (similar to before)
        // ... (request logic from previous implementation)

        // Try to get connection from pool first
        int target_socket = connection_pool_->get_connection(conn_info.target_host, conn_info.target_port);
        if (target_socket >= 0) {
            stats_.pool_hits++;
            logger_->log(LogLevel::DEBUG, "Pool hit for " + conn_info.target_host, conn_info.client_ip);
        } else {
            stats_.pool_misses++;
            target_socket = connect_to_target(conn_info.target_host, conn_info.target_port);
            if (target_socket < 0) {
                send_reply(fd, 0x05); // Connection refused
                close_connection(fd, "Target connection failed");
                return;
            }
        }

        // Set non-blocking
        fcntl(target_socket, F_SETFL, O_NONBLOCK);

        // Add target socket to epoll
        epoll_event event{};
        event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
        event.data.fd = target_socket;
        if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, target_socket, &event) < 0) {
            close(target_socket);
            send_reply(fd, 0x05);
            close_connection(fd, "Failed to add target to epoll");
            return;
        }

        // Store target socket info
        ConnectionInfo target_info{};
        target_info.fd = target_socket;
        target_info.state = ConnectionState::FORWARDING;
        target_info.client_ip = conn_info.client_ip;
        target_info.target_host = conn_info.target_host;
        target_info.target_port = conn_info.target_port;
        target_info.created_at = time(nullptr);
        target_info.last_activity = time(nullptr);
        target_info.user_data = std::make_shared<int>(fd); // Link to client

        connections_[target_socket] = target_info;
        stats_.active_connections++;

        // Link client to target
        conn_info.user_data = std::make_shared<int>(target_socket);
        conn_info.state = ConnectionState::FORWARDING;

        send_reply(fd, 0x00); // Success

        logger_->log(LogLevel::INFO, "Connected to " + conn_info.target_host + ":" +
                   std::to_string(conn_info.target_port), conn_info.client_ip);
    }

    void handle_forwarding(int fd, ConnectionInfo& conn_info, uint32_t events) {
        int peer_fd = *static_cast<int*>(conn_info.user_data.get());

        if (events & EPOLLIN) {
            char buffer[4096];
            ssize_t bytes = recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT);

            if (bytes > 0) {
                stats_.bytes_transferred += bytes;
                ssize_t sent = send(peer_fd, buffer, bytes, MSG_DONTWAIT | MSG_NOSIGNAL);
                if (sent < 0) {
                    close_connection(fd, "Send error during forwarding");
                }
            } else if (bytes == 0 || (bytes < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
                close_connection(fd, "Read error during forwarding");
            }
        }
    }

    void close_connection(int fd, const std::string& reason) {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        auto it = connections_.find(fd);
        if (it == connections_.end()) {
            return;
        }

        ConnectionInfo& conn_info = it->second;

        logger_->log(LogLevel::DEBUG, "Closing connection: " + reason, conn_info.client_ip);

        if (conn_info.state == ConnectionState::FORWARDING && conn_info.user_data) {
            int peer_fd = *static_cast<int*>(conn_info.user_data.get());
            auto peer_it = connections_.find(peer_fd);
            if (peer_it != connections_.end()) {
                // Return target connection to pool if it's still valid
                if (peer_it->second.state == ConnectionState::FORWARDING) {
                    connection_pool_->return_connection(
                        peer_it->second.target_host,
                        peer_it->second.target_port,
                        peer_fd
                    );
                }
                connections_.erase(peer_fd);
                stats_.active_connections--;
            }
        }

        epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
        close(fd);
        connections_.erase(fd);
        stats_.active_connections--;
    }

    void cleanup_timeout_connections() {
        time_t now = time(nullptr);
        std::vector<int> to_remove;

        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            for (const auto& [fd, conn_info] : connections_) {
                if (now - conn_info.last_activity > connection_timeout_) {
                    to_remove.push_back(fd);
                    stats_.connection_timeouts++;
                }
            }
        }

        for (int fd : to_remove) {
            close_connection(fd, "Connection timeout");
        }
    }

    // Other methods (connect_to_target, check_rate_limit, check_acl, send_reply, etc.)
    // remain similar to previous implementation but adapted for non-blocking I/O
    // ...
};

// Monitor thread for statistics
void start_monitor(const Socks5Proxy& proxy, std::atomic<bool>& running) {
    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        ProxyStats stats = proxy.get_stats();

        std::cout << "=== Proxy Statistics ===" << std::endl;
        std::cout << "Total connections: " << stats.total_connections << std::endl;
        std::cout << "Active connections: " << stats.active_connections << std::endl;
        std::cout << "Bytes transferred: " << stats.bytes_transferred << std::endl;
        std::cout << "Pool hits: " << stats.pool_hits << std::endl;
        std::cout << "Pool misses: " << stats.pool_misses << std::endl;
        std::cout << "Auth failures: " << stats.auth_failures << std::endl;
        std::cout << "ACL blocks: " << stats.acl_blocks << std::endl;
        std::cout << "Timeouts: " << stats.connection_timeouts << std::endl;
        std::cout << "========================" << std::endl;
    }
}

int main() {
    Socks5Proxy proxy("admin", "secret");

    // Configure ACL
    std::vector<std::string> allowed = {"192.168.1.0/24", "10.0.0.0/8"};
    std::vector<std::string> blocked = {"192.168.1.100"};
    proxy.set_allowed_destinations(allowed);
    proxy.set_blocked_destinations(blocked);

    // Start proxy
    if (!proxy.start(1080)) {
        return 1;
    }

    // Start monitoring
    std::atomic<bool> monitor_running{true};
    std::thread monitor_thread([&proxy, &monitor_running]() {
        start_monitor(proxy, monitor_running);
    });

    std::cout << "Proxy running. Press Enter to stop..." << std::endl;
    std::cin.get();

    monitor_running = false;
    if (monitor_thread.joinable()) {
        monitor_thread.join();
    }

    proxy.stop();
    return 0;
}
