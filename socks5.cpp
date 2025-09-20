#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <memory>
#include <map>
#include <chrono>
#include <functional>
#include <system_error>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <cstring>
#include <cerrno>
#include <fcntl.h>

class Socks5Proxy {
private:
    int server_socket_;
    std::atomic<bool> running_{false};
    std::vector<std::thread> client_threads_;
    std::mutex acl_mutex_;
    std::mutex rate_limit_mutex_;

    // Authentication configuration
    std::string username_;
    std::string password_;
    bool auth_required_;

    // Access Control Lists
    std::vector<std::string> allowed_destinations_;
    std::vector<std::string> blocked_destinations_;

    // Rate limiting
    struct ClientRateInfo {
        std::chrono::steady_clock::time_point last_connection;
        int connection_count;
    };
    std::map<std::string, ClientRateInfo> client_connections_;
    int max_connections_per_minute_;

public:
    Socks5Proxy(const std::string& username = "", const std::string& password = "",
                int max_connections = 60)
        : server_socket_(-1), username_(username), password_(password),
          max_connections_per_minute_(max_connections) {
        auth_required_ = !username_.empty() || !password_.empty();

        // Default ACL - allow everything
        allowed_destinations_.push_back("0.0.0.0/0");
    }

    ~Socks5Proxy() { stop(); }

    // Set access control lists
    void set_allowed_destinations(const std::vector<std::string>& destinations) {
        std::lock_guard<std::mutex> lock(acl_mutex_);
        allowed_destinations_ = destinations;
    }

    void set_blocked_destinations(const std::vector<std::string>& destinations) {
        std::lock_guard<std::mutex> lock(acl_mutex_);
        blocked_destinations_ = destinations;
    }

    // Check if a client is allowed based on rate limiting
    bool check_rate_limit(const std::string& client_ip) {
        std::lock_guard<std::mutex> lock(rate_limit_mutex_);

        auto now = std::chrono::steady_clock::now();
        auto it = client_connections_.find(client_ip);

        if (it == client_connections_.end()) {
            // First connection from this IP
            client_connections_[client_ip] = {now, 1};
            return true;
        }

        // Check if a minute has passed since first connection in current window
        auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second.last_connection);

        if (time_diff.count() >= 60) {
            // Reset counter
            it->second = {now, 1};
            return true;
        }

        // Check if within limit
        if (it->second.connection_count < max_connections_per_minute_) {
            it->second.connection_count++;
            return true;
        }

        return false;
    }

    // Check if destination is allowed by ACL
    bool check_acl(const std::string& destination) {
        std::lock_guard<std::mutex> lock(acl_mutex_);

        // First check blocked destinations (higher priority)
        for (const auto& blocked : blocked_destinations_) {
            if (matches_cidr(destination, blocked)) {
                return false;
            }
        }

        // Then check allowed destinations
        for (const auto& allowed : allowed_destinations_) {
            if (matches_cidr(destination, allowed)) {
                return true;
            }
        }

        // Default deny
        return false;
    }

    // Helper function to check if IP matches CIDR notation
    bool matches_cidr(const std::string& ip, const std::string& cidr) {
        // Handle "any" case
        if (cidr == "0.0.0.0/0") return true;

        size_t slash_pos = cidr.find('/');
        if (slash_pos == std::string::npos) {
            // Exact match required
            return ip == cidr;
        }

        std::string cidr_ip = cidr.substr(0, slash_pos);
        int prefix_bits = std::stoi(cidr.substr(slash_pos + 1));

        // Convert both IPs to network byte order
        uint32_t ip_num = inet_addr(ip.c_str());
        uint32_t cidr_ip_num = inet_addr(cidr_ip.c_str());

        if (ip_num == INADDR_NONE || cidr_ip_num == INADDR_NONE) {
            return false;
        }

        // Create mask
        uint32_t mask = prefix_bits == 0 ? 0 : ~((1 << (32 - prefix_bits)) - 1);

        // Compare network portions
        return (ip_num & mask) == (cidr_ip_num & mask);
    }

    bool start(int port) {
        server_socket_ = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket_ < 0) {
            std::cerr << "Socket creation failed: " << strerror(errno) << std::endl;
            return false;
        }

        // Set socket options
        int opt = 1;
        if (setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            std::cerr << "Setsockopt failed: " << strerror(errno) << std::endl;
            close(server_socket_);
            return false;
        }

        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(port);

        if (bind(server_socket_, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            std::cerr << "Bind failed: " << strerror(errno) << std::endl;
            close(server_socket_);
            return false;
        }

        if (listen(server_socket_, 10) < 0) {
            std::cerr << "Listen failed: " << strerror(errno) << std::endl;
            close(server_socket_);
            return false;
        }

        running_ = true;
        std::cout << "SOCKS5 proxy listening on port " << port << std::endl;
        if (auth_required_) {
            std::cout << "Authentication enabled: " << username_ << ":" << password_ << std::endl;
        }

        // Accept connections
        while (running_) {
            sockaddr_in client_addr{};
            socklen_t client_len = sizeof(client_addr);
            int client_socket = accept(server_socket_, (sockaddr*)&client_addr, &client_len);

            if (client_socket < 0) {
                if (running_) {
                    std::cerr << "Accept failed: " << strerror(errno) << std::endl;
                }
                continue;
            }

            std::string client_ip = inet_ntoa(client_addr.sin_addr);
            std::cout << "New connection from " << client_ip << std::endl;

            // Check rate limiting
            if (!check_rate_limit(client_ip)) {
                std::cout << "Rate limit exceeded for " << client_ip << std::endl;
                close(client_socket);
                continue;
            }

            client_threads_.emplace_back([this, client_socket, client_ip]() {
                handle_client(client_socket, client_ip);
            });
        }

        return true;
    }

    void stop() {
        running_ = false;
        if (server_socket_ >= 0) {
            close(server_socket_);
            server_socket_ = -1;
        }

        for (auto& thread : client_threads_) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        client_threads_.clear();
    }

private:
    void handle_client(int client_socket, const std::string& client_ip) {
        // Handshake phase
        if (!perform_handshake(client_socket)) {
            close(client_socket);
            return;
        }

        // Parse request and establish connection
        if (!handle_request(client_socket, client_ip)) {
            close(client_socket);
            return;
        }
    }

    bool perform_handshake(int client_socket) {
        unsigned char buffer[256];

        // Read version and number of methods
        ssize_t bytes_read = recv(client_socket, buffer, 2, 0);
        if (bytes_read != 2 || buffer[0] != 0x05) {
            return false;
        }

        uint8_t nmethods = buffer[1];
        if (nmethods == 0) {
            return false;
        }

        // Read methods
        bytes_read = recv(client_socket, buffer, nmethods, 0);
        if (bytes_read != nmethods) {
            return false;
        }

        // Check if supported methods are offered
        bool no_auth_supported = false;
        bool user_pass_auth_supported = false;

        for (int i = 0; i < nmethods; i++) {
            if (buffer[i] == 0x00) {
                no_auth_supported = true;
            } else if (buffer[i] == 0x02) {
                user_pass_auth_supported = true;
            }
        }

        // Determine authentication method
        uint8_t selected_method;
        if (auth_required_ && user_pass_auth_supported) {
            selected_method = 0x02; // username/password
        } else if (!auth_required_ && no_auth_supported) {
            selected_method = 0x00; // no authentication
        } else {
            // Send no acceptable methods
            unsigned char response[] = {0x05, 0xFF};
            send(client_socket, response, sizeof(response), 0);
            return false;
        }

        // Send selected method
        unsigned char response[] = {0x05, selected_method};
        if (send(client_socket, response, sizeof(response), 0) != sizeof(response)) {
            return false;
        }

        // If username/password authentication is required, perform it
        if (selected_method == 0x02) {
            if (!perform_username_password_auth(client_socket)) {
                return false;
            }
        }

        return true;
    }

    bool perform_username_password_auth(int client_socket) {
        unsigned char buffer[256];

        // Read authentication version and username length
        ssize_t bytes_read = recv(client_socket, buffer, 2, 0);
        if (bytes_read != 2 || buffer[0] != 0x01) {
            return false;
        }

        uint8_t username_len = buffer[1];

        // Read username
        bytes_read = recv(client_socket, buffer, username_len, 0);
        if (bytes_read != username_len) {
            return false;
        }

        std::string username((char*)buffer, username_len);

        // Read password length
        bytes_read = recv(client_socket, buffer, 1, 0);
        if (bytes_read != 1) {
            return false;
        }

        uint8_t password_len = buffer[0];

        // Read password
        bytes_read = recv(client_socket, buffer, password_len, 0);
        if (bytes_read != password_len) {
            return false;
        }

        std::string password((char*)buffer, password_len);

        // Validate credentials
        bool auth_success = (username == username_ && password == password_);

        // Send authentication result
        unsigned char response[] = {0x01, auth_success ? 0x00 : 0x01};
        if (send(client_socket, response, sizeof(response), 0) != sizeof(response)) {
            return false;
        }

        return auth_success;
    }

    bool handle_request(int client_socket, const std::string& client_ip) {
        unsigned char buffer[256];

        // Read request header
        ssize_t bytes_read = recv(client_socket, buffer, 4, 0);
        if (bytes_read != 4 || buffer[0] != 0x05) {
            return false;
        }

        uint8_t cmd = buffer[1];
        uint8_t atype = buffer[3];

        if (cmd != 0x01) { // Only support CONNECT
            send_reply(client_socket, 0x07); // Command not supported
            return false;
        }

        std::string target_host;
        uint16_t target_port;

        // Parse address based on type
        if (atype == 0x01) { // IPv4
            bytes_read = recv(client_socket, buffer, 6, 0);
            if (bytes_read != 6) return false;

            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, buffer, ip, sizeof(ip));
            target_host = ip;
            target_port = ntohs(*(uint16_t*)(buffer + 4));

        } else if (atype == 0x03) { // Domain name
            bytes_read = recv(client_socket, buffer, 1, 0);
            if (bytes_read != 1) return false;

            uint8_t domain_len = buffer[0];
            bytes_read = recv(client_socket, buffer, domain_len + 2, 0);
            if (bytes_read != domain_len + 2) return false;

            target_host = std::string((char*)buffer, domain_len);
            target_port = ntohs(*(uint16_t*)(buffer + domain_len));

        } else {
            send_reply(client_socket, 0x08); // Address type not supported
            return false;
        }

        // Validate destination against ACL
        if (!check_acl(target_host)) {
            std::cout << "ACL blocked connection from " << client_ip
                      << " to " << target_host << std::endl;
            send_reply(client_socket, 0x02); // Connection not allowed by ruleset
            return false;
        }

        std::cout << "Connecting from " << client_ip << " to "
                  << target_host << ":" << target_port << std::endl;

        // Connect to target
        int target_socket = connect_to_target(target_host, target_port);
        if (target_socket < 0) {
            send_reply(client_socket, 0x05); // Connection refused
            return false;
        }

        // Get local address info for reply
        sockaddr_in local_addr{};
        socklen_t addr_len = sizeof(local_addr);
        getsockname(target_socket, (sockaddr*)&local_addr, &addr_len);

        // Send success reply
        send_reply(client_socket, 0x00, &local_addr);

        // Start forwarding data
        forward_data(client_socket, target_socket);

        close(target_socket);
        return true;
    }

    int connect_to_target(const std::string& host, uint16_t port) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return -1;

        sockaddr_in target_addr{};
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(port);

        // Check if host is IP address or domain name
        if (inet_pton(AF_INET, host.c_str(), &target_addr.sin_addr) == 1) {
            // It's an IP address
        } else {
            // It's a domain name, resolve it
            hostent* he = gethostbyname(host.c_str());
            if (!he) {
                close(sock);
                return -1;
            }
            memcpy(&target_addr.sin_addr, he->h_addr_list[0], he->h_length);
        }

        if (connect(sock, (sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            close(sock);
            return -1;
        }

        return sock;
    }

    void send_reply(int client_socket, uint8_t rep, sockaddr_in* bind_addr = nullptr) {
        unsigned char response[22] = {0}; // Max size for IPv6
        response[0] = 0x05; // VER
        response[1] = rep;  // REP
        response[2] = 0x00; // RSV

        if (rep == 0x00 && bind_addr) {
            response[3] = 0x01; // ATYP (IPv4)
            memcpy(response + 4, &bind_addr->sin_addr, 4);
            memcpy(response + 8, &bind_addr->sin_port, 2);
            send(client_socket, response, 10, 0);
        } else {
            send(client_socket, response, 4, 0);
        }
    }

    void forward_data(int client_socket, int target_socket) {
        fd_set readfds;
        char buffer[4096];

        while (true) {
            FD_ZERO(&readfds);
            FD_SET(client_socket, &readfds);
            FD_SET(target_socket, &readfds);

            int max_fd = std::max(client_socket, target_socket) + 1;
            int activity = select(max_fd, &readfds, nullptr, nullptr, nullptr);

            if (activity < 0) {
                if (errno == EINTR) continue;
                break;
            }

            if (FD_ISSET(client_socket, &readfds)) {
                ssize_t bytes = recv(client_socket, buffer, sizeof(buffer), 0);
                if (bytes <= 0) break;
                if (send(target_socket, buffer, bytes, 0) <= 0) break;
            }

            if (FD_ISSET(target_socket, &readfds)) {
                ssize_t bytes = recv(target_socket, buffer, sizeof(buffer), 0);
                if (bytes <= 0) break;
                if (send(client_socket, buffer, bytes, 0) <= 0) break;
            }
        }
    }
};

int main() {
    // Create proxy with authentication (username: admin, password: secret)
    Socks5Proxy proxy("admin", "secret");

    // Set up access control lists
    std::vector<std::string> allowed_destinations = {
        "192.168.1.0/24",    // Allow local network
        "10.0.0.0/8",        // Allow private network
        "93.184.216.34"      // Allow example.com
    };

    std::vector<std::string> blocked_destinations = {
        "192.168.1.100",     // Block specific IP
        "10.0.0.50"          // Block another specific IP
    };

    proxy.set_allowed_destinations(allowed_destinations);
    proxy.set_blocked_destinations(blocked_destinations);

    // Start the proxy on port 1080
    if (!proxy.start(1080)) {
        std::cerr << "Failed to start proxy" << std::endl;
        return 1;
    }

    std::cout << "Proxy running with authentication and ACL. Press Enter to stop..." << std::endl;
    std::cin.get();

    proxy.stop();
    return 0;
}
