#pragma once
#include <queue>
#include <unistd.h> // for close()
#include <fcntl.h>  // for fcntl() and O_NONBLOCK
#include <sys/socket.h> // for getsockopt()

struct ConnectionInfo {
    int fd;
    ConnectionState state;
    std::string client_ip;
    std::string target_host;
    uint16_t target_port;
    time_t created_at;
    time_t last_activity;
    std::shared_ptr<void> user_data;
};

// Connection pool
class ConnectionPool {
private:
    std::mutex mutex_;
    std::map<std::pair<std::string, uint16_t>, std::queue<int>> pool_;
    std::map<int, time_t> connection_times_;
    size_t max_pool_size_;
    time_t max_connection_age_;

public:
    ConnectionPool(size_t max_pool_size = 100, time_t max_connection_age = 300)
        : max_pool_size_(max_pool_size), max_connection_age_(max_connection_age) {}

    ~ConnectionPool() {
        clear();
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [key, queue] : pool_) {
            while (!queue.empty()) {
                close(queue.front());
                queue.pop();
            }
        }
        pool_.clear();
        connection_times_.clear();
    }

    int get_connection(const std::string& host, uint16_t port) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto key = std::make_pair(host, port);

        // Clean up old connections first
        cleanup_old_connections();

        if (pool_.find(key) != pool_.end() && !pool_[key].empty()) {
            int fd = pool_[key].front();
            pool_[key].pop();
            connection_times_.erase(fd);
            return fd;
        }

        return -1; // No connection available in pool
    }

    void return_connection(const std::string& host, uint16_t port, int fd) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto key = std::make_pair(host, port);

        // Check if pool is full
        if (pool_.size() >= max_pool_size_) {
            close(fd);
            return;
        }

        // Set non-blocking and check if connection is still valid
        if (set_non_blocking(fd) && is_connection_valid(fd)) {
            pool_[key].push(fd);
            connection_times_[fd] = time(nullptr);
        } else {
            close(fd);
        }
    }

private:
    bool set_non_blocking(int fd) {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1) return false;
        return fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1;
    }

    bool is_connection_valid(int fd) {
        // Simple check: try to get socket error
        int error = 0;
        socklen_t len = sizeof(error);
        return getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0;
    }

    void cleanup_old_connections() {
        time_t now = time(nullptr);
        std::vector<int> to_remove;

        for (auto& [fd, create_time] : connection_times_) {
            if (now - create_time > max_connection_age_) {
                to_remove.push_back(fd);
            }
        }

        for (int fd : to_remove) {
            close(fd);
            connection_times_.erase(fd);

            // Remove from pool queues
            for (auto& [key, queue] : pool_) {
                std::queue<int> new_queue;
                while (!queue.empty()) {
                    int current_fd = queue.front();
                    queue.pop();
                    if (current_fd != fd) {
                        new_queue.push(current_fd);
                    }
                }
                pool_[key] = new_queue;
            }
        }
    }
};
