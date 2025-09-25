#pragma once
// Logging levels
enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    CRITICAL
};

// Connection states
enum class ConnectionState {
    HANDSHAKE,
    AUTHENTICATION,
    REQUEST,
    FORWARDING,
    CLOSING
};

class Logger {
private:
    LogLevel level_;
    std::mutex log_mutex_;
    std::ofstream log_file_;
    bool log_to_file_;

public:
    Logger(LogLevel level = LogLevel::INFO, const std::string& filename = "")
        : level_(level), log_to_file_(!filename.empty()) {
        if (log_to_file_) {
            log_file_.open(filename, std::ios::app);
        }
    }

    ~Logger() {
        if (log_file_.is_open()) {
            log_file_.close();
        }
    }

    void set_level(LogLevel level) {
        level_ = level;
    }

    void log(LogLevel severity, const std::string& message, const std::string& client_ip = "") {
        if (severity < level_) return;

        std::lock_guard<std::mutex> lock(log_mutex_);
        auto now = std::chrono::system_clock::now();
        auto now_time = std::chrono::system_clock::to_time_t(now);
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;

        std::stringstream ss;
        ss << std::put_time(std::localtime(&now_time), "%Y-%m-%d %H:%M:%S")
           << '.' << std::setfill('0') << std::setw(3) << now_ms.count()
           << " [" << level_to_string(severity) << "]";

        if (!client_ip.empty()) {
            ss << " [" << client_ip << "]";
        }

        ss << " " << message << std::endl;

        std::cout << ss.str();
        if (log_to_file_ && log_file_.is_open()) {
            log_file_ << ss.str();
            log_file_.flush();
        }
    }

private:
    std::string level_to_string(LogLevel level) {
        switch (level) {
            case LogLevel::DEBUG: return "DEBUG";
            case LogLevel::INFO: return "INFO";
            case LogLevel::WARNING: return "WARNING";
            case LogLevel::ERROR: return "ERROR";
            case LogLevel::CRITICAL: return "CRITICAL";
            default: return "UNKNOWN";
        }
    }
};
