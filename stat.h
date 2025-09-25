#pragma once
#include <atomic>

struct ProxyStats {
    std::atomic<uint64_t> total_connections{0};
    std::atomic<uint64_t> active_connections{0};
    std::atomic<uint64_t> auth_failures{0};
    std::atomic<uint64_t> acl_blocks{0};
    std::atomic<uint64_t> bytes_transferred{0};
    std::atomic<uint64_t> connection_timeouts{0};
    std::atomic<uint64_t> pool_hits{0};
    std::atomic<uint64_t> pool_misses{0};

    void reset() {
        total_connections = 0;
        active_connections = 0;
        auth_failures = 0;
        acl_blocks = 0;
        bytes_transferred = 0;
        connection_timeouts = 0;
        pool_hits = 0;
        pool_misses = 0;
    }
};


