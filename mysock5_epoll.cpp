//  g++ -std=c++17 -o epoll_mysocks5_proxy mysock5_epoll.cpp utils.cpp -lpthread -g
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <map>
#include <atomic>
#include <fstream>
#include "lib/json.hpp"
#include <cstring>
#include <sys/epoll.h>
#include "Logger.h"
#include "ConnectionPool.h"
#include "stat.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include "utils.h"

using json = nlohmann::json;


class sock5 {
private:
  int epoll_fd_;
  int server_socket_;
  std::atomic<bool> running_{false};
  std::thread epoll_thread_;
  std::vector<std::thread> client_threads_;
  std::mutex rate_limit_mtx;
  std::mutex acl_mtx_;

  std::unique_ptr<Logger> logger_;
  std::unique_ptr<ConnectionPool> connection_pool_;
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

  time_t connection_timeout_;
public:
    sock5(const std::string& username = "", const std::string& password = "",
                int max_connections = 2, time_t timeout=30)
        : server_socket_(-1), username_(username), password_(password),
          max_connections_per_minute_(max_connections), connection_timeout_(timeout) {
        auth_required_ = !username_.empty() || !password_.empty();

        // Default ACL - allow everything
        allowed_destinations_.push_back("0.0.0.0/0");

        logger_ = std::make_unique<Logger>(LogLevel::INFO, "socks5.log");
        connection_pool_ = std::make_unique<ConnectionPool>();
    }
  ~sock5() {stop();}

    void set_allowed_destinations(const std::vector<std::string>& destinations) {
        std::lock_guard<std::mutex> lock(acl_mtx_);
        allowed_destinations_ = destinations;
    }

    void set_blocked_destinations(const std::vector<std::string>& destinations) {
        std::lock_guard<std::mutex> lock(acl_mtx_);
        blocked_destinations_ = destinations;
    }
  bool start(int port){
    // server_socket_ = socket(AF_INET, SOCK_STREAM, 0);
    server_socket_ = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if(server_socket_ < 0){
      logger_->log(LogLevel::ERROR, "Socket creation failed: " + std::string(strerror(errno)));
      return false;
    }

    int opt = 1;
    if(setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0){
      logger_->log(LogLevel::ERROR, "Setsockopt failed: " + std::string(strerror(errno)));
      close(server_socket_);
      return false;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if(bind(server_socket_, (sockaddr*)&server_addr, sizeof(server_addr))< 0){
      logger_->log(LogLevel::ERROR, "Bind failed: " + std::string(strerror(errno)));
      close(server_socket_);
      return false;
    }

    if(listen(server_socket_, 1024) < 0){
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
    if(epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, server_socket_, &ev) < 0){
      logger_->log(LogLevel::ERROR, "Epoll_ctl failed: " + std::string(strerror(errno)));
      close(server_socket_);
      close(epoll_fd_);
      return false;
    }

    epoll_thread_ = std::thread(&sock5::epoll_loop, this);
    running_ = true;
    logger_->log(LogLevel::INFO, "SOCKS5 proxy listening on port " + std::to_string(port));
    if (auth_required_) {
      logger_->log(LogLevel::INFO, "Authentication enabled: " + username_ + ":" + password_);
    }

    return true;
  }

  const ProxyStats& get_stats() const {
    return stats_;
  }

  void epoll_loop(){
    const int MAX_EVT = 64;
    epoll_event evts[MAX_EVT];
    while(running_){
      int nfds = epoll_wait(epoll_fd_, evts, MAX_EVT, 1000); // timeout 1s
      if(nfds < 0){
        if (errno == EINTR) continue;
        logger_->log(LogLevel::ERROR, "Epoll_wait failed: " + std::string(strerror(errno)));
        break;
      }
      for(int i=0; i< nfds; ++i ){
        if(evts[i].data.fd == server_socket_){
          handle_new_connection();
        }else{
          handle_client_event(evts[i]);
        }
      }
      // Clean up timed out connections
      cleanup_timeout_connections();
    }
  }

  void handle_new_connection(){
    while(true){
      sockaddr_in client_addr{};
      socklen_t client_len = sizeof(client_addr);
      int client_socket = accept4(server_socket_, (sockaddr*)&client_addr, &client_len, SOCK_NONBLOCK);
      if(client_socket < 0){
        if(errno == EAGAIN || errno == EWOULDBLOCK) {
          break;
        }
        logger_->log(LogLevel::ERROR, "Accept failed: " + std::string(strerror(errno)));
        break;
      }

      std::string client_ip = inet_ntoa(client_addr.sin_addr);
      if (!check_rate_limit(client_ip)) {
        logger_->log(LogLevel::WARNING, "Rate limit exceeded for " + client_ip, client_ip);
        close(client_socket);
        continue;
      }

      // add to epoll
      epoll_event evt{};
      evt.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
      evt.data.fd = client_socket;
      if(epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, client_socket, &evt) < 0){
        logger_->log(LogLevel::ERROR, "Failed to add client to epoll: " +
                     std::string(strerror(errno)), client_ip);
        close(client_socket);
        continue;
      }

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

      stats_.total_connections ++;
      stats_.active_connections ++;
      logger_->log(LogLevel::INFO, "New connection from " + client_ip, client_ip);
    }
  }

  void handle_client_event(const epoll_event &event) {
    int fd = event.data.fd;

    std::unique_lock<std::mutex> lock(connections_mutex_);
    auto it = connections_.find(fd);
    if (it == connections_.end()) {
      return;
    }

    ConnectionInfo &conn_info = it->second;
    conn_info.last_activity = time(nullptr);

    if (event.events & EPOLLRDHUP || event.events & EPOLLHUP ||
        event.events & EPOLLERR) {
      // ipt
      lock.unlock();
      close_connection(fd, "Connection closed or error");
      return;
    }

    lock.unlock();
    try {
      switch (conn_info.state) {
      case ConnectionState::HANDSHAKE:
        std::cout << "HANDSHAKE\n";
        handle_handshake(fd, conn_info);
        break;
      case ConnectionState::AUTHENTICATION:
        std::cout << "AUTHENTICATION\n";
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
    } catch (const std::exception &e) {
      logger_->log(LogLevel::ERROR,
                   "Error handling connection: " + std::string(e.what()),
                   conn_info.client_ip);
      close_connection(fd, "Exception: " + std::string(e.what()));
    }
  }

  void close_connection(int fd, const std::string& reason){
    std::lock_guard<std::mutex> lock(connections_mutex_);
    auto it = connections_.find(fd);
    if(it == connections_.end()){
      return;
    }

    ConnectionInfo& conn_info = it->second;
    logger_->log(LogLevel::DEBUG, "Closing connection: " + reason, conn_info.client_ip);

    epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);

    if(conn_info.state == ConnectionState::FORWARDING && conn_info.target_fd){
      // int peer_fd = *static_cast<int*>(conn_info.user_data.get());
      int peer_fd = conn_info.target_fd;
      auto peer_it = connections_.find(peer_fd);
      if(peer_it != connections_.end()){
        epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, peer_fd, nullptr);
        close(peer_fd);
        connections_.erase(peer_it);
      }
    }
    close(fd);
    connections_.erase(it);
    // if (conn_info.is_client_socket) {  ?
      stats_.active_connections--;
    // }

  }
  void cleanup_timeout_connections(){
    time_t now = time(nullptr);
    std::vector<int> to_remove;
    {
      std::lock_guard<std::mutex> lock(connections_mutex_);
      for(const auto& [fd, conn_info] : connections_){
        if(now - conn_info.last_activity > connection_timeout_){
          to_remove.push_back(fd);
          ++stats_.connection_timeouts;
        }
      }
    }
    for (int fd : to_remove) {
      close_connection(fd, "Connection timeout");
    }


  }
  void stop(){
    running_ = false;
    if(server_socket_ >=0){
      close(server_socket_);
      server_socket_ = -1;
    }
    for(auto& th: client_threads_){
      if(th.joinable())
        th.join();
    }
    client_threads_.clear();
  }

private:

  bool check_rate_limit(const std::string& client_ip){
    std::lock_guard<std::mutex> lock(rate_limit_mtx);
    auto now = std::chrono::steady_clock::now();

    auto it = client_connections_.find(client_ip);
    if(it == client_connections_.end()){
      client_connections_[client_ip] = {
        now, 1
      };
      return true;
    }
    // calc interal , if >= 1min
    auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.last_connection);
    if(time_diff.count() >=60){
      it->second = {now ,1};
      return true;
    }

    if(it->second.connection_count < max_connections_per_minute_){
      it->second.connection_count ++;
      return true;
    }
    return false;
  }


  bool handle_handshake(int client_socket, ConnectionInfo& conn_info){
    unsigned char buffer[256];
    // ssize_t bytes_read = recv(client_socket, buffer, 2, 0);
    ssize_t bytes_read = recv(client_socket, buffer, 2, MSG_DONTWAIT);
    if (bytes_read <= 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        close_connection(client_socket, "Handshake read error");
      }
      return false;
    }

    if(bytes_read != 2 || buffer[0] != 0x05){
      return false;
    }
    uint8_t nmethods = buffer[1];
    if(nmethods == 0) {
      return false;
    }

    bytes_read = recv(client_socket, buffer, nmethods, 0);
    if (bytes_read != nmethods) {
      return false;
    }

    bool no_auth_supported = false;
    bool userpass_auth = false;
    for(int i=0; i < nmethods; ++i){
      if(buffer[i] == 0x00){
        no_auth_supported = true;
      }else if(buffer[i] == 0x02){
        userpass_auth = true;
      }
    }

    uint8_t selected_method;
    if(auth_required_ && userpass_auth){
      selected_method = 0x02; // username/pass
    }else if(!auth_required_ && no_auth_supported){
      selected_method = 0x00; // no authentication
    }else{
      unsigned char response[] = {0x05, 0xFF};
      send(client_socket, response, sizeof(response), 0);
      return false;
    }

    unsigned char response[] = {0x05, selected_method};
    // if(!send(client_socket, response, sizeof(response), 0)){
    if(send(client_socket, response, sizeof(response), 0) != sizeof(response)){
      return false;
    }

    // if(selected_method == 0x02){
    //   if(!perform_userpass_auth(client_socket)){
    //     return false;
    //   }
    // }

    if(auth_required_){
      conn_info.state = ConnectionState::AUTHENTICATION;
    }else{
      conn_info.state = ConnectionState::REQUEST;
    }
    return true;
  }

  bool handle_authentication(int client_socket, ConnectionInfo& conn_info){
    unsigned char buffer[256];
    ssize_t bytes = recv(client_socket, buffer, 2, 0);
    if(bytes != 2 || buffer[0] != 0x01){
      return false;
    }
    uint8_t user_len = buffer[1];
    // read username
    bytes = recv(client_socket, buffer, user_len, 0);
    if(bytes != user_len){
      return false;
    }

    std::string username((char*)buffer, user_len);

      // Read password length
      bytes = recv(client_socket, buffer, 1, 0);
      if (bytes != 1) {
          return false;
      }

      uint8_t password_len = buffer[0];

      // Read password
      bytes = recv(client_socket, buffer, password_len, 0);
      if (bytes != password_len) {
          return false;
      }

      std::string password((char*)buffer, password_len);

      // Validate credentials
      bool auth_success = (username == username_ && password == password_);
      unsigned char response[] = {0x01, (unsigned char)( auth_success ? 0x00 : 0x01 )};
      if(send(client_socket, response, sizeof(response), 0) != sizeof(response)){
        return false;
      }
      conn_info.state = ConnectionState::REQUEST;
      return auth_success;
  }

  // bool handle_request(int client_socket, const std::string& client_ip){
  bool handle_request(int client_socket, ConnectionInfo& conn_info){
    unsigned char buffer[256];
    ssize_t bytes_read = recv(client_socket, buffer, 4, 0);
    if(bytes_read != 4 || buffer[0] != 0x05){
      return false;
    }

    uint8_t cmd = buffer[1];
    uint8_t atype = buffer[3];
    if(cmd != 0x01){
      send_reply(client_socket, 0x07);
      return false;
    }

    std::string target_host;
    uint16_t target_port;
    if(atype == 0x01){// ipv4
      bytes_read = recv(client_socket, buffer, 6, 0);
      if(bytes_read != 6) return false;
      char ip[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, buffer, ip, sizeof(ip));
      target_host = ip;
      target_port = ntohs(*(uint16_t*)(buffer+4));
    }else if(atype == 0x03){
      bytes_read = recv(client_socket, buffer, 1, 0);
      if(bytes_read != 1) return false;
      uint8_t domain_len = buffer[0];
      bytes_read = recv(client_socket, buffer, domain_len + 2, 0);
      if(bytes_read != domain_len + 2) return false;
      target_host = std::string((char*)buffer, domain_len);
      target_port = ntohs(*(uint16_t*)(buffer +domain_len ));
    }else{
      send_reply(client_socket, 0x08); // add type not supported
      return false;
    }

    if(!check_acl(target_host)){
      std::cout << "ACL block from " << conn_info.client_ip << " to " << target_host << std::endl;
      send_reply(client_socket, 0x08);
      return false;
    }

    std::cout << "Connecting to " << target_host << ":" << target_port << std::endl;

    // connect to target
    int target_socket = connect_to_target(target_host, target_port);
    if(target_socket < 0){
      send_reply(client_socket, 0x05); // connection refused
      return false;
    }
    // Add target socket to epoll
    epoll_event event{};
    event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
    event.data.fd = target_socket;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, target_socket, &event) < 0) {
      close(target_socket);
      send_reply(client_socket, 0x05);
      close_connection(client_socket, "Failed to add target to epoll");
      return false;
    }

    // get local addr info for reply
    sockaddr_in local_addr{};
    socklen_t addr_len = sizeof(local_addr);
    getsockname(target_socket, (sockaddr*)&local_addr, &addr_len);
    send_reply(client_socket, 0x00, &local_addr);

    // Store target socket info
    ConnectionInfo target_info{};
    target_info.fd = target_socket;
    target_info.state = ConnectionState::FORWARDING;
    target_info.client_ip = conn_info.client_ip;
    target_info.target_host = conn_info.target_host;
    target_info.target_port = conn_info.target_port;
    target_info.created_at = time(nullptr);
    target_info.last_activity = time(nullptr);
    // target_info.user_data = std::make_shared<int>(client_socket); // Link to client, why
    target_info.target_fd = client_socket;

    connections_[target_socket] = target_info;
    stats_.active_connections++;

    // conn_info.user_data = std::make_shared<int>(target_socket);
    conn_info.target_fd = target_socket;
    conn_info.state = ConnectionState::FORWARDING;

    logger_->log(LogLevel::INFO, "Connected to " + conn_info.target_host + ":" +
                 std::to_string(conn_info.target_port), conn_info.client_ip);

    // // start forwarding data
    // forward_data(client_socket, target_socket);
    // close(target_socket);
    return true;
  }

  void handle_forwarding(int fd, ConnectionInfo& conn_info, uint32_t events ){
    // int peer_fd = *static_cast<int*>( conn_info.user_data.get() );
    int peer_fd =  conn_info.target_fd;
    if(events & EPOLLIN){
      char buffer[4096];
      ssize_t bytes = recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT);
      if(bytes > 0){
        stats_.bytes_transferred += bytes;
        ssize_t sent = send(peer_fd, buffer, bytes, MSG_DONTWAIT | MSG_NOSIGNAL);
        if(sent < 0){
          close_connection(fd, "send error during forwarding");
        }
      }else if (bytes == 0 || (bytes < 0 && errno != EAGAIN && errno != EWOULDBLOCK)){
        close_connection(fd, "Read error during forwarding");
      }
    }
  }

  void send_reply(int client_socket, uint8_t rep, sockaddr_in* bind_addr= nullptr){
    unsigned char response[22] = {0}; // Max size for IPv6
    response[0] = 0x05;// VER
    response[1] = rep; // REP
    response[2] = 0x00; // RSV
    response[3] = 0x01; // ipv4
    if(rep == 0x00 && bind_addr){
      memcpy(response+4, &bind_addr->sin_addr, 4);
      memcpy(response+8, &bind_addr->sin_port, 2);
      send(client_socket, response, 10, 0);
    }else{
      send(client_socket, response, 4, 0);
    }
  }

  int connect_to_target( const std::string&  target_host, uint16_t target_port){
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) return -1;
    sockaddr_in target_addr{};
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(target_port);
    // check if host is IP or domain

    if(inet_pton(AF_INET, target_host.c_str(), &target_addr.sin_addr) == 1){
      //  it's an IP addr
    }else{
      hostent* he = gethostbyname(target_host.c_str());
      if(!he){
        close(sock);
        return -1;
      }else{
        memcpy(&target_addr.sin_addr, he->h_addr_list[0], he->h_length);
      }
    }

    if(connect(sock, (sockaddr*)&target_addr, sizeof(target_addr)) < 0){
      close(sock);
      return -1;
    }
    return sock;
  }

  bool check_acl(const std::string& destination){
    std::lock_guard<std::mutex> lock(acl_mtx_);
    for(const auto& blocked : blocked_destinations_){
      if(matches_cidr(destination, blocked)){
        std::cout << destination << " is blocked\n";
        return false;
      }
    }
    for (const auto& allowed : allowed_destinations_) {
      if (matches_cidr(destination, allowed)) {
        std::cout << destination << " is allowed\n";
        return true;
      }
    }

    // default deny
   return false;
  }


};

void start_monitor(const sock5& proxy, std::atomic<bool>& running) {
  while (running) {
    std::this_thread::sleep_for(std::chrono::seconds(10));
    const ProxyStats& stats = proxy.get_stats();

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

int main(){
  std::ifstream config_file ("config.json");
  if(!config_file){
    std::cerr << "Failed to open config.json\n";
    return 1;
  }
  json config;
  config_file >> config;
  std::string usr = config.value("username", "");
  std::string pass = config.value("password", "");
  std::vector<std::string> allowed_destinations = config.value("allowed_destinations", std::vector<std::string>());
  std::vector<std::string> blocked_destinations = config.value("blocked_destinations", std::vector<std::string>());
  int max_connections = config.value("max_connections", 2);
  int timeout = config.value("timeout", 30);

  sock5 s5(usr, pass, max_connections, timeout);

  s5.set_allowed_destinations(allowed_destinations);
  s5.set_blocked_destinations(blocked_destinations);

  if(!s5.start(1080)){
    std::cerr << "Failed to start proxy\n";
    return 1;
  }
  // Start monitoring
  std::atomic<bool> monitor_running{true};
  std::thread monitor_thread([&s5, &monitor_running]() {
    start_monitor(s5, monitor_running);
  });

  while(1);
  // std::cout << "Proxy running. Press Enter to stop..." << std::endl;
  // std::cin.get();

  monitor_running = false;
  if (monitor_thread.joinable()) {
    monitor_thread.join();
  }

  s5.stop();
  return 0;

}

