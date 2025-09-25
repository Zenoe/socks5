// g++ -std=c++17 -o mysocks5_proxy mysock5.cpp utils.cpp -lpthread -g
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include "utils.h"

using json = nlohmann::json;


class sock5 {
private:
  int server_socket_;

  std::atomic<bool> running_{false};
  std::vector<std::thread> client_threads_;
  std::mutex rate_limit_mtx;
  std::mutex acl_mtx_;

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
public:
    sock5(const std::string& username = "", const std::string& password = "",
                int max_connections = 2)
        : server_socket_(-1), username_(username), password_(password),
          max_connections_per_minute_(max_connections) {
        auth_required_ = !username_.empty() || !password_.empty();

        // Default ACL - allow everything
        allowed_destinations_.push_back("0.0.0.0/0");
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
    server_socket_ = socket(AF_INET, SOCK_STREAM, 0);
    if(server_socket_ < 0){
      std::cerr << "socket creation failed: " << strerror(errno) << std::endl;
      return false;
    }

    int opt = 1;
    if(setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0){
      std::cerr << "setsocketopt  failed: " << strerror(errno) << std::endl;
      close(server_socket_);
      return false;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if(bind(server_socket_, (sockaddr*)&server_addr, sizeof(server_addr))< 0){
      std::cerr << "bind  failed: " << strerror(errno) << std::endl;
      close(server_socket_);
      return false;
    }

    if(listen(server_socket_, 10) < 0){
      std::cerr << "listen  failed: " << strerror(errno) << std::endl;
      close(server_socket_);
      return false;
    }

    running_ = true;
    std::cout << "sock5 listening on port " << port << std::endl;

    while(running_){
      // accept
      sockaddr_in client_addr{};
      socklen_t client_len = sizeof(client_addr);
      int client_socket = accept(server_socket_, (sockaddr*)&client_addr, &client_len);
      if(client_socket < 0){
        if(running_){  // 目的是只在服务还在运行时输出 accept 的错误，你主动关闭/停止服务时accept failed 不输出日志
          std::cerr << "accept failed " << std::endl;
        }
        continue;
      }
      const std::string client_ip = inet_ntoa(client_addr.sin_addr);
      std::cout <<"New connection from " << client_ip << std::endl;

      if(!check_rate_limit(client_ip)){
        std::cout << "Rate limit exceeded for " << client_ip << std::endl;
        close(client_socket);
        continue;
      }
      client_threads_.emplace_back([this,client_ip, client_socket]() {
        handle_client(client_socket, client_ip);
      });
    }

    return true;
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

  void handle_client(int client_socket, const std::string& client_ip){
    if(!handshake(client_socket)){
      close(client_socket);
      return;
    }
    if (!handle_request(client_socket, client_ip)) {
      close(client_socket);
      return;
    }

  }

  bool handshake(int client_socket){
    /*
+-----+----------+----------+
| VER | NMETHODS | METHODS  |
+-----+----------+----------+
|  1  |    1     | 1~255    |
+-----+----------+----------+
METHODS 有NMETHODS个字节
*/
    unsigned char buffer[256];
    ssize_t bytes_read = recv(client_socket, buffer, 2, 0);
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

    // if(!no_auth_supported){
    //   // 0xFF 表示不支持
    //   unsigned char response[] = {0x05, 0xFF};
    //   send(client_socket, response, sizeof(response), 0);
    //   return false;
    // }

    // unsigned char response[] = {0x05, 0x00};
    unsigned char response[] = {0x05, selected_method};
    // if(!send(client_socket, response, sizeof(response), 0)){
    if(send(client_socket, response, sizeof(response), 0) != sizeof(response)){
      return false;
    }

    if(selected_method == 0x02){
      if(!perform_userpass_auth(client_socket)){
        return false;
      }
    }
    return true;
  }

  bool perform_userpass_auth(int client_socket){
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
      return auth_success;
  }

  bool handle_request(int client_socket, const std::string& client_ip){
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
      std::cout << "ACL block from " << client_ip << " to " << target_host << std::endl;
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

    // get local addr info for reply
    sockaddr_in local_addr{};
    socklen_t addr_len = sizeof(local_addr);
    getsockname(target_socket, (sockaddr*)&local_addr, &addr_len);
    send_reply(client_socket, 0x00, &local_addr);

    // start forwarding data
    forward_data(client_socket, target_socket);
    close(target_socket);
    return true;
  }

  void forward_data(int client_socket, int target_socket){
    fd_set readfds;
    char buffer[4096];
    while(true){
      FD_ZERO(&readfds);
      FD_SET(client_socket, &readfds);
      FD_SET(target_socket, &readfds);

      int max_fd = std::max(client_socket, target_socket) + 1;
      int activity = select(max_fd, &readfds, nullptr, nullptr, nullptr);
      if(activity < 0){
        if(errno == EINTR) continue;
        break;
      }

      if(FD_ISSET(client_socket, &readfds)){
        ssize_t bytes = recv(client_socket, buffer, sizeof(buffer), 0);
        if(bytes <=0) break;
        if(send(target_socket, buffer, bytes, 0) <=0) break;
      }
      if(FD_ISSET(target_socket, &readfds)){
        ssize_t bytes = recv(target_socket, buffer, sizeof(buffer), 0);
        if(bytes <=0) break;
        if(send(client_socket, buffer, bytes, 0) <=0) break;
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
  // sock5 s5;
  sock5 s5(usr, pass);

    s5.set_allowed_destinations(allowed_destinations);
    s5.set_blocked_destinations(blocked_destinations);

  if(!s5.start(1080)){
    std::cerr << "Failed to start proxy\n";
    return 1;
  }
  std::cout << "Proxy running. Press Enter to stop..." << std::endl;
  std::cin.get();

  s5.stop();
  return 0;

}

void test(){
  if(matches_cidr("10.1.1.2", "10.0.0.0/8")){
    std::cout << "matched 1\n";
  }
    if(matches_cidr("10.1.1.2", "10.0.0.0/16")){
    std::cout << "matched 2\n";
  }

    if(matches_cidr("10.1.1.2", "10.1.1.0/24")){
    std::cout << "matched 3\n";
  }
    if(matches_cidr("10.1.1.2", "10.1.0.0/24")){
    std::cout << "matched 4\n";
  }

    if(matches_cidr("10.9.1.2", "10.1.0.0/8")){
    std::cout << "matched 5\n";
  }
    if(matches_cidr("11.9.1.2", "10.1.0.0/8")){
    std::cout << "matched 6\n";
  }
    if(matches_cidr("10.1.1.2", "10.1.1.0/24")){
    std::cout << "matched 10.1.1.2, 24\n";
  }
    if(matches_cidr("10.1.1.2", "10.1.1.0/16")){
    std::cout << "matched 10.1.1.2,16 \n";
  }
    if(matches_cidr("10.2.3.2", "10.0.0.0/8")){
    std::cout << "matched 10.2.3.2 \n";
  }
}
