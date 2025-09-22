#include "utils.h"
#include <arpa/inet.h>

bool matches_cidr(const std::string& destination, const std::string& cidr){
  if(cidr == "0.0.0.0/0") return true;
  int slashpos = cidr.find('/');
  if(slashpos == std::string::npos){
    return destination == cidr;
  }
  std::string cidr_ip = cidr.substr(0, slashpos);
  int prefix_bits = std::stoi(cidr.substr(slashpos + 1));

  uint32_t ip_num = ntohl(inet_addr(destination.c_str()));
  uint32_t cidr_ip_num = ntohl(inet_addr(cidr_ip.c_str()));

  uint32_t mask  = prefix_bits == 0 ? 0: ~(( 1 << (32-prefix_bits)) - 1 );
  return ( ip_num & mask ) == ( cidr_ip_num & mask );
}
