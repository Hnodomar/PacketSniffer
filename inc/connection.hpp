#ifndef CONNECTION_HPP
#define CONNECTION_HPP

#include <cstdint>
#include <utility>

/* Connections are defined by the IP 4-tuple
*  SOURCE_IP | SOURCE_PORT | DESTINATION_IP | DESTINATION_PORT
*  Currently only supporting ipv4 connections
*/
namespace PacketSniffing {
struct IPV4Connection {
  IPV4Connection(const uint16_t sport, const uint16_t dport, 
   const uint32_t sip, const uint32_t dip)
    : source_port(sport)
    , destination_port(dport)
    , source_ip(sip)
    , destination_ip(dip)
  {}
  IPV4Connection()
    : source_port(0)
    , destination_port(0)
    , source_ip(0)
    , destination_ip(0)
  {}
  std::size_t operator()(const IPV4Connection& connection) const {
    return std::hash<uint16_t>()(source_port) 
      + std::hash<uint16_t>()(destination_port)
      + std::hash<uint32_t>()(source_ip)
      + std::hash<uint32_t>()(destination_ip);
  }
  bool operator==(const IPV4Connection& oc) const {
    const bool seq = source_port == oc.source_port;
    const bool deq = destination_port == oc.destination_port;
    const bool sip = source_ip == oc.source_ip;
    const bool dip = destination_ip == oc.destination_ip;
    const bool conns_equal = (seq && deq && sip && dip);
    if (!conns_equal) {
      const bool seq = source_port == oc.destination_port;
      const bool deq = destination_port == oc.source_port;
      const bool sip = source_ip == oc.destination_ip;
      const bool dip = destination_ip == oc.source_ip;
      return seq && deq && sip && dip;
    }
    return conns_equal;
  }
  const uint16_t source_port;
  const uint16_t destination_port;
  const uint32_t source_ip; 
  const uint32_t destination_ip;
};
}
#endif
