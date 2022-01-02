#ifndef PACKET_SNIFFER_HPP
#define PACKET_SNIFFER_HPP

#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <string>
#include <fstream>
#include <array>

namespace PacketSniffing {

enum class NetworkProtocol {
	ICMP = 1,
	IGMP = 2,
	TCP = 6,
	UDP = 17
};

constexpr uint32_t MAX_IP_SIZE = 65536;
constexpr uint32_t ETH_HEADER_SIZE = sizeof(ethhdr);

/* PACKET SNIFFER
 * Captures all packets and will pass to analyzers
 * based on user-defined filters after parsing eth/ip/network layers
*/	
class PacketSniffer {
	using Buffer = std::array<uint8_t, MAX_IP_SIZE>;
public:
	PacketSniffer(const std::string& log_filename = "log.txt") 
	  : sniffer_fd_(socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))
		, log_file(log_filename)
	{
		if (sniffer_fd_ < 0)
			throw std::runtime_error("Failed to successfully open the raw socket - check sudo privilege");
		setsockopt(sniffer_fd_, SOL_SOCKET, SO_BINDTODEVICE, "eth0", strlen("eth0") + 1);
		analysePackets();
	} 
private:
	void analysePackets() {
		Buffer buffer; 
		for (;;) {
			socklen_t socket_addr_size = sizeof(sockaddr);
			sockaddr saddr;
			const int size_of_data_received = recvfrom( // thead-safe, happens atomically
				sniffer_fd_, 
				buffer.data(), 
				65536, 
				0, 
				&saddr, 
				&socket_addr_size
			);
			if (size_of_data_received < 0)
				throw std::runtime_error("Failed to successfully receive a packet");
			processPacket(buffer, size_of_data_received);
		}
	}
	void processPacket(const Buffer& buffer, const uint32_t data_size) {
		const iphdr* ip_header = reinterpret_cast<const iphdr*>(buffer.data() + ETH_HEADER_SIZE);
		switch (static_cast<NetworkProtocol>(ip_header->protocol)) {
			case NetworkProtocol::TCP:
			case NetworkProtocol::UDP:
				filterPort();
				break;
			default:
				break;
		}
	}
	template<typename T>
	void filterPort(const T& buffer, const uint32_t data_size) {

	}
	const int sniffer_fd_;
	std::ofstream log_file;
};
}
#endif
