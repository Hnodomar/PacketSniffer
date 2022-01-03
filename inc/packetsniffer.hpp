#ifndef PACKET_SNIFFER_HPP
#define PACKET_SNIFFER_HPP

#include "connection.hpp"
#include "ippacket.hpp"

#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <string>
#include <vector>
#include <fstream>
#include <unordered_map>
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
constexpr uint32_t IP_HEADER_SIZE = sizeof(iphdr);
constexpr uint16_t IP_FRAG_OFFSET_SIZE_IN_BITS = 13;
constexpr uint16_t IP_MORE_FRAGMENTS_FLAG = 3;

/* PACKET SNIFFER
 * Captures all packets and will pass to analyzers
 * based on user-defined filters after parsing eth/ip/transport layers
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
		const uint8_t num_cores = std::thread::hardware_concurrency();
		if (num_cores != 0) {
			for (uint8_t i = 0; i < num_cores; ++i)
				thread_pool_.emplace_back([&]{analysePackets();});
		}
		analysePackets();
	} 
private:
	void analysePackets() {
		Buffer buffer; 
		for (;;) {
			socklen_t socket_addr_size = sizeof(sockaddr);
			sockaddr saddr;
			const int32_t size_of_data_received = recvfrom( // thread-safe, happens atomically
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
	void processPacket(Buffer& buffer, uint32_t data_size) {
		const iphdr* ip_header = reinterpret_cast<const iphdr*>(buffer.data() + ETH_HEADER_SIZE);
		const uint16_t mask = (1 << IP_FRAG_OFFSET_SIZE_IN_BITS) - 1;
		const uint16_t fragment_offset = ntohs(ip_header->frag_off) & mask;
		const bool more_fragments = (ntohs(ip_header->frag_off) >> IP_MORE_FRAGMENTS_FLAG) & 1U;
		if (fragment_offset || more_fragments) {
			const auto protocol = static_cast<NetworkProtocol>(ip_header->protocol);
			if (protocol != NetworkProtocol::TCP || protocol != NetworkProtocol::UDP) {
				return;
			}
			const uint8_t ip_hdr_len = ip_header->ihl * 4;
			const uint16_t source_port = ntohs(
				static_cast<uint16_t>(*(buffer.data() + ETH_HEADER_SIZE + ip_hdr_len))
			);
			const uint16_t dest_port = ntohs(
				static_cast<uint16_t>(*(buffer.data() + ETH_HEADER_SIZE + ip_hdr_len + sizeof(uint16_t)))
			);
			IPV4Connection ipv4_conn(
				source_port, 
				dest_port, 
				ntohl(ip_header->saddr), 
				ntohl(ip_header->daddr)
			);
			const uint16_t pkt_id = ntohs(ip_header->id);
			auto& fragmented_pkt = fragmented_packets_[ipv4_conn][pkt_id];
			fragmented_pkt.addPacket(buffer, data_size, fragment_offset, more_fragments);
			if (fragmented_pkt.canBeDefragmented()) {
				auto defragmented_packet = fragmented_pkt.defragmentPacket();
				std::copy_n(defragmented_packet.begin(), defragmented_packet.size(), buffer.begin());
				data_size = defragmented_packet.size();
			}
			else {
				return;
			}
		}
		switch (static_cast<NetworkProtocol>(ip_header->protocol)) {
			case NetworkProtocol::TCP: 
				chooseTCPAnalyzer(buffer, data_size);
				break;
			case NetworkProtocol::UDP:
				chooseUDPAnalyzer(buffer, data_size);
				break;
			default:
				return;
		}
	}
	void reassembleIPFragmentation(const Buffer& buffer, const iphdr* ip_header) {

	}
	void chooseTCPAnalyzer(const Buffer& buffer, const uint32_t data_size) {
		const tcphdr* tcp_header = reinterpret_cast<const tcphdr*>(
			buffer.data() + ETH_HEADER_SIZE + IP_HEADER_SIZE
		);
	}
	void chooseUDPAnalyzer(const Buffer& buffer, const uint32_t data_size) {
		const udphdr* udp_header = reinterpret_cast<const udphdr*>(
			buffer.data() + ETH_HEADER_SIZE + IP_HEADER_SIZE
		);
		const uint16_t src_port = udp_header->uh_sport;
		const uint16_t dst_port = udp_header->uh_dport;
		if (src_port == 53 || dst_port == 53) {

		}
	}
	const int32_t sniffer_fd_;
	std::ofstream log_file;
	using IPHeaderID = uint16_t;
	std::unordered_map<
		IPV4Connection, 
		std::unordered_map<IPHeaderID, FragmentedIPPacket>
	> fragmented_packets_;
	std::vector<std::thread> thread_pool_;
};
}
#endif
