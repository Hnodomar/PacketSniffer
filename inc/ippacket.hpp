#ifndef IP_PACKET_HPP
#define IP_PACKET_HPP

#include "connection.hpp"

#include <vector>
#include <array>
#include <algorithm>
#include <cstdint>

/* IP PACKET HEADER
*  Class used to defragment IP packets
*/
namespace PacketSniffing {
class FragmentedIPPacket {
	using Buffer = std::array<uint8_t, MAX_IP_SIZE>;
public:
	void addPacket(const Buffer& buffer, const uint32_t data_size, const uint16_t fo, const bool more_fragments) {
		const iphdr* ip_header = reinterpret_cast<const iphdr*>(buffer.data() + ETH_HEADER_SIZE);
		const uint8_t ip_hdr_len = ip_header->ihl * 4;
		if (!more_fragments) {
			if (defrag_total_size_) {
				throw std::runtime_error("Encountered two IP fragments belonging to same ID and connection tuple that had more fragments set to zero");
			}
			defrag_total_size_ = (fo * 8) + (data_size - ETH_HEADER_SIZE - ip_hdr_len); 
		}
		const uint16_t num_bytes_in_packet = data_size - ETH_HEADER_SIZE - ip_hdr_len;
		const uint16_t ip_header_total_len_field = ntohs(ip_header->tot_len);
		if (num_bytes_in_packet != (ip_header_total_len_field - ETH_HEADER_SIZE)) {
			throw std::runtime_error(
				"Encountered IP header with false length. Stated length: " +
				std::to_string(ip_header_total_len_field) +
				" and the actual length: " +
				std::to_string(num_bytes_in_packet)
			);
		}
		bytes_seen_ += num_bytes_in_packet;
		fragments_.emplace_back(fo, buffer.data(), buffer.data() + data_size);
	}
	bool canBeDefragmented() const {
		return bytes_seen_ == defrag_total_size_;
	}
	[[nodiscard("Discarded defragmented packet")]] 
	std::vector<uint8_t> defragmentPacket() {
		std::sort(
			fragments_.begin(),
			fragments_.end(),
			[](const auto& lhs, const auto& rhs) {
				return lhs.fragment_offset < rhs.fragment_offset;
			}
		);
		std::vector<uint8_t> defragged_packet(0, defrag_total_size_ + 20 + ETH_HEADER_SIZE);
		const ethhdr* eth_header = reinterpret_cast<const ethhdr*>(*(fragments_[0].data.begin()));
		const iphdr* ip_header = reinterpret_cast<const iphdr*>(*(fragments_[0].data.begin() + sizeof(eth_header)));
		memcpy(defragged_packet.data(), eth_header, sizeof(ethhdr));
		memcpy(defragged_packet.data(), ip_header, sizeof(iphdr));
		size_t pos = sizeof(eth_header) + sizeof(iphdr) + 1;
		for (const auto& fragment : fragments_) {
			defragged_packet.insert(
				defragged_packet.begin() + pos, 
				std::make_move_iterator(fragment.data.begin()),
				std::make_move_iterator(fragment.data.end())
			);
		}	
	}
private:
	uint16_t defrag_total_size_ = 0;
	uint16_t bytes_seen_ = 0;
	struct Packet {
		Packet(const uint16_t fragment_offset, const std::vector<uint8_t> data)
		 : fragment_offset(fragment_offset), data(data)
		{}
		const uint16_t fragment_offset;
		const std::vector<uint8_t> data;
	};
	std::vector<Packet> fragments_;
};
}

#endif
