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
	void addPacket(const Buffer& buffer, const uint32_t data_size) {

	}
	bool canBeDefragmented() const {

	}
	const IPV4Connection& getConnection() const {
			return connection_;
	}
	[[nodiscard("Discarded defragmented packet")]] 
	std::vector<uint8_t> defragmentPacket() {
		std::sort();
	}
private:
	const uint16_t packetid_;
	const IPV4Connection& connection_;
	using Packet = 
	std::vector<
};
}

#endif
