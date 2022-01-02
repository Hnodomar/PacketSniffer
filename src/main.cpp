#include <cstdlib>
#include <iostream>
#include <cstring>
#include <fstream>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>

struct ProtocolCounter {
    int icmp = 0;
    int tcp = 0;
    int udp = 0;
    int igmp = 0;
    int others = 0;
    friend std::ostream& operator<<(std::ostream&, const ProtocolCounter&);
};

std::ostream& operator<<(std::ostream& o, const ProtocolCounter& pc) {
    o << "=== NUM PACKETS ===\n"
      << "TCP: " << pc.tcp
      << "\n UDP: " << pc.udp
      << "\n IGMP: " << pc.igmp
      << "\n ICMP: " << pc.icmp
    << "\n";
    return o;
}

enum ProtocolType {
    ICMP = 1,
    IGMP = 2,
    TCP = 6,
    UDP = 17
};

static void processPacket(unsigned char*, int);
static void printIPHeader(unsigned char*, int);
static void printTCPPacket(unsigned char*, int);
static void printUDPPacket(unsigned char*, int);
static void printICMPPacket(unsigned char*, int);
static void printData(unsigned char*, int);

int num_packets_seen = 0;
ProtocolCounter pc_counter;
sockaddr_in source, dest;
std::ofstream log_file("log.txt", std::fstream::ios_base::out);

int main() {
    sockaddr saddr;
    in_addr in;
    unsigned char* buffer = (unsigned char*)malloc(65536);
    if (!log_file.is_open())
        throw std::runtime_error("Failed to open log file for writing");
    std::cout << "Setting up raw socket\n";
    const int raw_socket_sniff = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_socket_sniff < 0)
        throw std::runtime_error("Failed to successfully open the raw socket");
	setsockopt(raw_socket_sniff, SOL_SOCKET, SO_BINDTODEVICE, "eth0", strlen("eth0") + 1);
    while (true) {
        socklen_t socket_addr_size = sizeof(saddr);
        const int data_recv_size = recvfrom(raw_socket_sniff, buffer, 65536, 0, &saddr, &socket_addr_size);
        if (data_recv_size < 0)
            throw std::runtime_error("Failed to successfully receive a packet");
        processPacket(buffer, data_recv_size);
    }
    log_file.close();
    if (log_file.fail())
        throw std::runtime_error("Failbit set on log file, probably failed to close");
    std::cout << "Successfully finished sniffing packets\n";
    return 0;
}

static void processPacket(unsigned char* buffer, const int size) {
    iphdr* ip_header = reinterpret_cast<iphdr*>(buffer);
    ++num_packets_seen;
    switch (ip_header->protocol) {
        case ProtocolType::ICMP:
            ++pc_counter.icmp;
            break;
        case ProtocolType::IGMP:
            ++pc_counter.igmp;
            break;
        case ProtocolType::TCP:
            ++pc_counter.tcp;
            printTCPPacket(buffer, size);
            break;
        case ProtocolType::UDP:
            ++pc_counter.udp;
            printUDPPacket(buffer, size);
            break;
        default:
            ++pc_counter.others;
            break;
    }
    std::cout << pc_counter;
}

static void printIPHeader(unsigned char* Buffer, const int size) {
	unsigned short iphdrlen;
		
	struct iphdr *iph = (struct iphdr *)Buffer;
	iphdrlen = iph->ihl * 4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	
	log_file << "\n";
	log_file << "IP Header\n";
	log_file << "   |-IP Version        : " << (unsigned int)iph->version << "\n";
	log_file << "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4;
	log_file << "   |-Type Of Service   : %d\n",(unsigned int)iph->tos;
	log_file << "   |-IP Total Length   : " << ntohs(iph->tot_len) << " Bytes(Size of Packet)\n";
	log_file << "   |-Identification    : %d\n",ntohs(iph->id);
	//log_file << "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
	//log_file << "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
	//log_file << "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
	log_file << "   |-TTL      : %d\n",(unsigned int)iph->ttl;
	log_file << "   |-Protocol : %d\n",(unsigned int)iph->protocol;
	log_file << "   |-Checksum : %d\n",ntohs(iph->check);
	log_file << "   |-Source IP        : " << inet_ntoa(source.sin_addr) << "\n";
	log_file << "   |-Destination IP   : " << inet_ntoa(dest.sin_addr) << "\n";
}

static void printTCPPacket(unsigned char* Buffer, const int size) {
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)Buffer;
	iphdrlen = iph->ihl*4;
	
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen);
			
	log_file << "\n\n***********************TCP Packet*************************\n";	
		
	printIPHeader(Buffer, size);
		
	log_file << "\n";
	log_file << "TCP Header\n";
	log_file << "   |-Source Port      : " << ntohs(tcph->source) << "\n";
	log_file << "   |-Destination Port : " << ntohs(tcph->dest) << "\n";
	log_file << "   |-Sequence Number    : " << ntohl(tcph->seq) << "\n";
	log_file << "   |-Acknowledge Number : " << ntohl(tcph->ack_seq) << "\n";
	log_file << "   |-Header Length      : " << (unsigned int)tcph->doff << " DWORDS or " << (unsigned int)tcph->doff * 4 << " BYTES\n";
	//log_file << "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
	//log_file << "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
	log_file << "   |-Urgent Flag          : " << (unsigned int)tcph->urg << "\n";
	log_file << "   |-Acknowledgement Flag : " << (unsigned int)tcph->ack << "\n";
	log_file << "   |-Push Flag            : " << (unsigned int)tcph->psh << "\n";
	log_file << "   |-Reset Flag           : " << (unsigned int)tcph->rst << "\n";
	log_file << "   |-Synchronise Flag     : " << (unsigned int)tcph->syn << "\n";
	log_file << "   |-Finish Flag          : " << (unsigned int)tcph->fin << "\n";
	log_file << "   |-Window         : " << ntohs(tcph->window) << "\n";
	log_file << "   |-Checksum       : " << ntohs(tcph->check) << "\n";
	log_file << "   |-Urgent Pointer : " << tcph->urg_ptr << "\n";
	log_file << "\n";
	log_file << "                        DATA Dump                         ";
	log_file << "\n";
		
	log_file << "IP Header\n";
	printData(Buffer, iphdrlen);
		
	log_file << "TCP Header\n";
	printData(Buffer + iphdrlen, tcph->doff * 4);
		
	log_file << "Data Payload\n";	
	printData(Buffer + iphdrlen + tcph->doff * 4, (size - tcph->doff * 4 - iph->ihl * 4));
						
	log_file << "\n###########################################################";
}

static void printUDPPacket(unsigned char* Buffer, const int Size) {
	
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)Buffer;
	iphdrlen = iph->ihl*4;
	
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen);
	
	log_file << "\n\n***********************UDP Packet*************************\n";
	
	printIPHeader(Buffer, Size);			
	
	log_file << "\nUDP Header\n";
	log_file << "   |-Source Port      : %d\n" , ntohs(udph->source);
	log_file << "   |-Destination Port : %d\n" , ntohs(udph->dest);
	log_file << "   |-UDP Length       : %d\n" , ntohs(udph->len);
	log_file << "   |-UDP Checksum     : %d\n" , ntohs(udph->check);
	
	log_file << "\n";
	log_file << "IP Header\n";
	printData(Buffer , iphdrlen);
		
	log_file << "UDP Header\n";
	printData(Buffer+iphdrlen , sizeof udph);
		
	log_file << "Data Payload\n";	
	printData(Buffer + iphdrlen + sizeof udph ,( Size - sizeof udph - iph->ihl * 4 ));
	
	log_file << "\n###########################################################";
}

static void printICMPPacket(unsigned char* Buffer, const int size) {
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)Buffer;
	iphdrlen = iph->ihl*4;
	
	struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen);
			
	log_file << "\n\n***********************ICMP Packet*************************\n";	
	
	printIPHeader(Buffer, size);
			
	log_file << "\n";
		
	log_file << "ICMP Header\n";
	log_file << "   |-Type : %d",(unsigned int)(icmph->type);
			
	if((unsigned int)(icmph->type) == 11) 
		log_file << "  (TTL Expired)\n";
	else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY) 
		log_file << "  (ICMP Echo Reply)\n";
	log_file << "   |-Code : %d\n",(unsigned int)(icmph->code);
	log_file << "   |-Checksum : %d\n",ntohs(icmph->checksum);
	//log_file << "   |-ID       : %d\n",ntohs(icmph->id));
	//log_file << "   |-Sequence : %d\n",ntohs(icmph->sequence));
	log_file << "\n";

	log_file << "IP Header\n";
	printData(Buffer, iphdrlen);
		
	log_file << "UDP Header\n";
	printData(Buffer + iphdrlen , sizeof icmph);
		
	log_file << "Data Payload\n";	
	printData(Buffer + iphdrlen + sizeof icmph , (size - sizeof icmph - iph->ihl * 4));
	
	log_file << "\n###########################################################";
}

void printData (unsigned char* data, const int size) {
	for(int i=0 ; i < size ; i++) {
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			log_file << "         ";
			for (int j = i-16 ; j < i; j++) {
				if(data[j]>=32 && data[j]<=128)
					log_file << (unsigned char)data[j]; //if its a number or alphabet
				
				else log_file << "."; //otherwise print a dot
			}
			log_file << "\n";
		} 
		
		if(i%16==0) log_file << "   ";
			log_file << (unsigned int)data[i];
				
		if( i==size-1)  //print the last spaces
		{
			for(int j=0; j<15-i%16; j++) log_file << "   "; //extra spaces
			
			log_file << "         ";
			
			for (int j = i - i % 16 ; j <= i; j++) {
				if (data[j] >= 32 && data[j] <= 128) log_file << (unsigned char)data[j];
				else log_file << ".";
			}
			log_file << "\n";
		}
	}
}

