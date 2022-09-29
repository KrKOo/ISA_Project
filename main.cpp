#include <iostream>
#include <cstdint>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <fstream>
#include <string>

// NetFlow v5 header
struct NF5_HEADER
{
	uint16_t version;
	uint16_t count;
	uint32_t sys_uptime;
	uint32_t unix_secs;
	uint32_t unix_nsecs;
	uint32_t flow_sequence;
	uint8_t engine_type;
	uint8_t engine_id;
	uint8_t sampling_interval;
};

// NetFlow v5 record
struct NF5_RECORD
{
	uint32_t srcaddr;
	uint32_t dstaddr;
	uint32_t nexthop;
	uint16_t input;
	uint16_t output;
	uint32_t dpkts;
	uint32_t doctets;
	uint32_t first;
	uint32_t last;
	uint16_t srcport;
	uint16_t dstport;
	uint8_t pad1;
	uint8_t tcp_flags;
	uint8_t prot;
	uint8_t tos;
	uint16_t src_as;
	uint16_t dst_as;
	uint8_t src_mask;
	uint8_t dst_mask;
	uint16_t pad2;
};

void packet_handler(u_char *args, const struct pcap_pkthdr *header,
					const u_char *packet)
{
	(void)args;
	(void)packet;
	struct ether_header *eth_header;
	eth_header = (struct ether_header *)packet;

	int eth_type = ntohs(eth_header->ether_type);
	if (eth_type == ETHERTYPE_IP)
	{
		iphdr *ip_header = (iphdr *)packet + sizeof(ether_header);

		if (ip_header->protocol == IPPROTO_TCP)
		{
		}
		else if (ip_header->protocol == IPPROTO_UDP)
		{
		}
		else if (ip_header->protocol == IPPROTO_ICMP)
		{
		}
	}
}

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	char errbuf[PCAP_ERRBUF_SIZE];
	FILE *pcapFile = fopen("data/flow.pcap", "r");
	if (pcapFile == NULL)
	{
		std::cout << "Error opening file" << std::endl;
		return 1;
	}

	pcap_t *pcap = pcap_fopen_offline(pcapFile, errbuf);
	pcap_loop(pcap, 0, packet_handler, NULL);
	return 0;
}
