#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include "PacketParser.hpp"

PacketParser::PacketParser(FILE *pcapFile, FlowCache *flowCache)
{
	this->pcapFile = pcapFile;
	this->flowCache = flowCache;
}

PacketParser::~PacketParser()
{
}

void PacketParser::parse()
{
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	pcap_t *pcap = pcap_fopen_offline(this->pcapFile, errbuf);
	setFilter(pcap, "icmp || tcp || udp");

	pcap_loop(pcap, 0, packetHandler, (u_char *)(this->flowCache));
	std::cout << errbuf << std::endl;
}

void PacketParser::setFilter(pcap_t *handle, const char *filterString)
{
	struct bpf_program filter;

	if (pcap_compile(handle, &filter, filterString, 0, PCAP_NETMASK_UNKNOWN) == -1)
	{
		throw std::runtime_error("Couldn't parse filter " + std::string(filterString) + ": " + pcap_geterr(handle));
	}
	if (pcap_setfilter(handle, &filter) == -1)
	{
		throw std::runtime_error("Couldn't install filter " + std::string(filterString) + ": " + pcap_geterr(handle));
	}
}

void PacketParser::packetHandler(u_char *args, const struct pcap_pkthdr *header,
								 const u_char *packet)
{
	FlowCache *flowCache = (FlowCache *)args;

	struct ether_header *ethHeader;
	ethHeader = (struct ether_header *)packet;

	int ethType = ntohs(ethHeader->ether_type);
	if (ethType == ETHERTYPE_IP)
	{
		iphdr *ipHeader = (iphdr *)(packet + sizeof(ether_header));

		NF5Record record;

		if (ipHeader->protocol == IPPROTO_TCP)
		{
			tcphdr *tcpHeader = (tcphdr *)(packet + sizeof(ether_header) + sizeof(iphdr));

			record = FlowCache::createRecord(tcpHeader, ipHeader, header->ts);
		}
		else if (ipHeader->protocol == IPPROTO_UDP)
		{
			udphdr *udpHeader = (udphdr *)(packet + sizeof(ether_header) + sizeof(iphdr));
			record = FlowCache::createRecord(udpHeader, ipHeader, header->ts);
		}
		else if (ipHeader->protocol == IPPROTO_ICMP)
		{
			icmphdr *icmpHeader = (icmphdr *)(packet + sizeof(ether_header) + sizeof(iphdr));
			record = FlowCache::createRecord(icmpHeader, ipHeader, header->ts);
		}

		flowCache->upsertRecord(record);
	}
}