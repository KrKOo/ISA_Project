#ifndef __PACKETPARSER__H__
#define __PACKETPARSER__H__

#include <iostream>
#include <pcap/pcap.h>

#include "FlowCache.hpp"

class PacketParser
{
private:
	FILE *pcapFile;
	FlowCache *flowCache;

	void setFilter(pcap_t *handle, const char *filter);
	static void packetHandler(u_char *args, const struct pcap_pkthdr *header,
							  const u_char *packet);

public:
	PacketParser(FILE *pcapFile, FlowCache *flowCache);
	~PacketParser();

	void parse();
};

#endif //!__PACKETPARSER__H__