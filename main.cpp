#include <iostream>
#include <cstdint>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <fstream>
#include <string>

#include "ArgumentParser.hpp"
#include "PacketParser.hpp"
#include "FlowCache.hpp"

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	Arguments defaultArguments = {
		.filename = "",
		.netflow_collector = "127.0.0.1:2005",
		.active_interval = 60,
		.inactive_interval = 10,
		.flow_cache_size = 1024};

	ArgumentParser argumentParser(argc, argv);
	Arguments arguments = argumentParser.parse(defaultArguments);

	FILE *pcapFile = fopen(arguments.filename.c_str(), "r");
	if (pcapFile == NULL)
	{
		std::cout << "Error opening file" << std::endl;
		return 1;
	}

	FlowCache *flowCache = new FlowCache(arguments.flow_cache_size);

	PacketParser packetParser(pcapFile, flowCache);
	packetParser.parse();

	fclose(pcapFile);

	return 0;
}
