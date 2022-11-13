#include <iostream>
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
		.netflow_collector_host = "127.0.0.1",
		.netflow_collector_port = 2055,
		.active_interval = 60,
		.inactive_interval = 10,
		.flow_cache_size = 1024};

	ArgumentParser argumentParser(argc, argv);
	Arguments arguments = argumentParser.parse(defaultArguments);

	FILE *pcapFile = stdin;
	if (arguments.filename != "")
	{
		pcapFile = fopen(arguments.filename.c_str(), "r");
		if (pcapFile == NULL)
		{
			std::cout << "Error opening file" << std::endl;
			return 1;
		}
	}

	Exporter exporter(arguments.netflow_collector_host, arguments.netflow_collector_port);
	FlowCache *flowCache = new FlowCache(arguments.flow_cache_size, arguments.active_interval, arguments.inactive_interval, &exporter);

	PacketParser packetParser(pcapFile, flowCache);
	packetParser.parse();

	fclose(pcapFile);

	return 0;
}
