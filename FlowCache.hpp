#ifndef __FLOWCACHE__H__
#define __FLOWCACHE__H__

#include <stdint.h>
#include <string>
#include <tuple>
#include <vector>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#include "Netflow.hpp"
#include "Exporter.hpp"

class FlowCache
{
private:
	uint32_t flowCacheSize;
	long activeInterval;
	long inactiveInterval;
	Exporter *exporter;
	std::vector<NF5Record> cache;
	uint32_t flowSequence;
	long currentTime;

	void checkTimers();
	void checkCacheSize();
	void exportFlows(std::vector<NF5Record> flows);
	void exportFlowChunk(std::vector<NF5Record> chunk);
	NF5Record popOldestFlow();
	static bool compare(const NF5Record &record1, const NF5Record &record2);
	static NF5Record hostToNetworkByteOrder(NF5Record record);
	static NF5Record networkToHostByteOrder(NF5Record record);

public:
	FlowCache(uint32_t flowCacheSize, long activeInterval, long inactiveInterval, Exporter *exporter);
	~FlowCache();
	static NF5Record createRecord(tcphdr *tcpHeader, iphdr *ipHeader, timeval timestamp);
	static NF5Record createRecord(udphdr *udpHeader, iphdr *ipHeader, timeval timestamp);
	static NF5Record createRecord(icmphdr *icmpHeader, iphdr *ipHeader, timeval timestamp);
	void upsertRecord(NF5Record record);
	void exportAll();
};

#endif //!__FLOWCACHE__H__
