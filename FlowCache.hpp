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
	timeval currentTime;
	timeval systemBootTime;

	// Check timers of all flows in the cache and export the ones that are inactive or active for too long
	void checkTimers();

	// Check if the cache is full and remove the oldest flow if it is
	void checkCacheSize();

	// Create flow chunks (30 flows) and send them to the exporter
	void exportFlows(std::vector<NF5Record> flows);

	// Export a chunk of flows
	void exportFlowChunk(std::vector<NF5Record> chunk);

	// Remove the oldest flow from the cache and return it
	NF5Record popOldestFlow();

	// Compare flows by the cache key
	static bool compare(const NF5Record &record1, const NF5Record &record2);

	// Convert NF5Record structure from host to network byte order
	static NF5Record hostToNetworkByteOrder(NF5Record record);

	// Convert NF5Record structure from network to host byte order
	static NF5Record networkToHostByteOrder(NF5Record record);

	// Set the virtual current time
	void setCurrentTime(timeval time);

	// Convert actual time to system uptime
	uint32_t timeToSystemUptime(timeval time);

	// Return the current system uptime
	uint32_t getSystemUptime();

	// Set the system boot time if not set already
	void initSystemBootTime(timeval time);

public:
	FlowCache(uint32_t flowCacheSize, long activeInterval, long inactiveInterval, Exporter *exporter);
	~FlowCache();

	// Create a NF5Record from a TCP packet
	NF5Record createRecord(tcphdr *tcpHeader, iphdr *ipHeader, timeval timestamp);

	// Create a NF5Record from a UDP packet
	NF5Record createRecord(udphdr *udpHeader, iphdr *ipHeader, timeval timestamp);

	// Create a NF5Record from an ICMP packet
	NF5Record createRecord(icmphdr *icmpHeader, iphdr *ipHeader, timeval timestamp);

	// Insert or update record in the cache and export flows if necessary
	void upsertRecord(NF5Record record);

	// Export all remaining flows
	void exportAll();
};

#endif //!__FLOWCACHE__H__
