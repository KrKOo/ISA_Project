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

// NetFlow v5 header
struct NF5Header
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
struct NF5Record
{
	uint32_t src_addr;
	uint32_t dst_addr;
	uint32_t next_hop;
	uint16_t input;
	uint16_t output;
	uint32_t dpkts;
	uint32_t doctets;
	uint32_t first;
	uint32_t last;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t __pad1;
	uint8_t tcp_flags;
	uint8_t prot;
	uint8_t tos;
	uint16_t src_as;
	uint16_t dst_as;
	uint8_t src_mask;
	uint8_t dst_mask;
	uint16_t __pad2;
};

struct FlowKey
{
	uint32_t src_addr;
	uint32_t dst_addr;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t protocol;
};

class FlowCache
{
private:
	int flowCacheSize;
	std::vector<NF5Record> cache;

	bool compare(const NF5Record &record1, const NF5Record &record2);

public:
	FlowCache(int flowCacheSize);
	~FlowCache();
	static NF5Record createRecord(tcphdr *tcpHeader, iphdr *ipHeader, timeval timestamp);
	static NF5Record createRecord(udphdr *udpHeader, iphdr *ipHeader, timeval timestamp);
	static NF5Record createRecord(icmphdr *icmpHeader, iphdr *ipHeader, timeval timestamp);
	void upsertRecord(NF5Record record);
};

#endif //!__FLOWCACHE__H__
