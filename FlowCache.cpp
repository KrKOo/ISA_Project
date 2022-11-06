#include <algorithm>
#include <iostream>

#include "FlowCache.hpp"

FlowCache::FlowCache(int flowCacheSize)
{
	this->flowCacheSize = flowCacheSize;
}

FlowCache::~FlowCache()
{
}

void FlowCache::upsertRecord(NF5Record record)
{
	auto pred = [this, record](const NF5Record &r)
	{
		return compare(record, r);
	};

	auto it = std::find_if(cache.begin(), cache.end(), pred);

	if (it != cache.end())
	{
		// update existing record
		it->dpkts += record.dpkts;
		it->doctets += record.doctets;
		it->first = std::min(it->first, record.first);
		it->last = std::max(it->last, record.last);
		it->tcp_flags = it->tcp_flags | record.tcp_flags;
	}
	else
	{
		// insert new record
		cache.push_back(record);
	}
}

bool FlowCache::compare(const NF5Record &record1, const NF5Record &record2)
{
	return (record1.src_addr == record2.src_addr && record1.dst_addr == record2.dst_addr &&
			record1.src_port == record2.src_port && record1.dst_port == record2.dst_port &&
			record1.prot == record2.prot);
}

NF5Record FlowCache::createRecord(tcphdr *tcpHeader, iphdr *ipHeader, timeval timestamp)
{
	// create new record
	NF5Record record = {};
	record.src_addr = ipHeader->saddr;
	record.dst_addr = ipHeader->daddr;
	record.src_port = tcpHeader->source;
	record.dst_port = tcpHeader->dest;
	record.prot = ipHeader->protocol;
	record.dpkts = 1;
	record.doctets = ntohs(ipHeader->tot_len);
	record.first = timestamp.tv_sec;
	record.last = timestamp.tv_sec;
	record.tcp_flags = tcpHeader->fin | tcpHeader->syn | tcpHeader->rst | tcpHeader->psh | tcpHeader->ack | tcpHeader->urg;

	return record;
}

NF5Record FlowCache::createRecord(udphdr *udpHeader, iphdr *ipHeader, timeval timestamp)
{
	// create new record
	NF5Record record = {};
	record.src_addr = ipHeader->saddr;
	record.dst_addr = ipHeader->daddr;
	record.src_port = udpHeader->source;
	record.dst_port = udpHeader->dest;
	record.prot = ipHeader->protocol;
	record.dpkts = 1;
	record.doctets = ntohs(ipHeader->tot_len);
	record.first = timestamp.tv_sec;
	record.last = timestamp.tv_sec;

	return record;
}

NF5Record FlowCache::createRecord(icmphdr *icmpHeader, iphdr *ipHeader, timeval timestamp)
{
	(void)icmpHeader;
	// create new record
	NF5Record record = {};
	record.src_addr = ipHeader->saddr;
	record.dst_addr = ipHeader->daddr;
	record.prot = ipHeader->protocol;
	record.dst_port = 0; // TODO
	record.src_port = 0; // TODO
	record.dpkts = 1;
	record.doctets = ntohs(ipHeader->tot_len);
	record.first = timestamp.tv_sec;
	record.last = timestamp.tv_sec;

	return record;
}