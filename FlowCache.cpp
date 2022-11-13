#include <algorithm>
#include <iostream>
#include <cstring>

#include "FlowCache.hpp"

FlowCache::FlowCache(uint32_t flowCacheSize, long activeInterval, long inactiveInterval, Exporter *exporter)
{
	this->flowCacheSize = flowCacheSize;
	this->activeInterval = activeInterval * 1000000;
	this->inactiveInterval = inactiveInterval * 1000000;
	this->exporter = exporter;
	this->flowSequence = 0;
}

FlowCache::~FlowCache()
{
}

void FlowCache::upsertRecord(NF5Record record)
{
	this->currentTime = record.last;
	checkCacheSize();
	checkTimers();

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
		cache.push_back(record);
	}
}

void FlowCache::exportAll()
{
	exportFlows(cache);
}

void FlowCache::checkTimers()
{
	std::vector<NF5Record> flowsToExport;

	for (auto it = this->cache.begin(); it != this->cache.end();)
	{
		if (this->currentTime - it->last > this->inactiveInterval)
		{
			flowsToExport.push_back(*it);
			it = this->cache.erase(it);
		}
		else if (this->currentTime - it->first > this->activeInterval)
		{
			flowsToExport.push_back(*it);
			it = this->cache.erase(it);
		}
		else
		{
			++it;
		}
	}

	if (flowsToExport.size() > 0)
	{
		exportFlows(flowsToExport);
	}
}

void FlowCache::checkCacheSize()
{
	if (this->cache.size() >= this->flowCacheSize)
	{
		exportFlows({popOldestFlow()});
	}
}

NF5Record FlowCache::popOldestFlow()
{
	NF5Record oldest = this->cache[0];
	int index = 0;

	for (size_t i = 0; i < this->cache.size(); i++)
	{
		if (this->cache[i].first < oldest.first)
		{
			oldest = this->cache[i];
			index = i;
		}
	}

	this->cache.erase(this->cache.begin() + index);

	return oldest;
}

void FlowCache::exportFlows(std::vector<NF5Record> flows)
{
	std::vector<NF5Record> chunk;
	for (size_t i = 0; i < flows.size() / 30 + 1; i++)
	{
		for (size_t j = 0; j < 30 && i * 30 + j < flows.size(); j++)
		{
			// NF5Record record = flows[i * 30 + j];
			chunk.push_back(hostToNetworkByteOrder(flows[i * 30 + j]));
		}

		this->exportFlowChunk(chunk);

		chunk.clear();
	}
}

void FlowCache::exportFlowChunk(std::vector<NF5Record> chunk)
{
	this->flowSequence += chunk.size();
	FlowPacket flowPacket = {
		.header = {
			.version = htons(5),
			.count = htons(chunk.size()),
			.sys_uptime = htonl(0),
			.unix_secs = htonl(this->currentTime / 1000),
			.unix_nsecs = htonl((this->currentTime % 1000) * 1000),
			.flow_sequence = htonl(this->flowSequence),
			.engine_type = 0,
			.engine_id = 0,
			.sampling_interval = 0},
		.records = {}};

	memcpy(flowPacket.records, &chunk[0], chunk.size() * sizeof(NF5Record));

	this->exporter->send(&flowPacket);
}

bool FlowCache::compare(const NF5Record &record1, const NF5Record &record2)
{
	return (record1.src_addr == record2.src_addr && record1.dst_addr == record2.dst_addr &&
			record1.src_port == record2.src_port && record1.dst_port == record2.dst_port &&
			record1.prot == record2.prot);
}

NF5Record FlowCache::createRecord(tcphdr *tcpHeader, iphdr *ipHeader, timeval timestamp)
{
	NF5Record record = {};
	record.src_addr = ipHeader->saddr;
	record.dst_addr = ipHeader->daddr;
	record.src_port = tcpHeader->source;
	record.dst_port = tcpHeader->dest;
	record.prot = ipHeader->protocol;
	record.dpkts = htonl(1);
	record.doctets = htonl(ntohs(ipHeader->tot_len));
	record.first = timestamp.tv_sec;
	record.last = timestamp.tv_sec;
	record.tcp_flags = tcpHeader->fin | tcpHeader->syn | tcpHeader->rst | tcpHeader->psh | tcpHeader->ack | tcpHeader->urg;

	return networkToHostByteOrder(record);
}

NF5Record FlowCache::createRecord(udphdr *udpHeader, iphdr *ipHeader, timeval timestamp)
{
	NF5Record record = {};
	record.src_addr = ipHeader->saddr;
	record.dst_addr = ipHeader->daddr;
	record.src_port = udpHeader->source;
	record.dst_port = udpHeader->dest;
	record.prot = ipHeader->protocol;
	record.dpkts = htonl(1);
	record.doctets = htonl(ntohs(ipHeader->tot_len));
	record.first = timestamp.tv_sec;
	record.last = timestamp.tv_sec;

	return networkToHostByteOrder(record);
}

NF5Record FlowCache::createRecord(icmphdr *icmpHeader, iphdr *ipHeader, timeval timestamp)
{
	(void)icmpHeader;
	NF5Record record = {};
	record.src_addr = ipHeader->saddr;
	record.dst_addr = ipHeader->daddr;
	record.prot = ipHeader->protocol;
	record.dpkts = htonl(1);
	record.doctets = htonl(ntohs(ipHeader->tot_len));
	record.first = timestamp.tv_sec;
	record.last = timestamp.tv_sec;

	return networkToHostByteOrder(record);
}

NF5Record FlowCache::hostToNetworkByteOrder(NF5Record record)
{
	record.src_addr = htonl(record.src_addr);
	record.dst_addr = htonl(record.dst_addr);
	record.next_hop = htonl(record.next_hop);
	record.input = htons(record.input);
	record.output = htons(record.output);
	record.dpkts = htonl(record.dpkts);
	record.doctets = htonl(record.doctets);
	record.first = htonl(record.first);
	record.last = htonl(record.last);
	record.src_port = htons(record.src_port);
	record.dst_port = htons(record.dst_port);
	record.src_as = htons(record.src_as);
	record.dst_as = htons(record.dst_as);

	return record;
}

NF5Record FlowCache::networkToHostByteOrder(NF5Record record)
{
	record.src_addr = ntohl(record.src_addr);
	record.dst_addr = ntohl(record.dst_addr);
	record.next_hop = ntohl(record.next_hop);
	record.input = ntohs(record.input);
	record.output = ntohs(record.output);
	record.dpkts = ntohl(record.dpkts);
	record.doctets = ntohl(record.doctets);
	record.first = ntohl(record.first);
	record.last = ntohl(record.last);
	record.src_port = ntohs(record.src_port);
	record.dst_port = ntohs(record.dst_port);
	record.src_as = ntohs(record.src_as);
	record.dst_as = ntohs(record.dst_as);

	return record;
}