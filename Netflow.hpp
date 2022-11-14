#ifndef __NETFLOW__H__
#define __NETFLOW__H__

#include <stdint.h>

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

// NetFlow v5 packet
struct FlowPacket
{
	NF5Header header;
	NF5Record records[30];
};

#endif //!__NETFLOW__H__