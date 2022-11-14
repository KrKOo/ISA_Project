#ifndef __EXPORTER__H__
#define __EXPORTER__H__

#include <string>

#include "Netflow.hpp"

class Exporter
{
private:
	sockaddr_in collector;
	int socketFd;
	// Opens the socket and returns the file descriptor
	int openSocket();

public:
	Exporter(std::string host, uint16_t port);
	~Exporter();

	// Send a flow packet to the collector
	void send(FlowPacket *flow);
};

#endif //!__EXPORTER__H__