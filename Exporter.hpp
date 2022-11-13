#ifndef __EXPORTER__H__
#define __EXPORTER__H__

#include <string>

#include "Netflow.hpp"

class Exporter
{
private:
	sockaddr_in collector;
	int socketFd;
	int openSocket();

public:
	Exporter(std::string host, uint16_t port);
	~Exporter();

	void send(FlowPacket *flow);
};

#endif //!__EXPORTER__H__