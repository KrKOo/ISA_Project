#include <iostream>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include "Exporter.hpp"

#define NF5HEADER_SIZE 24
#define NF5RECORD_SIZE 48

Exporter::Exporter(std::string host, uint16_t port)
{
	this->collector = {};
	this->collector.sin_family = AF_INET;
	this->collector.sin_port = htons(port);

	struct hostent *servent;
	if ((servent = gethostbyname(host.c_str())) == NULL)
	{
		throw std::runtime_error("Hostname resolution failed");
	}
	memcpy(&this->collector.sin_addr, servent->h_addr, servent->h_length);

	this->socketFd = openSocket();
}

Exporter::~Exporter()
{
	close(this->socketFd);
}

void Exporter::send(FlowPacket *flow)
{
	size_t packetSize = NF5HEADER_SIZE + (ntohs(flow->header.count) * NF5RECORD_SIZE);
	sendto(this->socketFd, flow, packetSize, 0, (struct sockaddr *)&this->collector, sizeof(this->collector));
}

int Exporter::openSocket()
{
	int sockfd;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}

	return sockfd;
}