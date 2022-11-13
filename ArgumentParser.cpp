#include <iostream>
#include <getopt.h>

#include "ArgumentParser.hpp"

ArgumentParser::ArgumentParser(int argc, char **argv)
{
	this->argc = argc;
	this->argv = argv;
}

// Modified example from
// https://www.man7.org/linux/man-pages/man3/getopt.3.html
Arguments ArgumentParser::parse(Arguments &defaultArguments)
{
	Arguments arguments = defaultArguments;
	const char *shortOptions = "f:c:a:i:m:";
	struct option longOptions[] = {
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}};

	int opt;
	int optIndex;
	while ((opt = getopt_long(this->argc, this->argv, shortOptions, longOptions, &optIndex)) != -1)
	{
		switch (opt)
		{
		case 0:
			break;
		case 'h':
			printHelp();
			exit(0);
		case 'f':
			arguments.filename = getArgument();
			break;
		case 'c':
		{
			std::string netflow_collector = getArgument();
			arguments.netflow_collector_host = netflow_collector.substr(0, netflow_collector.find(":"));

			std::size_t pos = netflow_collector.find(":");
			if (pos != std::string::npos)
			{
				arguments.netflow_collector_port = std::stoi(netflow_collector.substr(pos + 1));
			}
		}
		break;
		case 'a':
			arguments.active_interval = getNumericArgument();
			break;
		case 'i':
			arguments.inactive_interval = getNumericArgument();
			break;
		case 'm':
			arguments.flow_cache_size = getNumericArgument();
			break;
		case '?':
			/* getopt_long already printed an error message. */
			exit(INVALID_ARUMENT_ERROR);
			break;

		default:
			abort();
		}
	}

	return arguments;
}

void ArgumentParser::printHelp()
{
	std::cout << "Usage: ./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]" << std::endl;
}

std::string ArgumentParser::getArgument()
{
	if (optarg == NULL && optind < this->argc && this->argv[optind][0] != '-')
	{
		return this->argv[optind++];
	}
	else
	{
		return optarg;
	}
}

int ArgumentParser::getNumericArgument()
{
	try
	{
		return std::stoi(this->getArgument());
	}
	catch (const std::invalid_argument &e)
	{
		std::cerr << "Invalid argument type" << std::endl;
		exit(INVALID_ARUMENT_ERROR);
	}
}
