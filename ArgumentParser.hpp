#ifndef __ARGUMENTPARSER__H__
#define __ARGUMENTPARSER__H__

#define INVALID_ARUMENT_ERROR 2
#define MISSING_ARGUMENT_ERROR 3

struct Arguments
{
	std::string filename;
	std::string netflow_collector_host;
	uint16_t netflow_collector_port;
	long active_interval;
	long inactive_interval;
	int flow_cache_size;
};

class ArgumentParser
{
private:
	// Argument count
	int argc;

	// Argument values
	char **argv;

	// Helper function to check for arguments in an optional argument
	bool optionalArgumentIsPresent();

	// Get the value of the argument
	std::string getArgument();

	// Get the value of the argument as a number
	int getNumericArgument();

	// Print help
	void printHelp();

public:
	ArgumentParser(int argc, char **argv);

	// Parse the arguments
	Arguments parse(Arguments &arguments);
};

#endif //!__ARGUMENTPARSER__H__