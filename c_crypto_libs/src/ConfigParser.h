#pragma once

#include <optional>
#include <vector>
#include <string>
#include <cstdint>

#include <unistd.h>
#include <netinet/in.h>

#include "Common.h"

namespace ccl {

typedef struct 
{
    std::string local_ipaddr; // own ip address as printable string
    std::string remote_ipaddr; // own ip address as printable string
    bool isServer;
    bool useLibTom; // true -> LibTom, false -> Hydrogen
    std::vector<std::string> freeParams;
} config_t;

extern std::optional<config_t> getConfigFromOptions(int argc, char *argv[]);
extern void printUsage(char *argv0);
}

