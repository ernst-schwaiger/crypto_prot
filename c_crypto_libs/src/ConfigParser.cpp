#include <iostream>
#include <fmt/core.h>

#include "ConfigParser.h"

using namespace ccl;
using namespace std;

std::optional<config_t> ccl::getConfigFromOptions(int argc, char *argv[])
{
    optional<config_t> ret;
    config_t parsed_values{ DEFAULT_IP_ADDRESS, DEFAULT_IP_ADDRESS, false, true, {} };
    bool error = false;   
    int8_t c; // in contrast to Intel, char seems to be unsigned on ARM, int8_t works on both architectures

    bool useLibTom = false;
    bool useHydrogen = false;
    bool isServer = false;
    bool isClient = false;

    while ((c = getopt (argc, argv, "l:r:scth")) != -1)
    {
        switch (c)
        {
        case 'l':
            parsed_values.local_ipaddr = optarg;
        break;
        case 'r':
            parsed_values.remote_ipaddr = optarg;
        break;
        case 's':
            isServer = true;
        break;
        case 'c':
            isClient = true;
        break;
        case 't':
            useLibTom = true;
        break;
        case 'h':
            useHydrogen = true;
        break;

        case '?':
        {
            if (optopt == 'l' || optopt == 'r')
            {
                cerr << fmt::format("Option -{} requires an argument.\n", optopt);
            }
            else if (isprint(optopt))
            {
                cerr << fmt::format("Unknown option -{}.\n", optopt);
            }
            else
            {
                cerr << fmt::format("Unknown option character -{}.\n", static_cast<uint16_t>(optopt));
            }
            error = true;
            break;
        }
        default:
            throw runtime_error("Unexpected error parsing command line arguments.\n");
        }
    }

    // Additional parameters without 
    for (int i = optind; i < argc; i++)
    { 
        parsed_values.freeParams.push_back(argv[i]);
    }

    if (isClient == isServer)
    {
        cerr << "Either use -c for client mode or -s for server mode.\n";
        error = true;
    }
    else
    {
        parsed_values.isServer = isServer;
    }

    // 
    if (useLibTom && useHydrogen)
    {
        cerr << "Only use one of LibTomCrypt or Hydrogen.\n";
        error = true;
    }
    else
    {
        // LibTomCrypt is default, flip switch if Hydrogen is explicitly requested
        parsed_values.useLibTom = !useHydrogen;
    }

    if (!error)
    {
        ret = parsed_values;
    }

    return ret;
}

void ccl::printUsage(char *argv0)
{
    cerr << fmt::format("Usage: {} -s|-c [-l <ipaddr>] [-r <ipaddr>] [-t|-h] [<message>]\n", argv0);
    cerr << fmt::format("   -s|-c              run either in server or client mode.\n");
    cerr << fmt::format("   -l <ipaddr>        local IPV4 address, default is {}.\n", DEFAULT_IP_ADDRESS);
    cerr << fmt::format("   -r <ipaddr>        remote IPV4 address, default is {}.\n", DEFAULT_IP_ADDRESS);
    cerr << fmt::format("   [-t|-h]            use LibTomCrypt or Hydrogen, only relevant in client role, default is -t\n");
    cerr << fmt::format("   <message>          message to send, only relevant in client role\n");
}

