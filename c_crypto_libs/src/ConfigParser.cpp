#include <iostream>

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

    while ((c = getopt (argc, argv, "l:r:sth")) != -1)
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
            parsed_values.isServer = true;
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
                cerr << "Option -" << optopt << "requires an argument\n";
            }
            else if (isprint(optopt))
            {
                cerr << "Unknown option -" << optopt << ".\n";
            }
            else
            {
                cerr << "Unknown option character -" << static_cast<uint16_t>(optopt) << ".\n";
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
    cerr << "Usage: " << argv0 << " [-l <ipaddr>] [-r <ipaddr>] [-s] [-t|-h]<message>\n";
    cerr << "   -l <ipaddr>        local IPV4 address, default is " << DEFAULT_IP_ADDRESS <<".\n";
    cerr << "   -r <ipaddr>        remote IPV4 address, default is " << DEFAULT_IP_ADDRESS <<".\n";
    cerr << "   -s                 assume server role, if left out assume client role\n";
    cerr << "   [-t|-h]            use LibTomCrypt or Hydrogen, only relevant in client role, default is -t\n";
    cerr << "   <message>          message to send, only relevant in client role\n";
}

