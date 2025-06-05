#include <iostream>
#include <iomanip>
#include <array>

extern "C"
{
#include <stdio.h>
#include <hydrogen.h>
}

#include "LibTomWrapper.h"

using namespace std;

void printHash(std::vector<uint8_t> const &in)
{
    for (size_t idx = 0; idx < in.size(); idx++)
    {
        int val = in[idx];
        cout << hex << setw(2) << setfill('0') << static_cast<int>(val);
    }
    cout << "\n";
}

int main(int argc, char *argv[])
{
    try
    {
        if (hydro_init() != 0)
        {
            throw runtime_error("Could not init libhydrogen.");
        }

        std::string in = "Hello, World";

        if (argc == 2)
        {
            in = argv[1];
        }

        LibTomWrapper ltw;
        std::vector<uint8_t> hash = ltw.hash(in);
        printHash(hash);

        std::vector<uint8_t> rnd = ltw.secure_rnd();
        printHash(rnd);
        
    }
    catch(const runtime_error& e)
    {
        std::cerr << e.what() << '\n';
    }

    return 0;
}
