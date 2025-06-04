#include <iostream>
#include <iomanip>
#include <array>

extern "C"
{
#include <stdio.h>
#include <tomcrypt.h>
}

using namespace std;

array<unsigned char, 32> getHash(string in)
{
    array<unsigned char, 32> ret;
    size_t out_len = ret.size();

    if (register_hash(&sha256_desc) == -1)
    {
        throw runtime_error("Could not get libtom sha256.");
    }

    int idx = find_hash("sha256");
    if (idx < 0)
    {
        throw runtime_error("Could not get libtom sha256.");
    }

    int result = hash_memory(idx, reinterpret_cast<unsigned char const *>(in.c_str()), in.length(), &ret[0], &out_len);
    if (result < 0)
    {
        throw runtime_error("Could not get run libtom sha256.");
    }

    return ret;
}

void printHash(array<unsigned char, 32> const &in)
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
    std::string in = "Hello, World";

    if (argc == 2)
    {
        in = argv[1];
    }

    array<unsigned char, 32> hash = getHash(in);
    printHash(hash);

    return 0;
}
