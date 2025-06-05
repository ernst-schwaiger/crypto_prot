#include <stdexcept>
#include "LibTomWrapper.h"
	
using namespace std;

extern "C"
{
#include <tomcrypt.h>
}

LibTomWrapper::LibTomWrapper()
{
    if (register_hash(&sha256_desc) != CRYPT_OK)
    {
        throw runtime_error("Could not get libtom sha256.");
    }

    if (register_prng(&sprng_desc) != CRYPT_OK)
    {
        throw runtime_error("Could not get libtom secure random generator.");
    }
}

vector<uint8_t> LibTomWrapper::hash(string const &in) const
{
    vector<uint8_t> ret(32);
    size_t out_len = ret.size();

    int idx = find_hash("sha256");
    if (idx < 0)
    {
        throw runtime_error("Could not get libtom sha256.");
    }

    int result = hash_memory(idx, reinterpret_cast<unsigned char const *>(in.c_str()), in.length(), ret.data(), &out_len);
    if (result < 0)
    {
        throw runtime_error("Could not get libtom sha256.");
    }

    return ret;
}

std::vector<uint8_t> LibTomWrapper::secure_rnd() const
{
    std::vector<uint8_t> ret(128); // 128 * 8 = 1024 bit random
    prng_state prngState;

    int wprng = find_prng("sprng");

    if (wprng < 0)
    {
        throw runtime_error("Could not get RNG");
    }

    if (rng_make_prng(ret.size() * 8, wprng, &prngState, nullptr) != CRYPT_OK)
    {
        throw runtime_error("Could not get sufficient entropy bits.");
    }

    if (rng_get_bytes(ret.data(), ret.size(), nullptr) < ret.size())
    {
        throw runtime_error("Could not get sufficient random data.");
    }

    return ret;
}
