#include <stdexcept>

#include "HydrogenWrapper.h"
	
using namespace std;
using namespace ccl;

void HydrogenWrapper::init()
{
    // Init code for Hydrogen Library comes here
    if (hydro_init() != 0)
    {
        throw runtime_error("Could not init libhydrogen.");
    }    
}

HydrogenWrapper::HydrogenWrapper()
{
    // Initialize state variables of a wrapper instance
}

payload_t HydrogenWrapper::hash(string const &in) const
{
    // Generate a digest out of the in parameter using
    // an arbitrary hashing algorithm the library provides
    // and return that digest

    // Replace dummy implementation
    if (in != in){}; // silence compiler
    payload_t ret(32); // 31 bytes, all zeros

    return ret;
}

payload_t HydrogenWrapper::secureRnd(size_t lenBytes) const
{
    // Generate a secure true random number of length lenBytes
    // and return the random number

    // Replace dummy implementation
    payload_t ret(lenBytes); // all zeros

    return ret;
}

payload_t HydrogenWrapper::setupDH()
{
    // Generate private, public key pair for DH Key exchange
    // return the public key as flat byte stream. For storing
    // the internal state (i.e. the private key), add a class
    // member and store it for usage in finishDH

    // Replace dummy implementation
    payload_t ret(32); // 32 bytes/256 bits all zeros

    return ret;
}

payload_t HydrogenWrapper::finishDH(payload_t &remoteKey)
{
    // generate shared secret out of own (stored) private key and remote
    // public key. Out of the shared secret generate the symmetric key,
    // and return it

    // Replace dummy implementation
    if (remoteKey != remoteKey){}; // silence compiler
    payload_t ret(32);

    return ret;
}

std::pair<payload_t, payload_t> HydrogenWrapper::encrypt(std::string const &plainText, payload_t const &symmKey) const
{
    // generate random IV, encrypt plain text using IV and symmetric key
    // return IV and ciphertext in ret

    // Replace dummy implementation
    payload_t IV = secureRnd(16);
    if (symmKey != symmKey){}; // silence compiler
    payload_t ciphertext(begin(plainText), end(plainText)); // fixme ciphertext is same as plain text here

    return pair(IV, ciphertext);
}

std::string HydrogenWrapper::decrypt(std::pair<payload_t, payload_t> const &ivAndCipherText, payload_t const &symmKey) const
{
    // decrypt ciphertext using IV and symmetric key, convert it into a string
    // return the string
    payload_t IV = ivAndCipherText.first;
    payload_t ciphertext = ivAndCipherText.second;

    // Replace dummy implementation
    if (symmKey != symmKey){}; // silence compiler
    string ret(begin(ciphertext), end(ciphertext)); // plain text equals ciphertext

    return ret;
}
