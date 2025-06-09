#include <stdexcept>

#include "HydrogenWrapper.h"

using namespace std;
using namespace ccl;

constexpr char const *HydrogenWrapper::CONTEXT;
constexpr uint8_t HydrogenWrapper::PSK[hydro_kx_PSKBYTES];

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

    
    payload_t ret(32); // 31 bytes, all zeros
    // generic hash without key
    if (hydro_hash_hash(ret.data(), ret.size(), in.data(), in.size(), CONTEXT, NULL) != 0)
    {
        throw runtime_error("hash failed");
    }

    return ret;
}

payload_t HydrogenWrapper::secureRnd(size_t lenBytes) const
{
    // Generate a secure true random number of length lenBytes
    // and return the random number

    // Replace dummy implementation
    payload_t ret(lenBytes); // all zeros
    hydro_random_buf(ret.data(), ret.size());

    return ret;
}

payload_t HydrogenWrapper::setupDH(payload_t const &remotePayload, ICryptoWrapper::Role role)
{
    // Generate private, public key pair for DH Key exchange
    // return the public key as flat byte stream. For storing
    // the internal state (i.e. the private key), add a class
    // member and store it for usage in finishDH

    hydro_kx_keygen(&keyExKeyPair);

    if (role == ICryptoWrapper::Role::CLIENT)
    {
        // Client initiates DH
        payload_t ret(hydro_kx_XX_PACKET1BYTES);
        if (hydro_kx_xx_1(&keyExState, ret.data(), PSK) != 0)
        {
            throw runtime_error("Failed to create DH request.");
        }
        return ret;
    }
    else
    {
        payload_t ret(hydro_kx_XX_PACKET2BYTES);
        // Server initiates DH using init data received from client
        if ((remotePayload.size() != hydro_kx_XX_PACKET1BYTES) ||
            (hydro_kx_xx_2(&keyExState, ret.data(), remotePayload.data(), PSK, &keyExKeyPair) != 0))
        {
            throw runtime_error("Failed to create DH response.");
        }
        return ret;
    }
}

payload_t HydrogenWrapper::updateDH(payload_t const &remotePayload, ICryptoWrapper::Role role)
{
    // generate shared secret out of own (stored) private key and remote
    // public key. Out of the shared secret generate the symmetric key,
    // and return it

    if (role == ICryptoWrapper::Role::CLIENT)
    {
        payload_t ret(hydro_kx_XX_PACKET3BYTES);
        if ((remotePayload.size() != hydro_kx_XX_PACKET2BYTES) ||
            (hydro_kx_xx_3(&keyExState, &keyPair, ret.data(), nullptr, remotePayload.data(), PSK, &keyExKeyPair) != 0))
        {
            throw runtime_error("updating DH (server) failed");
        }
        return ret;
    }
    else
    {
        payload_t ret; // empty return payload (server case)
        return ret;
    }
}


payload_t HydrogenWrapper::finishDH(payload_t const &remotePayload, ICryptoWrapper::Role role)
{
    // generate shared secret out of own (stored) private key and remote
    // public key. Out of the shared secret generate the symmetric key,
    // and return it

    if (role == ICryptoWrapper::Role::SERVER)
    {
        if ((remotePayload.size() != hydro_kx_XX_PACKET3BYTES) ||
            (hydro_kx_xx_4(&keyExState, &keyPair, nullptr, remotePayload.data(), PSK) != 0))
        {
            throw runtime_error("finishing DH (server) failed");
        }

        payload_t ret(begin(keyPair.rx), begin(keyPair.rx) + hydro_kx_SESSIONKEYBYTES);
        return ret;
    }
    else
    {
        // We only use one symmetric key: the tx key of the client, which equals the rx key of the server
        payload_t ret(begin(keyPair.tx), begin(keyPair.tx) + hydro_kx_SESSIONKEYBYTES);
        return ret;
    }
}

pair<payload_t, payload_t> HydrogenWrapper::encrypt(string const &plainText, payload_t const &symmKey) const
{
    // generate random IV, encrypt plain text using IV and symmetric key
    // return IV and ciphertext in ret

    // Replace dummy implementation
    payload_t IV; // = secureRnd(16);
    payload_t ciphertext(hydro_secretbox_HEADERBYTES + plainText.size());
    
    if (hydro_secretbox_encrypt(ciphertext.data(), plainText.data(), plainText.size(), 0, CONTEXT, symmKey.data()) != 0)
    {
        throw runtime_error("encryption failed");
    }
    
    return pair(IV, ciphertext);
}

string HydrogenWrapper::decrypt(pair<payload_t, payload_t> const &ivAndCipherText, payload_t const &symmKey) const
{
    // decrypt ciphertext using IV and symmetric key, convert it into a string
    // return the string
    payload_t IV = ivAndCipherText.first;
    payload_t ciphertext = ivAndCipherText.second;
    payload_t plaintext(ciphertext.size()-hydro_secretbox_HEADERBYTES);

    // Replace dummy implementation
     // silence compiler
    if (hydro_secretbox_decrypt(plaintext.data(), ciphertext.data(), ciphertext.size(), 0, CONTEXT, symmKey.data()) != 0)
    {
        throw runtime_error("decryption failed");
    }
    string ret(begin(plaintext), end(plaintext)); 
    return ret;
}
