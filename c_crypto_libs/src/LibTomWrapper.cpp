#include <stdexcept>
#include <cstring> // std::memset

#include "LibTomWrapper.h"
	
using namespace std;
using namespace ccl;


int LibTomWrapper::m_wprng;

void LibTomWrapper::init()
{
    crypt_mp_init("LibTomMath");

    if (register_hash(&sha256_desc) != CRYPT_OK)
    {
        throw runtime_error("Could not get libtom sha256.");
    }

    if (register_prng(&sprng_desc) != CRYPT_OK)
    {
        throw runtime_error("Could not get libtom secure random generator.");
    }

    if (register_cipher(&aes_desc) == -1)
    {
        throw runtime_error("Could not register rijndael/aes cipher");
    }

    m_wprng = find_prng("sprng");

    if (m_wprng < 0)
    {
        throw runtime_error("Could not get RNG");
    }    
}

LibTomWrapper::LibTomWrapper()
{
    // zero-out ecdh keys so that freeing them works even if they were never initialized by libtomcrpt
    memset(&m_ecdhLocalKey, 0x00, sizeof(m_ecdhLocalKey));
    memset(&m_ecdhRemoteKey, 0x00, sizeof(m_ecdhRemoteKey));
}

payload_t LibTomWrapper::hash(string const &in) const
{
    payload_t ret(32);
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

payload_t LibTomWrapper::secureRnd(size_t lenBytes) const
{
    payload_t ret(lenBytes); // 128 * 8 = 1024 bit random
    prng_state prngState;

    if (rng_make_prng(ret.size() * 8, m_wprng, &prngState, nullptr) != CRYPT_OK)
    {
        throw runtime_error("Could not get sufficient entropy bits.");
    }

    if (rng_get_bytes(ret.data(), ret.size(), nullptr) < ret.size())
    {
        throw runtime_error("Could not get sufficient random data.");
    }

    return ret;
}

payload_t LibTomWrapper::setupDH(payload_t const &remotePayload, ICryptoWrapper::Role role)
{
    prng_state prngState;

    if (role != ICryptoWrapper::Role::CLIENT) {} // symmetric dh, role not needed, silence the compiler

    if (!remotePayload.empty())
    {
        // we are in server mode, we can ignore the data here
    }

    // 128 bit randomness for the key pair
    if (rng_make_prng(128, m_wprng, &prngState, nullptr) != CRYPT_OK)
    {
        throw runtime_error("Could not get sufficient entropy bits.");
    }

    // generate 256-bit ECC key
    if (ecc_make_key(&prngState, m_wprng, 32, &m_ecdhLocalKey) != CRYPT_OK) {
        throw runtime_error("Could not generate ECDH key pair");
    }

    // Query actual length of public key
    unsigned long exportLen = 1;
    uint8_t dummy;
    ecc_export(&dummy, &exportLen, PK_PUBLIC, &m_ecdhLocalKey);
    // Allocate large enough buffer, export public key
    payload_t ret(exportLen);
    if (ecc_export(ret.data(), &exportLen, PK_PUBLIC, &m_ecdhLocalKey) != CRYPT_OK)
    {
        throw runtime_error("Could not export local ECDH public key");
    }

    return ret;
}

payload_t LibTomWrapper::updateDH(payload_t const &remotePayload, ICryptoWrapper::Role role)
{
    // Not used in LibTomWrapper
    payload_t ret;
    if (role != ICryptoWrapper::Role::CLIENT) {} // symmetric dh, role not needed, silence the compiler
    if (remotePayload == remotePayload) {} // to silence the compiler
    return ret;
}


payload_t LibTomWrapper::finishDH(payload_t const &remotePayload, ICryptoWrapper::Role role)
{
    if (role != ICryptoWrapper::Role::CLIENT) {} // symmetric dh, role not needed, silence the compiler

    // remotePayload == remote public key
    if (ecc_import(remotePayload.data(), remotePayload.size(), &m_ecdhRemoteKey) != CRYPT_OK)
    {
        throw runtime_error("Could not import remote ECDH public key");
    }

    uint8_t dummy;
    unsigned long outLen = 0;
    ecc_shared_secret(&m_ecdhLocalKey, &m_ecdhRemoteKey, &dummy, &outLen);
    payload_t secret(outLen);
    if (ecc_shared_secret(&m_ecdhLocalKey, &m_ecdhRemoteKey, secret.data(), &outLen) != CRYPT_OK)
    {
        throw runtime_error("Could not generate shared secret.");
    }

    // create an symmetric key out of the shared secret
    int hash_idx = find_hash("sha256");
    if (hash_idx < 0)
    {
        throw runtime_error("Could not get libtom sha256.");
    }

    payload_t ret(32);

    if (hkdf(hash_idx, nullptr, 0, nullptr, 0, secret.data(), secret.size(), ret.data(), ret.size()) != CRYPT_OK)
    {
        throw runtime_error("Could not derive AES key out of shared secret.");
    }

    return ret;
}

std::pair<payload_t, payload_t> LibTomWrapper::encrypt(std::string const &plainText, payload_t const &symmKey) const
{
    payload_t IV = secureRnd(16); // AES Block Size
    payload_t ciphertext(plainText.size());
    symmetric_CTR ctr;

    int aes = find_cipher("aes");
    if (aes < 0)
    {
        throw runtime_error("Could not retrieve aes cipher");
    }

    if (ctr_start(aes, IV.data(), symmKey.data(), symmKey.size(), 0, CTR_COUNTER_LITTLE_ENDIAN | 4, &ctr) != CRYPT_OK)
    {
        throw runtime_error("Could not initialize colunter mode");
    }

    if (ctr_encrypt(reinterpret_cast<unsigned char const *>(plainText.c_str()), ciphertext.data(), plainText.length(), &ctr) != CRYPT_OK)
    {
        throw runtime_error("Could not encrypt plain text");
    }

    return pair(IV, ciphertext);
}

std::string LibTomWrapper::decrypt(std::pair<payload_t, payload_t> const &ivAndCipherText, payload_t const &symmKey) const
{
    payload_t IV = ivAndCipherText.first;
    payload_t ciphertext = ivAndCipherText.second;
    payload_t plaintext(ciphertext.size());
    symmetric_CTR ctr;

    int aes = find_cipher("aes");
    if (aes < 0)
    {
        throw runtime_error("Could not retrieve aes cipher");
    }

    if (ctr_start(aes, IV.data(), symmKey.data(), symmKey.size(), 0, CTR_COUNTER_LITTLE_ENDIAN | 4, &ctr) != CRYPT_OK)
    {
        throw runtime_error("Could not initialize colunter mode");
    }    

    if (ctr_decrypt(ciphertext.data(), plaintext.data(), ciphertext.size(), &ctr) != CRYPT_OK)
    {
        throw runtime_error("Could not decrypt ciphertext");
    }

    string ret(begin(plaintext), end(plaintext));
    return ret;
}

