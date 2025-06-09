#pragma once

#include <string>

#include "Common.h"

namespace ccl {

class ICryptoWrapper
{
public:
    enum class Role
    {
        CLIENT,
        SERVER
    };

    // Identifies the wrapper
    virtual uint8_t getId() const = 0;

    // generates an arbitrary hash on a passed string
    virtual payload_t hash(std::string const &in) const = 0;

    // generates a secure random number
    virtual payload_t secureRnd(size_t lenBytes) const = 0;

    // sets up a DH Key Exchange, returns a public key to transmit to the peer
    // if remote payload is empty: nothing to process
    virtual payload_t setupDH(payload_t const &remotePayload, Role const role) = 0;

    // client-only, generate DH update to server. 
    virtual payload_t updateDH(payload_t const &remotePayload, Role const role) = 0;

    // finalizes the DH Key Exchange, returning a shared secret
    virtual payload_t finishDH(payload_t const &remotePayload, Role const role) = 0;

    // generates IV, encrypts and returns IV and ciphertext
    virtual std::pair<payload_t, payload_t> encrypt(std::string const &plainText, payload_t const &symmKey) const = 0;

    // decrypts from IV and ciphertext
    virtual std::string decrypt(std::pair<payload_t, payload_t> const &ivAndCipherText, payload_t const &symmKey) const = 0;

    virtual ~ICryptoWrapper() = default;
};

} // namespace ccl