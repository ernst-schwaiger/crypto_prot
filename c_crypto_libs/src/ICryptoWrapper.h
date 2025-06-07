#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <utility>

#include "CommonTypes.h"

namespace ccl {

class ICryptoWrapper
{
public:
    // Identifies the wrapper
    virtual uint8_t getId() const = 0;

    // generates an arbitrary hash on a passed string
    virtual payload_t hash(std::string const &in) const = 0;

    // generates a secure random number
    virtual payload_t secureRnd(size_t lenBytes) const = 0;

    // sets up a DH Key Exchange, returns a public key to transmit to the peer
    virtual payload_t setupDH() = 0;

    // finalizes the DH Key Exchange, returning a shared secret
    virtual payload_t finishDH(payload_t &remote_key) = 0;

    // generates IV, encrypts and returns IV and ciphertext
    virtual std::pair<payload_t, payload_t> encrypt(std::string const &plainText, payload_t const &symmKey) const = 0;

    // decrypts from IV and ciphertext
    virtual std::string decrypt(std::pair<payload_t, payload_t> const &ivAndCipherText, payload_t const &symmKey) const = 0;

    virtual ~ICryptoWrapper() = default;
};

} // namespace ccl