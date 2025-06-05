#pragma once

#include <vector>
#include <string>
#include <cstdint>

class ICryptoWrapper
{
public:
    // generates an arbitrary hash on a passed string
    virtual std::vector<uint8_t> hash(std::string const &in) const = 0;

    // generates a secure random number
    virtual std::vector<uint8_t> secure_rnd() const = 0;

    virtual ~ICryptoWrapper() = default;
};