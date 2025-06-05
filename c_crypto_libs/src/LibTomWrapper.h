#pragma once

#include "ICryptoWrapper.h"

class LibTomWrapper : public ICryptoWrapper
{
public:
    LibTomWrapper();
    virtual std::vector<uint8_t> hash(std::string const &in) const override;
    virtual std::vector<uint8_t> secure_rnd() const override;
    virtual ~LibTomWrapper() {};
};
