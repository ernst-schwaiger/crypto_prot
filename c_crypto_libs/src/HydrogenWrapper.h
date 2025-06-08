#pragma once
#include <memory>
#include <hydrogen.h>

#include "ICryptoWrapper.h"
#include "Common.h"

namespace ccl {

class HydrogenWrapper : public ICryptoWrapper
{
public:
    static void init(); // call this before any other method!
    static std::unique_ptr<ICryptoWrapper> createInstance()
    {
        return std::unique_ptr<HydrogenWrapper>(new HydrogenWrapper());        
    }

    virtual uint8_t getId() const
    {
        return WRAPPER_ID_LIBHYDROGEN; // ...and the LibHydrogenWrapper shall return 1;
    }

    virtual payload_t hash(std::string const &in) const override;
    virtual payload_t secureRnd(size_t lenBytes) const override;
    
    virtual payload_t setupDH() override;
    virtual payload_t finishDH(payload_t &remote_key) override;

    // generates IV, encrypts using the symmetric key and returns IV and ciphertext
    virtual std::pair<payload_t, payload_t> encrypt(std::string const &plainText, payload_t const &symmKey) const;

    // decrypts from IV, symmetric key and ciphertext
    virtual std::string decrypt(std::pair<payload_t, payload_t> const &ivAndCipherText, payload_t const &symmKey) const;    

    virtual ~HydrogenWrapper()
    {
        // Free allocated resources here
    };
private:
    HydrogenWrapper(); // prevent direct instantiation 
};

} // namespace ccl