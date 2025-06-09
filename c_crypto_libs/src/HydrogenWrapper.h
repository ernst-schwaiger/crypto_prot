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

    virtual uint8_t getId() const override
    {
        return WRAPPER_ID_LIBHYDROGEN; // ...and the LibHydrogenWrapper shall return 1;
    }

    virtual payload_t hash(std::string const &in) const override;
    virtual payload_t secureRnd(size_t lenBytes) const override;
    
    virtual payload_t setupDH(payload_t const &remotePayload, ICryptoWrapper::Role role) override;
    virtual payload_t updateDH(payload_t const &remotePayload, ICryptoWrapper::Role role) override;
    virtual payload_t finishDH(payload_t  const &remotePayload, ICryptoWrapper::Role role) override;


    // generates IV, encrypts using the symmetric key and returns IV and ciphertext
    virtual std::pair<payload_t, payload_t> encrypt(std::string const &plainText, payload_t const &symmKey) const override;

    // decrypts from IV, symmetric key and ciphertext
    virtual std::string decrypt(std::pair<payload_t, payload_t> const &ivAndCipherText, payload_t const &symmKey) const override;    

    virtual ~HydrogenWrapper()
    {
        // Free allocated resources here
    };
private:
    HydrogenWrapper(); // prevent direct instantiation
    hydro_kx_keypair keyExKeyPair;
    hydro_kx_state keyExState;
    hydro_kx_session_keypair keyPair; // symmetric rx/tx session key pair
};

} // namespace ccl