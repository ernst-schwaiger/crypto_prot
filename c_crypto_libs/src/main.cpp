#include <iostream>
#include <iomanip>
#include <array>

#include <stdio.h>
#include <hydrogen.h>

#include "LibTomWrapper.h"
#include "SendReceive.h"

using namespace std;
using namespace ccl;

void printHash(payload_t const &in)
{
    for (size_t idx = 0; idx < in.size(); idx++)
    {
        int val = in[idx];
        cout << hex << setw(2) << setfill('0') << static_cast<int>(val);
    }
    cout << "\n";
}

void client(ICryptoWrapper *pCW, SendReceive *pSR, string messageToSend)
{
    payload_t ownDHPubKey = pCW->setupDH();
    pSR->sendDHRequest(pCW->getId(), ownDHPubKey);

    payload_t remoteDHPubKey = pSR->parseDHResponse(pCW->getId());
    payload_t symKey = pCW->finishDH(remoteDHPubKey);

    payload_t digest = pCW->hash(messageToSend);
    pair<payload_t, payload_t> ivAndCiphertext = pCW->encrypt(messageToSend, symKey);
    pSR->sendCipherTextAndHash(pCW->getId(), ivAndCiphertext.first, ivAndCiphertext.second, digest);
}

// FIXME: Add wrappers for both LibTomCrypt and LibHydrogen
void server(ICryptoWrapper *pCW, SendReceive *pSR)
{
    optional<payload_t> localDHPubKey;
    optional<payload_t> remoteDHPubKey;

    for(;;)
    {
        optional<payload_t> optRxPayload = pSR->receive(NO_TIMEOUT);

        if (optRxPayload.has_value() && optRxPayload->size() >= 1)
        {
            switch(optRxPayload->at(0))
            {
                case MSG_ID_DH_REQUEST:
                    remoteDHPubKey = pSR->parseDHRequest(pCW->getId());
                    localDHPubKey = pCW->setupDH();
                    pSR->sendDHResponse(pCW->getId(), *localDHPubKey);
                    break;
                case MSG_ID_CIPHERTEXT_HASH:
                    if (localDHPubKey.has_value() && remoteDHPubKey.has_value())
                    {
                        payload_t symKey = pCW->finishDH(*remoteDHPubKey);
                        pair<pair<payload_t, payload_t>, payload_t> ivCipherTextHash = pSR->parseCipherTextAndHash(pCW->getId());
                        std::string plainText = pCW->decrypt(ivCipherTextHash.first, symKey);
                        payload_t hash = pCW->hash(plainText);

                        if (hash == ivCipherTextHash.second)
                        {
                            // Hash is correct
                            cout << "Server received msg: \"" << plainText << "\", successfully compared hash.\n";
                        }

                        localDHPubKey.reset();
                        remoteDHPubKey.reset();
                    }
                    break;
                default:
                    throw runtime_error("Unknown message type encountered");
            }
        }
    }
}


int main(int argc, char *argv[])
{
    try
    {
        // FIXME: move this to HydroGenWrapper class
        if (hydro_init() != 0)
        {
            throw runtime_error("Could not init libhydrogen.");
        }

        std::string in = "Hello, World";

        if (argc == 2)
        {
            in = argv[1];
        }
        LibTomWrapper::init();
        auto ltw = LibTomWrapper::createInstance();
        payload_t hash = ltw->hash(in);
        printHash(hash);

        payload_t rnd = ltw->secureRnd(16);
        printHash(rnd);

        payload_t dhPublic = ltw->setupDH();
        payload_t secret = ltw->finishDH(dhPublic);
        
    }
    catch(const runtime_error& e)
    {
        std::cerr << e.what() << '\n';
    }

    return 0;
}
