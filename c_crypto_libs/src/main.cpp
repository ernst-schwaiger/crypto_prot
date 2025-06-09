#include <iostream>
#include <iomanip>
#include <array>

#include <stdio.h>
#include <hydrogen.h>

#include "ConfigParser.h"
#include "LibTomWrapper.h"
#include "HydrogenWrapper.h"
#include "SendReceive.h"

using namespace std;
using namespace ccl;

static uint8_t printChar(uint8_t in)
{
    return ((in >= 32) && (in <= 126)) ? in : '.';
}

static void printPayload(payload_t const &in, string const &header)
{
    cout << header << "\n";
    std::stringstream ss;
    for (size_t idx = 0; idx < in.size(); idx++)
    {
        int val = in[idx];
        ss << printChar(val);
        cout << hex << setw(2) << setfill('0') << static_cast<int>(val) << " ";
        if (idx % 16 == 7)
        {
            cout << " ";
            ss << " ";
        }
        if (idx % 16 == 15)
        {
            cout << "  " << ss.str() << "\n";
            ss.str("");
            ss.clear();
        }
    }

    // Pad the last line so the printable chars are aligned
    uint8_t padLen = ((16 - (in.size() % 16)) * 3) + 3;
    if (((in.size() % 16) >=8))
    {
        padLen--;
    }
    string padding(padLen, ' ');
    
    cout << padding << ss.str() << "\n";
}

static void client(ICryptoWrapper *pCW, SendReceive *pSR, string messageToSend)
{
    payload_t empty;
    ICryptoWrapper::Role const role = ICryptoWrapper::Role::CLIENT;
    payload_t clientDHRequestData = pCW->setupDH(empty, role);
    payload_t dhRequest = pSR->createDHRequest(pCW->getId(), clientDHRequestData);
    printPayload(dhRequest, "Send DH request message:");
    pSR->send(dhRequest);

    optional<payload_t> optdhResponse = pSR->receive(NO_TIMEOUT);
    printPayload(*optdhResponse, "Received DH response message:");
    payload_t dhResponseData = pSR->parseDHResponse(pCW->getId(), optdhResponse);

    payload_t dhUpdateData = pCW->updateDH(dhResponseData, role);
    if (!dhUpdateData.empty())
    {
        // For the DH, client has to send a DH update to server
        // FIXME: update finishData
        payload_t dhUpdate = pSR->createDHUpdate(pCW->getId(), dhUpdateData);
        printPayload(dhUpdate, "Send DH update message:");
        pSR->send(dhUpdate);
    }

    payload_t symKey = pCW->finishDH(dhResponseData, role);

    payload_t digest = pCW->hash(messageToSend);
    pair<payload_t, payload_t> ivAndCiphertext = pCW->encrypt(messageToSend, symKey);
    payload_t cipherTextAndHash = pSR->createCipherTextAndHash(pCW->getId(), ivAndCiphertext.first, ivAndCiphertext.second, digest);
    printPayload(cipherTextAndHash, "Send ciphertext and hash:");
    pSR->send(cipherTextAndHash);
}

static void server(std::unique_ptr<ICryptoWrapper> CWs[], SendReceive *pSR)
{
    ICryptoWrapper::Role const role = ICryptoWrapper::Role::SERVER;
    optional<payload_t> localDHPubKey;
    optional<payload_t> remoteDHPubKey;

    for(;;)
    {
        optional<payload_t> optRxPayload = pSR->receive(NO_TIMEOUT);

        if (optRxPayload.has_value() && optRxPayload->size() >= 2)
        {
            // Second byte in received payload indicates the wrapper we have to use
            uint8_t cwIdx = optRxPayload->at(1);
            if (cwIdx >= 2)
            {
                runtime_error("Unknown handler field encountered in message.");
            }

            ICryptoWrapper *pCW = CWs[cwIdx].get();
            
            // First byte indicates the type of message we received
            switch(optRxPayload->at(0))
            {
                case MSG_ID_DH_REQUEST:
                {
                    printPayload(*optRxPayload, "Received DH request message:");
                    remoteDHPubKey = pSR->parseDHRequest(pCW->getId(), optRxPayload);
                    localDHPubKey = pCW->setupDH(*remoteDHPubKey, role);
                    payload_t dhResponse = pSR->createDHResponse(pCW->getId(), *localDHPubKey);
                    printPayload(dhResponse, "Send DH response message:");
                    pSR->send(dhResponse);
                    break;
                }
                case MSG_ID_DH_UPDATE:
                {
                    printPayload(*optRxPayload, "Received DH update message:");
                    remoteDHPubKey = pSR->parseDHUpdate(pCW->getId(), optRxPayload);
                    break;
                }
                case MSG_ID_CIPHERTEXT_HASH:
                    if (localDHPubKey.has_value() && remoteDHPubKey.has_value())
                    {
                        printPayload(*optRxPayload, "Received ciphertext and hash:");
                        payload_t symKey = pCW->finishDH(*remoteDHPubKey, role);
                        pair<pair<payload_t, payload_t>, payload_t> ivCipherTextHash = pSR->parseCipherTextAndHash(pCW->getId(), optRxPayload);
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
    int ret = 0;
    try
    {
        std::optional<config_t> optCfg = getConfigFromOptions(argc, argv);

        if (optCfg.has_value())
        {
            // Set up Libraries, wrappers for accessing them
            LibTomWrapper::init();
            HydrogenWrapper::init();
            std::unique_ptr<ICryptoWrapper> CWs[2];
            CWs[WRAPPER_ID_LIBTOMCRYPT] = LibTomWrapper::createInstance();
            CWs[WRAPPER_ID_LIBHYDROGEN] = HydrogenWrapper::createInstance();

            // Set up Udp Sockets for sending/receiving
            uint16_t localPort  = optCfg->isServer ? SERVER_PORT : CLIENT_PORT;
            uint16_t remotePort = optCfg->isServer ? CLIENT_PORT : SERVER_PORT;
            SendReceive sr(optCfg->local_ipaddr, localPort, optCfg->remote_ipaddr, remotePort);

            if (optCfg->isServer)
            {
                server(CWs, &sr);
            }
            else
            {
                string message = optCfg->freeParams.empty() ? 
                    "All your base are belong to us." : 
                    optCfg->freeParams.at(0);

                uint8_t wrapperIdx = optCfg->useLibTom ? WRAPPER_ID_LIBTOMCRYPT : WRAPPER_ID_LIBHYDROGEN;
                ICryptoWrapper *pCW = CWs[wrapperIdx].get();
                client(pCW, &sr, message);
            }
        }
        else
        {
            printUsage(argv[0]);
            ret = 1;
        }

    }
    catch(const runtime_error& e)
    {
        std::cerr << e.what() << '\n';
    }

    return ret;
}
