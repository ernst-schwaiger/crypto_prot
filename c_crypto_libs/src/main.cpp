#include <iostream>
#include <iomanip>
#include <fmt/core.h>

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
    ICryptoWrapper::Role const role = ICryptoWrapper::Role::CLIENT;

    if (messageToSend.empty())
    {
        throw runtime_error("Error: trying to send an empty message.");
    }

    // Initiate Diffie-Hellman Key Exchange, send request to Server
    payload_t clientDHRequestData = pCW->setupDH(payload_t(), role);
    payload_t dhRequestMsg = pSR->createDHRequest(pCW->getId(), clientDHRequestData);
    printPayload(dhRequestMsg, "Send DH request message:");
    pSR->send(dhRequestMsg);

    // Process Diffie-Hellman response Message from Server
    payload_t dhResponseMsg = pSR->receive(NO_TIMEOUT);
    printPayload(dhResponseMsg, "Received DH response message:");
    payload_t dhResponseData = pSR->parseDHResponse(pCW->getId(), dhResponseMsg);

    // Optional: Send Diffie-Hellman Update Message back to Server
    payload_t dhUpdateData = pCW->updateDH(dhResponseData, role);
    if (!dhUpdateData.empty())
    {
        payload_t dhUpdateMsg = pSR->createDHUpdate(pCW->getId(), dhUpdateData);
        printPayload(dhUpdateMsg, "Send DH update message:");
        pSR->send(dhUpdateMsg);
    }

    // Derive the symmetric key out of the shared secret
    payload_t symKey = pCW->finishDH(dhResponseData, role);

    // Calculate a hash on the plain text message
    payload_t digest = pCW->hash(messageToSend);

    // Encrypt plain text message
    pair<payload_t, payload_t> ivAndCiphertext = pCW->encrypt(messageToSend, symKey);

    // Send ciphertext, hash of the message is appended in plain text
    payload_t cipherTextAndHashMsg = pSR->createCipherTextAndHash(pCW->getId(), ivAndCiphertext.first, ivAndCiphertext.second, digest);
    printPayload(cipherTextAndHashMsg, "Send ciphertext and hash:");
    pSR->send(cipherTextAndHashMsg);
}

static void server(std::unique_ptr<ICryptoWrapper> CWs[], SendReceive *pSR)
{
    ICryptoWrapper::Role const role = ICryptoWrapper::Role::SERVER;
    optional<payload_t> localDHData;
    optional<payload_t> remoteDHData;

    cout << "Listening to client requests...\n";

    for(;;)
    {
        payload_t rxMsg = pSR->receive(NO_TIMEOUT);

        if (rxMsg.size() >= 2)
        {
            // Second byte in received payload indicates the wrapper we have to use
            uint8_t cwIdx = rxMsg.at(1);
            if (cwIdx >= 2)
            {
                throw runtime_error("Unknown handler field encountered in message.");
            }

            ICryptoWrapper *pCW = CWs[cwIdx].get();
            
            // First byte indicates the type of message we received
            switch(rxMsg.at(0))
            {
                // Diffie-Hellman request arrived from client
                case MSG_ID_DH_REQUEST:
                {
                    printPayload(rxMsg, "Received DH request message:");
                    // Setup internal state using DH data from client
                    remoteDHData = pSR->parseDHRequest(pCW->getId(), rxMsg);
                    localDHData = pCW->setupDH(*remoteDHData, role);

                    // Create DH response message, send back to client
                    payload_t dhResponseMsg = pSR->createDHResponse(pCW->getId(), *localDHData);
                    printPayload(dhResponseMsg, "Send DH response message:");
                    pSR->send(dhResponseMsg);
                    break;
                }

                // Otional: DH Update message from client
                case MSG_ID_DH_UPDATE:
                {
                    // Parse update message data, store it in remoteDHData
                    printPayload(rxMsg, "Received DH update message:");
                    remoteDHData = pSR->parseDHUpdate(pCW->getId(), rxMsg);
                    break;
                }

                // On reception of encrypted message: Derive symmetric key, decrypt ciphertext,
                // compare hash of cleartext message with received hash
                case MSG_ID_CIPHERTEXT_HASH:
                    if (localDHData.has_value() && remoteDHData.has_value())
                    {
                        printPayload(rxMsg, "Received ciphertext and hash:");
                        // derive symmetric key
                        payload_t symKey = pCW->finishDH(*remoteDHData, role);
                        // parse IV, ciphertext, hash
                        pair<pair<payload_t, payload_t>, payload_t> ivCipherTextHash = pSR->parseCipherTextAndHash(pCW->getId(), rxMsg);

                        // decrypt ciphertext
                        std::string plainText = pCW->decrypt(ivCipherTextHash.first, symKey);
                        // calculate hash on plain text
                        payload_t hash = pCW->hash(plainText);

                        if (hash == ivCipherTextHash.second)
                        {
                            // Hash is correct
                            cout << fmt::format("Server received msg: \"{}\", successfully compared hash.\n", plainText);
                        }
                        else
                        {
                            cout << "Received hash differs from calculated one. Am I being hacked?\n";
                        }

                        // Reset state data for subsequent client calls
                        localDHData.reset();
                        remoteDHData.reset();
                    }
                    break;
                default:
                    throw runtime_error(fmt::format("Unknown message type: {} encountered", static_cast<uint16_t>(rxMsg.at(0))));
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
