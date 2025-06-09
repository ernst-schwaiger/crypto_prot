#include <stdexcept>
#include <algorithm>

#include "SendReceive.h"

using namespace std;
using namespace ccl;

SendReceive::SendReceive(std::string const &localIp, uint16_t localPort, std::string const &remoteIp, uint16_t remotePort)
{
    in_addr tmpAddr;
    if (inet_aton(localIp.c_str(), &tmpAddr) < 0)
    {
        throw runtime_error("Could not convert local IP address");
    }

    m_rxSocket = make_unique<UdpRxSocket>(tmpAddr.s_addr, localPort);

    if (inet_aton(remoteIp.c_str(), &tmpAddr) < 0)
    {
        throw runtime_error("Could not convert remote IP address");
    }

    m_txSocket = make_unique<UdpTxSocket>(tmpAddr.s_addr, remotePort, m_rxSocket->getSocketDescriptor());
}

void SendReceive::send(payload_t const &payload) const
{
    TransmitStatus status = m_txSocket->send(payload);
    if (status.status != 0)
    {
        throw runtime_error("Could not send payload");
    }
}

std::optional<payload_t> SendReceive::receive(uint16_t timeoutMS) const
{
    rx_buffer_t buf;
    struct sockaddr_in remoteSockAddr;
    optional<payload_t> ret;
    
    // Polling for incoming data until there is nothing left to receive or an error happens 
    for (;;)
    {
        ccl::TransmitStatus status = m_rxSocket->receive(buf, remoteSockAddr);

        if (status.status != 0)
        {
             throw runtime_error("Could not receive payload");
        }
        else
        {
            if (status.transmitBytes > 0)
            {
                payload_t payload(&buf[0], &buf[status.transmitBytes]);
                ret = payload;
                break;
            }
        }

        if ((timeoutMS == 0) || (status.status != 0))
        {
            break;
        }

        if (timeoutMS < NO_TIMEOUT)
        {
            usleep(100000); // Sleep for 100 milliseconds
            timeoutMS -= min(timeoutMS, static_cast<uint16_t>(100));
        }
    }

    return ret;
}

payload_t SendReceive::createDHRequest(uint8_t wrapperId, payload_t const &remotePayload) const
{
    return createDHRequestResponse(MSG_ID_DH_REQUEST, wrapperId, remotePayload);
}

payload_t SendReceive::createDHResponse(uint8_t wrapperId, payload_t const &remotePayload) const
{
    return createDHRequestResponse(MSG_ID_DH_RESPONSE, wrapperId, remotePayload);
}

payload_t SendReceive::createDHUpdate(uint8_t wrapperId, payload_t const &remotePayload) const
{
    return createDHRequestResponse(MSG_ID_DH_UPDATE, wrapperId, remotePayload);
}

payload_t SendReceive::createCipherTextAndHash(uint8_t wrapperId, payload_t const &IV, payload_t const &ciphertext, payload_t const &hash) const
{
    payload_t payload;
    payload.reserve(4 + hash.size() + IV.size() + ciphertext.size());
    payload.emplace_back(MSG_ID_CIPHERTEXT_HASH);
    payload.emplace_back(wrapperId);
    payload.emplace_back(static_cast<uint8_t>(hash.size())); // for SHA256, this is 32 bytes, so we are safe here
    payload.emplace_back(static_cast<uint8_t>(IV.size())); // for AES, IV length is 16 bytes, so we are safe here
    payload.insert(end(payload), begin(hash), end(hash));
    payload.insert(end(payload), begin(IV), end(IV));
    payload.insert(end(payload), begin(ciphertext), end(ciphertext));
    return payload;
}

pair<pair<payload_t, payload_t>, payload_t> SendReceive::parseCipherTextAndHash(uint8_t wrapperId, optional<payload_t> const &optClientCipherHash) const
{
    // Validate first four bytes: Message Id, Wrapper Id, Hash Length, IV Length
    if (optClientCipherHash->size() <= 4)
    {
        throw runtime_error("Received truncated Client response");
    }

    if (optClientCipherHash->at(0) != MSG_ID_CIPHERTEXT_HASH)
    {
        throw runtime_error("Received incorrect message id from Client");
    }

    if (optClientCipherHash->at(1) != wrapperId)
    {
        throw runtime_error("Received incorrect wrapper id from Client");
    }

    uint8_t hashLength = optClientCipherHash->at(2);
    uint8_t ivLength = optClientCipherHash->at(3);

    if (optClientCipherHash->size() <= (4U + hashLength + ivLength))
    {
        throw runtime_error("Received truncated Client response");
    }

    payload_t hash(begin(*optClientCipherHash) + 4, begin(*optClientCipherHash) + 4 + hashLength);
    payload_t IV(begin(*optClientCipherHash) + 4 + hashLength, begin(*optClientCipherHash) + 4 + hashLength + ivLength);
    payload_t ciphertext(begin(*optClientCipherHash) + 4 + hashLength + ivLength, end(*optClientCipherHash));

    return pair(pair(IV, ciphertext), hash);
}

payload_t SendReceive::parseDHRequest(uint8_t wrapperId, optional<payload_t> const &optDHRequest) const
{
    return parseDHRequestResponse(MSG_ID_DH_REQUEST, wrapperId, optDHRequest);
}

payload_t SendReceive::parseDHResponse(uint8_t wrapperId, optional<payload_t> const &optDHResponse) const
{
    return parseDHRequestResponse(MSG_ID_DH_RESPONSE, wrapperId, optDHResponse);
}

payload_t SendReceive::parseDHUpdate(uint8_t wrapperId, std::optional<payload_t> const &optDHUpdate) const
{
    return parseDHRequestResponse(MSG_ID_DH_UPDATE, wrapperId, optDHUpdate);
}

payload_t SendReceive::createDHRequestResponse(uint8_t msgId, uint8_t wrapperId, payload_t const &remotePayload) const
{
    payload_t payload;
    payload.reserve(2 + remotePayload.size());
    payload.emplace_back(msgId);
    payload.emplace_back(wrapperId);
    payload.insert(end(payload), begin(remotePayload), end(remotePayload));
    return payload;
}

payload_t SendReceive::parseDHRequestResponse(uint8_t msgId, uint8_t wrapperId, optional<payload_t> const &optDHReqResponse) const
{
    // Validate first two bytes: Message Id and Wrapper Id
    if (optDHReqResponse->size() <= 2)
    {
        throw runtime_error("Received truncated Server response");
    }

    if (optDHReqResponse->at(0) != msgId)
    {
        throw runtime_error("Received incorrect message id from Server");
    }

    if (optDHReqResponse->at(1) != wrapperId)
    {
        throw runtime_error("Received incorrect wrapper id from Server");
    }

    // Rest of message is public key of server
    payload_t ret(begin(*optDHReqResponse) + 2, end(*optDHReqResponse));
    return ret;
}
