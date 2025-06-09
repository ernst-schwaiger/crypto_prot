#include <string>
#include <optional>
#include <cstdint>
#include <memory>
#include <utility> // pair

#include <unistd.h>

#include "UdpSocket.h"

namespace ccl {

class SendReceive
{
public:
    SendReceive(std::string const &localIp, uint16_t localPort, std::string const &remoteIp, uint16_t remotePort);

    payload_t createDHRequest(uint8_t wrapperId, payload_t const &remotePayload) const;
    payload_t parseDHRequest(uint8_t wrapperId, std::optional<payload_t> const &optDHRequest) const;

    payload_t createDHUpdate(uint8_t wrapperId, payload_t const &remotePayload) const;
    payload_t parseDHUpdate(uint8_t wrapperId, std::optional<payload_t> const &optDHUpdate) const;

    payload_t createDHResponse(uint8_t wrapperId, payload_t const &remotePayload) const;
    payload_t parseDHResponse(uint8_t wrapperId, std::optional<payload_t> const &optDHResponse) const;

    payload_t createCipherTextAndHash(uint8_t wrapperId, payload_t const &IV, payload_t const &ciphertext, payload_t const &hash) const;
    std::pair<std::pair<payload_t, payload_t>, payload_t> parseCipherTextAndHash(uint8_t wrapperId, std::optional<payload_t> const &optClientCipherHash) const;

    void send(payload_t const &payload) const;
    std::optional<payload_t> receive(uint16_t timeoutMS) const;

private:

    payload_t parseDHRequestResponse(uint8_t msgId, uint8_t wrapperId, std::optional<payload_t> const &optDHReqResponse) const;
    payload_t createDHRequestResponse(uint8_t msgId, uint8_t wrapperId, payload_t const &remotePayload) const;

    std::unique_ptr<UdpRxSocket> m_rxSocket;
    std::unique_ptr<UdpTxSocket> m_txSocket;
};


}