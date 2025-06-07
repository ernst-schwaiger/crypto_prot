#pragma once
#include <array>
#include <cstddef>
#include <cstdint>

#include <arpa/inet.h> // struct struct ::sockaddr_in

#include "CommonTypes.h"

namespace ccl {

static constexpr size_t BUFFER_SIZE = 1024;

typedef std::array<uint8_t,  BUFFER_SIZE> rx_buffer_t; 

struct [[nodiscard]] TransmitStatus
{
    size_t transmitBytes;
    uint8_t status;
};

class IRxSocket
{
public:
    virtual ~IRxSocket() {};
    virtual TransmitStatus receive(rx_buffer_t &buf, struct sockaddr_in &remoteAddr) const = 0;
};

class ITxSocket
{
public:
    virtual ~ITxSocket() {};
    virtual TransmitStatus send(payload_t const &payload) const = 0;
    virtual struct ::sockaddr_in const &getRemoteSocketAddr() const = 0;
};

} // namespace