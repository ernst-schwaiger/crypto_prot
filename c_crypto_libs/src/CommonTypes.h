#pragma once

#include <vector>
#include <cstdint>

namespace ccl
{
constexpr uint8_t WRAPPER_ID_LIBTOMCRYPT = 0x00;
constexpr uint8_t WRAPPER_ID_LIBHYDROGEN = 0x01;

constexpr uint8_t MSG_ID_DH_REQUEST = 0x01;
constexpr uint8_t MSG_ID_DH_RESPONSE = 0x02;
constexpr uint8_t MSG_ID_CIPHERTEXT_HASH = 0x03;

constexpr uint16_t NO_TIMEOUT = 0xffffU;

typedef std::vector<uint8_t> payload_t; 
}