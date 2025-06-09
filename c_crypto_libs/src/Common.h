#pragma once

#include <vector>
#include <cstdint>

// Commonly used data types and constants
namespace ccl
{
typedef std::vector<uint8_t> payload_t; 

constexpr uint8_t WRAPPER_ID_LIBTOMCRYPT = 0x00;
constexpr uint8_t WRAPPER_ID_LIBHYDROGEN = 0x01;

constexpr uint8_t MSG_ID_DH_REQUEST = 0x01;
constexpr uint8_t MSG_ID_DH_RESPONSE = 0x02;
constexpr uint8_t MSG_ID_DH_UPDATE = 0x03; // optional third message from client to server
constexpr uint8_t MSG_ID_CIPHERTEXT_HASH = 0x04;

constexpr uint16_t SERVER_PORT = 4200;
constexpr uint16_t CLIENT_PORT = 4201;
constexpr uint16_t NO_TIMEOUT = 0xffffU;

static constexpr char const * DEFAULT_IP_ADDRESS = "127.0.0.1";
}