#include <vector>
#include <cstdint>
#include <catch2/catch_test_macros.hpp>
#include "LibTomWrapper.h"
#include "HydrogenWrapper.h"
#include "SendReceive.h"

#include <hydrogen.h> // FIXME: Remove

using namespace std;
using namespace ccl;

class TestFixture
{
public:
    TestFixture()
    {
        // init code
        LibTomWrapper::init();
        HydrogenWrapper::init();
    }

    ~TestFixture()
    {
        // cleanup code
    }
};

static TestFixture tf;

TEST_CASE( "Ensure that Key Exchange is working properly in LibTomWrapper " )
{
    auto ltw1 = LibTomWrapper::createInstance();
    auto ltw2 = LibTomWrapper::createInstance();

    payload_t empty;

    payload_t pubKey1 = ltw1->setupDH(empty, ICryptoWrapper::Role::CLIENT);
    payload_t pubKey2 = ltw2->setupDH(pubKey1, ICryptoWrapper::Role::SERVER); // ignored in LibTom

    payload_t sharedSymmKey1 = ltw1->finishDH(pubKey2, ICryptoWrapper::Role::CLIENT);
    payload_t sharedSymmKey2 = ltw2->finishDH(pubKey1, ICryptoWrapper::Role::SERVER);

    REQUIRE(sharedSymmKey1 == sharedSymmKey2);
}

TEST_CASE( "Ensure that SHA256 is working properly" )
{
    auto ltw = LibTomWrapper::createInstance();
    // taken from https://emn178.github.io/online-tools/sha256.html
    payload_t digest_ref = 
    {
        0xa8, 0xa2, 0xf6, 0xeb, 0xe2, 0x86, 0x69, 0x7c, 
        0x52, 0x7e, 0xb3, 0x5a, 0x58, 0xb5, 0x53, 0x95, 
        0x32, 0xe9, 0xb3, 0xae, 0x3b, 0x64, 0xd4, 0xeb, 
        0x0a, 0x46, 0xfb, 0x65, 0x7b, 0x41, 0x56, 0x2c
    };
    payload_t digest = ltw->hash("This is a test.");

    REQUIRE(digest == digest_ref);
}

TEST_CASE( "Ensure that encrypting and decrypring works properly" )
{
    auto ltw = LibTomWrapper::createInstance();

    string plainText="This is my secret message.";
    payload_t key = ltw->secureRnd(32);

    auto ivAndCipherText = ltw->encrypt(plainText, key);
    string decryptedText = ltw->decrypt(ivAndCipherText, key);

    REQUIRE(plainText == decryptedText);
}

TEST_CASE( "Sending and Receiving Udp Packets works properly" )
{
    string myMessage("Hello, World!");
    payload_t byteMsg(begin(myMessage), end(myMessage));

    SendReceive sr("127.0.0.1", 4200, "127.0.0.1", 4200);
    sr.send(byteMsg);

    optional<payload_t> optRxMessage = sr.receive(0);
    REQUIRE(optRxMessage.has_value());

    string rxMessage(begin(*optRxMessage), end(*optRxMessage));
    REQUIRE(myMessage == rxMessage);

    // Nothing more to receive
    optional<payload_t> optRxMessage2 = sr.receive(0);
    REQUIRE(optRxMessage2.has_value() == false);
}

TEST_CASE( "Ensure that encrypting and decrypring with LibHydrogen works properly" )
{
    auto lhw = HydrogenWrapper::createInstance();

    string plainText="This is my secret message.";
    payload_t key = lhw->secureRnd(32);

    auto ivAndCipherText = lhw->encrypt(plainText, key);
    string decryptedText = lhw->decrypt(ivAndCipherText, key);

    REQUIRE(plainText == decryptedText);
}

TEST_CASE( "Ensure that Key Exchange is working properly in HydrogenWrapper " )
{
    auto ltw1 = HydrogenWrapper::createInstance();
    auto ltw2 = HydrogenWrapper::createInstance();

    payload_t empty;

    payload_t payload1 = ltw1->setupDH(empty, ICryptoWrapper::Role::CLIENT);
    payload_t payload2 = ltw2->setupDH(payload1, ICryptoWrapper::Role::SERVER);

    payload_t payload3 = ltw1->updateDH(payload2, ICryptoWrapper::Role::CLIENT);

    payload_t sharedSymmKey1 = ltw1->finishDH(empty, ICryptoWrapper::Role::CLIENT);
    payload_t sharedSymmKey2 = ltw2->finishDH(payload3, ICryptoWrapper::Role::SERVER);

    REQUIRE(sharedSymmKey1 == sharedSymmKey2);
}



TEST_CASE( "Ensure that HydrogenKey Exchange is working properly" )
{
    uint8_t PSK[hydro_kx_PSKBYTES] = 
    {
        0xaf, 0xfe, 0xaf, 0xfe, 0xaf, 0xfe, 0xaf, 0xfe, 
        0xaf, 0xfe, 0xaf, 0xfe, 0xaf, 0xfe, 0xaf, 0xfe, 
        0xaf, 0xfe, 0xaf, 0xfe, 0xaf, 0xfe, 0xaf, 0xfe, 
        0xaf, 0xfe, 0xaf, 0xfe, 0xaf, 0xfe, 0xaf, 0xfe, 
    };

    hydro_kx_keypair clientKeyPair;
    hydro_kx_keypair serverKeyPair;

    hydro_kx_state clientKeyExchangeState;
    hydro_kx_state serverKeyExchangeState;

    hydro_kx_session_keypair clientSessionKeyPair;
    hydro_kx_session_keypair serverSessionKeyPair;

    int status = hydro_init();

    REQUIRE(status == 0);
    hydro_kx_keygen(&clientKeyPair);
    hydro_kx_keygen(&serverKeyPair);

    // 1st message from client to server
    payload_t packet1ClientServer(hydro_kx_XX_PACKET1BYTES);
    hydro_kx_xx_1(&clientKeyExchangeState, packet1ClientServer.data(), PSK);

    // 2nd message from server to client
    payload_t packet2ServerClient(hydro_kx_XX_PACKET2BYTES);
    hydro_kx_xx_2(&serverKeyExchangeState, packet2ServerClient.data(), packet1ClientServer.data(), PSK, &serverKeyPair);

    // 3rd message from client to server
    payload_t packet3ClientServer(hydro_kx_XX_PACKET3BYTES);
    hydro_kx_xx_3(&clientKeyExchangeState, &clientSessionKeyPair, packet3ClientServer.data(), nullptr, packet2ServerClient.data(), PSK, &clientKeyPair);

    // Process 3rd message on server side
    hydro_kx_xx_4(&serverKeyExchangeState, &serverSessionKeyPair, nullptr, packet3ClientServer.data(), PSK);

    REQUIRE(memcmp(&clientSessionKeyPair.rx, &serverSessionKeyPair.tx, hydro_kx_SESSIONKEYBYTES) == 0);
    REQUIRE(memcmp(&clientSessionKeyPair.tx, &serverSessionKeyPair.rx, hydro_kx_SESSIONKEYBYTES) == 0);
}
