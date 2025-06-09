#include <vector>
#include <cstdint>
#include <catch2/catch_test_macros.hpp>
#include "LibTomWrapper.h"
#include "HydrogenWrapper.h"
#include "SendReceive.h"

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

    payload_t rxMsg = sr.receive(0);

    string rxMessage(begin(rxMsg), end(rxMsg));
    REQUIRE(myMessage == rxMessage);

    // Nothing more to receive
    payload_t rxMessage2 = sr.receive(0);
    REQUIRE(rxMessage2.empty());
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
