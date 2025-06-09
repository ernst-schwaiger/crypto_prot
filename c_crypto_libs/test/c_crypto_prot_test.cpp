#include <vector>
#include <cstdint>
#include <catch2/catch_test_macros.hpp>
#include "LibTomWrapper.h"
#include "SendReceive.h"
#include "HydrogenWrapper.h"

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

TEST_CASE( "Ensure that ECDH is working properly" )
{
    auto ltw1 = LibTomWrapper::createInstance();
    auto ltw2 = LibTomWrapper::createInstance();

    payload_t pubKey1 = ltw1->setupDH();
    payload_t pubKey2 = ltw2->setupDH();

    payload_t sharedSecret1 = ltw1->finishDH(pubKey2);
    payload_t sharedSecret2 = ltw2->finishDH(pubKey1);

    REQUIRE(sharedSecret1 == sharedSecret2);
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