# crypto_prot
Basic Cryptographic Protocols implemented in Java

## Preconditions

- OpenSSL installed
- OpenJDK 21 installed
- gradle 8.x installed, see https://gradle.org/install/ (Version 4.x, like installed on Ubuntu, won't work!)

## build and run tests

- run `./gradlew build`

## get test coverage via JaCoCo

- run `./gradlew test jacocoTestReport`

## Client-Server Protocol

Client and Server exchange messages via localhost:12345/Tcp

All multibyte payload entities are serialized in Big-Endian byte order, i.e. MSB comes first, LSB comes last
First Message byte is MsgId, index of the message: 1..6
For each handshake, Random_Client, Random_Server are generated just once.
Peers generate by using private key of their certificate, verify payload using public key of Peers certificate.
Signature is calculated over all bytes up to the signature itself.
Certificates are verified for validity, expected CN, and checked that they are signed by a common root certificate.

- Message 1 (Client -> Server): MsgId | Random_Client/4Bytes
- Message 2 (Server -> Client): MsgId | Random_Server/4Bytes | Random_Client/4Bytes | Server_Cert_Len/4Bytes | Server_Cert | Signature
- Message 3 (Client -> Server): MsgId | Random_Server/4Bytes | Random_Client/4Bytes | Client_Cert_Len/4Bytes | Client_Cert | Signature
- Message 4 (Server -> Client): MsgId | Random_Server/4Bytes | Random_Client/4Bytes | PubKey_e_Len/4Bytes | PubKey_m_Len/4Bytes | PubKey_e | PubKey_m | Signature
- Message 5 (Client -> Server): MsgId | Random_Server/4Bytes | Random_Client/4Bytes | Ciphertext_Len/4Bytes | Ciphertext | Signature
- Message 6 (Server -> Client): MsgId | Random_Server/4Bytes | Random_Client/4Bytes | PubKey_DSA_Len/4Bytes | PubKey_DSA_Signature_Len | PubKey_DSA | PubKey_DSA_Signature

To run the protocol:
- Run server via gradlew `./gradlew :server:run`.
- Run client via gradlew: `./gradlew :client:run --args <secret message>`.

After a few seconds, the client should have terminated with a happy message. The traffic
between client and server is exchanged can be seen on wireshark, localhost:12345/Tcp

## TODO

- Describe Client/Server Protocol
- Describe source code structure
- Describe where required function impls can be found and run
