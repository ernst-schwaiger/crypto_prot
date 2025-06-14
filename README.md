# crypto_prot

## Preconditions

- OpenSSL installed
- OpenJDK 21 installed
- gradle 8.x installed, see https://gradle.org/install/ (Version 4.x, like installed on Ubuntu, won't work!)

## basics

Basic cryptographic primitives implemented in Java, client-server protocol showcasing (parts of) these primitives.

[Basics](./basics/README.md)

## MQV

Menezes Qu Vanstone Key Exchange protocol implemented in Java

[MQV](./mqv/README.md)

## Merkle Signatures

Merkle Signatures built ontop of Lamport One-Time Signatures implemented in Java

[merkle](./merkle/README.md)

## Needham-Schroeder Protocol

Protocol for exchanging symmetric/asymmetric keys, implemented in Java

[needham_schoeder](./needham_schroeder/README.md)

## C Crypto Libraries

Implementation of a custom protocol using LibTomMath and Hydrogen

[c_crypto_libs](./c_crypto_libs/README.md)
