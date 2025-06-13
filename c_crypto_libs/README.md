# C Crypto Libraries
Group 3: Lorenzo Haidinger, Samuel Kominek, Stefan Ohnewith, Ernst Schwaiger

## Preconditions

For building the project, the following dependencies must be installed upfront:

```bash
sudo apt install gcc g++ make cmake
```

LibTomCrypt uses libtommath as a dependency. It can be checked out from github, built and (optionally) installed:

```bash
git clone https://github.com/libtom/libtommath.git
mkdir libtommath/build
cd libtommath/build
cmake ..
make -sj
```

If the `cmake` command in `c_crypto_libs` reports error messages concerning missing `libtommath`, invoke 
`sudo make install` in the `build` folder of `libtommath` and repeat building `c_crypto_libs`.

## Build and run

To build the project for debugging (for release builds, use `-DCMAKE_BUILD_TYPE=Release`):
```bash
cd c_crypto_libs
mkdir -p build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -sj
```

Run the unit tests via `./c_crypto_prot_test`.

The binary can be executed in both server and client roles. The server uses LibTomCrypt or Hydrogen
depending on the requests it receives from the client. For the client `-t` (default) will use
LibTomCrypt and `-h` will use Hydrogen.

Usage:
```
Usage: ./c_crypto_prot [-l <ipaddr>] [-r <ipaddr>] [-s] [-t|-h]<message>
   -l <ipaddr>        local IPV4 address, default is 127.0.0.1.
   -r <ipaddr>        remote IPV4 address, default is 127.0.0.1.
   -s                 assume server role, if left out assume client role
   [-t|-h]            use LibTomCrypt or Hydrogen, only relevant in client role, default is -t
   <message>          message to send, only relevant in client role
```

## TODO

## Slide Deck Input

### Github Metrics

| Category | LibTomCrypt | LibHydrogen 
|----------|--------|------------|
| Github | https://github.com/libtom/libtomcrypt | https://github.com/jedisct1/libhydrogen
| License | LibTom License (permissive) | ISC License (permissive)
| Contributors total/active | 53/1 | 26/1
| Open bugs | 2 | 0
| Open PRs 2025/Total| 1/14 | 0/0
| Commits 2025/total| 40/2400 | 4/390
| Lines of Code | 60k | 3k
| Test Line Coverage | ~90% | n/a
| Stars | 1.7k | 700
| Forks | 480 | 105

### Our Experience with Libraries

#### LibTomCrypt

LibTomCrypt is a portable ISO C (C99?) library providing cryptographic primitives for implementing cryptosystems. 
Key Features:
- Symmetric ciphers
- One-way hashes
- Pseudo random number generators
- Public key cryptography

For each type of primitive it provides multiple implementations, e.g public key cryptography based on RSA or Elliptic curves, >30 hashing functions, >20 symmetric ciphers which can be combined with
several modes of operation.

The interfaces are kept very uniform for each type of primitive, e.g. switching to a different symmetric cipher only requires little change in the client code.

The generic interfaces also allow an extension of the library by client code. Client code can register their own implementations, which then can be used like the already built in functions
(Use case: Random generator function using HW-specific RNG).

Due to the modular nature, client code can pick primitives from each class and tie them together for setting up their crypto application. Users have to know whether a particular primitive can
be used in a secure way for a given purpose (e.g. MD5, MD4 are also supported by LibTomCrypt),
or whether the combination of two particular primitives is secure.

The library comes with a comprehensive 230 page developers guide containing lots of examples,
getting code to compile and run is fairly easy.

One very specific problem we ran into was that LibTomCrypt is built on top of LibTomMath. We failed to integrate both dependencies into a CMake file, such that LibTomMath gets built before LibTomCrypt and that the LibTomCrypt build finds the LibTomMath library as its own dependency.
We did not find any CMake examples on github which did this and using LLMs also did not help.
The workaround is to build LibTomMath upfront. After that build, our own application builds (only defining LibTomMath as dependency in the CMake file).

#### LibHydrogen

FIXME Stefan

### Application Architecture

LibTomCrypt and LibHydrogen do not provide common primitives for hashing, encryption, or key exchange.
Getting e.g. a LibHydrogen client to talk to a LibTomCrypt server is not possible.

Our concept to use both libraries:
* Both client and server use both libraries to implement the protocol
* Exchanged messages, and number of exchanged messages are different in both variants
* Client uses a command line parameter to determine which library to use
* Server detects from clients request message which library to use

`ICryptoWrapper` interface decouples protocol implementation from the library idiosyncrasies. For
each of the libraries a wrapper class implements that interface. Once the client/server application
knows which library to use, it fetches the appropriate instance of `ICryptoWrapper`, then uses it
to implement the protocol.

Both client and server parts of the protocol are implemented in the same binary. Whether the client
or server part of the protocol shall be executed is controlled by a command line parameter.

For message transmission, the application uses UDP Posix sockets, which are also wrapped in dedicated
classes for easier usage. 

![Class Diagram](CryptoLibs.drawio.svg)

### Application Protocol

* The client sends a "Diffie-Hellman request message" to the server, which contains the public part of the DH key pair.
* The server responds with a "Diffie-Hellman response message", which contains the public key of the server.
* (Only LibHydrogen) The client sends a "Diffie-Hellman update message" to the server
* Both client and server derive a symmetric key from the shared secret
* The client calculates a hash on a secret message to send, encrypts the message using the symmetric key, then sends both to the server
* The server decrypts the secret message, calculates the hash on the clear text, and prints the clear text message on the console if own hash and received hash are matching

FIXME Stefan: Recherche, welche Informationen packt LibHydrogen in die Botschaften?


