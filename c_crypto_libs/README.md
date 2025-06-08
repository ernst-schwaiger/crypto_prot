# C Crypto Libraries
Group 3: Lorenzo Haidinger, Samuel Kominek, Stefan Ohnewith, Ernst Schwaiger

## Preconditions

For building the project, the following dependencies must be installed upfront:

```bash
sudo apt install gcc g++ make cmake libtommath-dev
```

If libtommath-dev is not available for installation, it can be checked out from github, built and installed manually:

```bash
git clone https://github.com/libtom/libtommath.git
mkdir libtommath/build
cd libtommath/build
cmake ..
make -sj
sudo make install
# -- Install configuration: "Release"
# -- Installing: /usr/local/lib/libtommath.a
# -- Installing: /usr/local/include/libtommath/tommath.h
# -- Installing: /usr/local/share/man/man3/tommath.3
# -- Installing: /usr/local/lib/cmake/libtommath/libtommath-config-version.cmake
# -- Installing: /usr/local/lib/cmake/libtommath/libtommath-config.cmake
# -- Installing: /usr/local/lib/cmake/libtommath/libtommath-config-release.cmake
```

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

### TODO

* Clean up logging messages
* Test on ARM platform
* Extract Metrics: Performance for key generation, symmetric encryption, Memory consumption
* Replace dummy implementations in CryptoWrapper for Hydrogen
