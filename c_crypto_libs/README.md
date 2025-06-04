# C Crypto Libraries
Group 3: Lorenzo Haidinger, Samuel Kominek, Stefan Ohnewith, Ernst Schwaiger

## Preconditions

For building the project, the following dependencies must be installed upfront:

```bash
sudo apt install gcc g++ make cmake libtommath-dev
```

As an alternative, libtommath can be checked out from github, built and installed manually:

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

To build the Project:
```bash
cd c_crypto_libs
mkdir -p build
cd build
cmake ..
make -sj
```
