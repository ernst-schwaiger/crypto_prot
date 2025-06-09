cmake_minimum_required(VERSION 3.11)
project(c_crypto_prot VERSION 0.0.1 LANGUAGES CXX)

Include(FetchContent)
Include(ExternalProject)
Include(CTest)

#
# For getting Catch2 sources
#
FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v3.7.1 # or a later release
)

#
# Fmt library
#
FetchContent_Declare(
  fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt
  GIT_TAG        11.1.1)

#
# libtomcrypt (requires libtommath being installed upfront!)
#
FetchContent_Declare(
  libtomcrypt
  GIT_REPOSITORY https://github.com/libtom/libtomcrypt.git
  GIT_TAG        d448df1938e8988bcdb0eed6591387e82b26874b)

#
# libhydrogen
#
FetchContent_Declare(
  hydrogen
  GIT_REPOSITORY https://github.com/jedisct1/libhydrogen.git
  GIT_TAG        bbca575b62510bfdc6dd927a4bfa7df4a51cb846)

FetchContent_MakeAvailable(Catch2 fmt libtomcrypt hydrogen)

# use libtommath descriptor in libtomcrypt
target_compile_options(libtomcrypt PRIVATE "-DLTM_DESC")

enable_testing()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

#
# c_crypto_prot binary
#
add_executable(c_crypto_prot
    src/main.cpp
    src/LibTomWrapper.cpp
    src/HydrogenWrapper.cpp
    src/UdpSocket.cpp
    src/SendReceive.cpp
    src/ConfigParser.cpp
    )
    
# Increase Warnings, treat warnings as errors
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror")

# Enable AddressSanitizer for X86_64 Debug builds on clang or gcc only
# Sanitizers don't seem to work on ARM/Raspberry Pi
if (CMAKE_BUILD_TYPE STREQUAL "Debug" AND CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address,undefined")
        set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} -fsanitize=address,undefined")
    endif()
endif()

target_link_libraries(c_crypto_prot PRIVATE fmt::fmt libtomcrypt hydrogen)

#
# Tests
#
add_executable(c_crypto_prot_test 
    test/c_crypto_prot_test.cpp
    src/LibTomWrapper.cpp
    src/HydrogenWrapper.cpp
    src/SendReceive.cpp
    src/UdpSocket.cpp
    )

# for coverage: ensure tests are executed in debug mode
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(c_crypto_prot_test PRIVATE --coverage)
    target_link_options(c_crypto_prot_test PRIVATE --coverage)
endif()

target_include_directories(c_crypto_prot_test PRIVATE 
    ${CMAKE_SOURCE_DIR}/src)

target_link_libraries(c_crypto_prot_test PRIVATE Catch2::Catch2WithMain fmt::fmt libtomcrypt hydrogen)
add_test(NAME c_crypto_prot_test COMMAND c_crypto_prot_test)

# Custom target to run tests and generate coverage report 
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
add_custom_target(coverage 
    COMMAND ${CMAKE_CTEST_COMMAND} -T test --output-on-failure 
    COMMAND gcovr -r ${CMAKE_SOURCE_DIR} --xml -o coverage.xml 
    COMMAND gcovr -r ${CMAKE_SOURCE_DIR} --html --html-details -o coverage.html
    DEPENDS c_crypto_prot_test )
endif()
