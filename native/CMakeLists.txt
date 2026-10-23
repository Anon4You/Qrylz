cmake_minimum_required(VERSION 3.22)
project(qrylz_hook C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# One build directory per abi, the ndk toolchain reads ANDROID_ABI when it is
# configured. The gradle build drives one configure and one build per abi.

add_library(qrylz_hook SHARED qrylz_hook.cpp)

target_compile_options(qrylz_hook PRIVATE
        -O2
        -fvisibility=hidden
        -fno-exceptions
        -fno-rtti
        -Wall)

# 16 KB is a multiple of the 4 KB page size, so the same library loads on both.
target_link_options(qrylz_hook PRIVATE -Wl,-z,max-page-size=16384)

target_link_libraries(qrylz_hook log dl)
