cmake_minimum_required(VERSION 3.22)
project(qrylz_hook CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(qrylz_hook SHARED qrylz_hook.cpp)

target_compile_options(qrylz_hook PRIVATE
        -O2
        -fvisibility=hidden
        -fno-exceptions
        -fno-rtti
        -Wall)

target_link_libraries(qrylz_hook log)
