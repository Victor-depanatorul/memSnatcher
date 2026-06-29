cmake_minimum_required(VERSION 4.1)
project(Cross_Platform_Memory_Scanner)

set(CMAKE_CXX_STANDARD 26)

add_executable(Cross_Platform_Memory_Scanner main.cpp
        win_scanner.hpp)
