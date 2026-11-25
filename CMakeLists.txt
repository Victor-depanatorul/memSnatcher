cmake_minimum_required(VERSION 4.1)
project(Cross_Platform_Memory_Scanner)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-stdlib=libc++)
add_link_options(-stdlib=libc++)

add_executable(Cross_Platform_Memory_Scanner main.cpp
        win_scanner.hpp
        linux_scanner.hpp
        generic_scanner.hpp
)
