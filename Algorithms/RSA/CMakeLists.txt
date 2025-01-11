cmake_minimum_required(VERSION 3.30)
project(RSA C)

set(CMAKE_C_STANDARD 11)

add_executable(RSA main.c
        src/ApiHashing/ApiHashing.c
        src/ApiHashing/ApiHashing.h
        src/defines.c
        src/defines.h
        src/RSA/RSA.c
        src/RSA/RSA.h
)
