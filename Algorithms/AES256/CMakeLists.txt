cmake_minimum_required(VERSION 3.30)
project(AES256_CBC C)

set(CMAKE_C_STANDARD 11)

add_executable(AES256_CBC main.c
        src/ApiHashing/ApiHashing.c
        src/ApiHashing/ApiHashing.h
        src/defines.c
        src/defines.h
)

