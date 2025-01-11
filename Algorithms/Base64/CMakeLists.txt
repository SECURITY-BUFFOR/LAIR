cmake_minimum_required(VERSION 3.30)
project(Base64 C)

set(CMAKE_C_STANDARD 11)

add_executable(Base64 main.c
        src/Base64/Base64.c
        src/Base64/Base64.h
        src/ApiHashing/ApiHashing.c
        src/ApiHashing/ApiHashing.h
        src/defines.c
        src/defines.h
)
