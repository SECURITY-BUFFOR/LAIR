cmake_minimum_required(VERSION 3.30)
project(HTTP_HTTPS C)

set(CMAKE_C_STANDARD 11)

add_executable(HTTP_HTTPS main.c
        src/ApiHashing/ApiHashing.c
        src/ApiHashing/ApiHashing.h
        src/defines.c
        src/defines.h
        src/http_https/HttpTransport.c
        src/http_https/HttpTransport.h
)
