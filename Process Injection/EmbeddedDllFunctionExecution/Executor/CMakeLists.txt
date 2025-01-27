cmake_minimum_required(VERSION 3.30)
project(MemoryDLL C)

set(CMAKE_C_STANDARD 99)

add_executable(MemoryDLL main.c dll.h)
