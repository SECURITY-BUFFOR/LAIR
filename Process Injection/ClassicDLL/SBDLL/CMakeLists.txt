cmake_minimum_required(VERSION 3.30)
project(SBDLL C)

set(CMAKE_C_STANDARD 99)

add_library(SBDLL SHARED library.c)
