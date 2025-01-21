cmake_minimum_required(VERSION 3.30)
project(HTTP_SERVER C)

set(CMAKE_C_STANDARD 17)

include_directories(${PROJECT_SOURCE_DIR})

add_executable(${PROJECT_NAME}
        main.c
        src/ApiHashing/ApiHashing.c
        src/ApiHashing/ApiHashing.h
        src/defines.h
        src/defines.c

)
