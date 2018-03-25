cmake_minimum_required(VERSION 3.9)
project(direncrypt C)

set(CMAKE_C_STANDARD 11)

add_executable(direncrypt main.c utils.h utils.c pthread_routines.h pthread_routines.c)
target_link_libraries(direncrypt pthread)