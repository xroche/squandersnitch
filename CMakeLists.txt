cmake_minimum_required(VERSION 3.10)
project(squandersnitch VERSION 1.0.1 DESCRIPTION "Memory Squander Snitch")

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "-g3")
set(CMAKE_CXX_FLAGS_RELEASE "-Ofast")

add_library(squandersnitch SHARED squandersnitch.cpp)
set_property(TARGET squandersnitch PROPERTY CMAKE_CXX_STANDARD_REQUIRED ON)
set_property(TARGET squandersnitch PROPERTY CXX_STANDARD 17)
target_link_libraries(squandersnitch ${CMAKE_DL_LIBS})
