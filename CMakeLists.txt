cmake_minimum_required(VERSION 3.0.0)
cmake_policy(SET CMP0074 NEW)

project(boost.beast.coro VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fcoroutines")

find_package(OpenSSL 1.0.1 REQUIRED)

FIND_PACKAGE(Boost 1.78.0 REQUIRED COMPONENTS thread)
INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIRS})
LINK_DIRECTORIES(${Boost_LIBRARY_DIRS})

add_executable(boost.beast.coro main.cpp)
add_subdirectory(jwt-cpp)

SET(USED_LIBS ${Boost_THREAD_LIBRARY} OpenSSL::SSL OpenSSL::Crypto)
TARGET_LINK_LIBRARIES(boost.beast.coro ${USED_LIBS})

INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})
target_link_libraries(boost.beast.coro jwt-cpp)
