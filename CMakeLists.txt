cmake_minimum_required(VERSION 3.0.0)
cmake_policy(SET CMP0074 NEW)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fcoroutines")

include(FetchContent)

project(boost.beast.coro VERSION 0.1.0)

find_package(OpenSSL 1.0.1 REQUIRED)

find_package(Boost 1.78.0 REQUIRED COMPONENTS thread)

FetchContent_Declare(
  jwt-cpp
  GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
  GIT_TAG v0.6.0
)
FetchContent_GetProperties(jwt-cpp)
if(NOT jwt-cpp_POPULATED)
  FetchContent_Populate(jwt-cpp)
endif()
add_subdirectory("${jwt-cpp_SOURCE_DIR}" "${jwt-cpp_BINARY_DIR}")

add_executable(boost.beast.coro main.cpp)

set(USED_LIBS ${Boost_THREAD_LIBRARY} OpenSSL::SSL OpenSSL::Crypto jwt-cpp)
target_link_libraries(boost.beast.coro ${USED_LIBS})

set(INCLUDE_DIRS ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
target_include_directories(boost.beast.coro PRIVATE ${INCLUDE_DIRS})
