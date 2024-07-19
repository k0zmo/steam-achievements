cmake_minimum_required(VERSION 3.24)
project(steam-achievements LANGUAGES CXX)

find_file(STEAMSDK_DIR isteamclient.h PATH_SUFFIXES public/steam REQUIRED)
cmake_path(GET STEAMSDK_DIR PARENT_PATH STEAMSDK_DIR)

add_executable(steam-achievements main.cpp)
target_compile_features(steam-achievements PRIVATE cxx_std_20)
target_include_directories(steam-achievements PRIVATE ${STEAMSDK_DIR})
