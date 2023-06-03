cmake_minimum_required(VERSION 3.22)
project(adclient)
set(CMAKE_CXX_STANDARD 23)

file(GLOB_RECURSE SRC
        "src/*.*" ,
        "src/*.cpp" ,
        "src/*/*.*" ,
        "includes/*.*" ,
        "includes/*/*.*" ,
        "lib/*.*" ,
        "lib/*/*.*" ,
        )

add_library(${PROJECT_NAME} SHARED ${SRC})
target_include_directories(${PROJECT_NAME} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_include_directories(${PROJECT_NAME} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/includes")
target_include_directories(${PROJECT_NAME} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/lib")

# required to make an map file for perses obfusication engine.
target_link_options(${PROJECT_NAME} PRIVATE "/MAP:${PROJECT_SOURCE_DIR}/adclient.map")