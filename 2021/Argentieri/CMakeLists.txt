cmake_minimum_required(VERSION 3.19)
project(anomalydetect C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -pedantic")

find_package(PkgConfig REQUIRED)

pkg_search_module(LIBRRD librrd REQUIRED)
include_directories(${LIBRRD_INCLUDE_DIRS})

pkg_search_module(LIBXML libxml-2.0 REQUIRED)
include_directories(${LIBXML_INCLUDE_DIRS})


add_executable(anomalydetect main.c array_list.c)

target_link_libraries(${PROJECT_NAME} PRIVATE ${LIBRRD_LIBRARIES} ${LIBXML_LIBRARIES} m)
