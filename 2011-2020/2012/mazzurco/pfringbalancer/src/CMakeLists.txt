aux_source_directory(. SRC_LIST)
add_executable(${PROJECT_NAME} ${SRC_LIST})

find_package(Threads)
find_library(PCAP pcap)
find_library(PF_RING pfring)
target_link_libraries(${PROJECT_NAME} ${PF_RING} ${PCAP} ${CMAKE_THREAD_LIBS_INIT})
