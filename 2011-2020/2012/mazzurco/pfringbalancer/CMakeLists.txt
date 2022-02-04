project(pfringbalancer)

add_subdirectory(./doc)
add_subdirectory(./src)

cmake_minimum_required(VERSION 2.8)

# To enable debug pass options -DCMAKE_BUILD_TYPE=Debug to cmake and set BPFRD_DEBUG_LEVEL with an integer bigger than 0 (passing 0 will disable debug)
add_definitions(-DBPFRD_DEBUG_LEVEL=99)

# Define BPFRD_FUNC_PARAMS_CHECKING to enable params checking ( disabling it improve performance but function call can lead to error if parameter are wrong such as a NULL pointer )
add_definitions(-DBPFRD_FUNC_PARAMS_CHECKING)
