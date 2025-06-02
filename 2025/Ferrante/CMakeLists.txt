cmake_minimum_required(VERSION 3.22)
project(Ferrante C)

set(CMAKE_C_STANDARD 11)

# Percorsi di Net-SNMP e rrdtool installato con Homebrew e ndpi
include_directories(/opt/homebrew/include)
link_directories(/opt/homebrew/lib)
include_directories(/opt/homebrew/include)
link_directories(/opt/homebrew/lib)

# Aggiungi l'eseguibile
add_executable(Ferrante src/port_similarity.c)

# Includi l'header di nDPI (PRIVATE = solo per questo target)
target_include_directories(Ferrante PRIVATE
        ${CMAKE_SOURCE_DIR}/src/utils/ndpi/src/include
)

# Linka la libreria statica di nDPI
target_link_libraries(Ferrante
        ${CMAKE_SOURCE_DIR}/src/utils/ndpi/src/lib/libndpi.a
)
#Linka la libreria rrds
target_link_libraries(Ferrante rrd)

# Linka la libreria SNMP
target_link_libraries(Ferrante netsnmp)

