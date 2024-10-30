cmake_minimum_required(VERSION 3.10.2)

project(privmxdrv-ecc)

include(FindOpenSSL)
include(GNUInstallDirs)

add_compile_options(-Os)

file(GLOB_RECURSE SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
add_library(privmxdrvecc ${SOURCES})
target_include_directories(privmxdrvecc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
set_target_properties(privmxdrvecc PROPERTIES PUBLIC_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/include/privmx/drv/ecc.h)
target_link_libraries(privmxdrvecc PRIVATE OpenSSL::Crypto)
install(TARGETS privmxdrvecc PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/privmx/drv)
