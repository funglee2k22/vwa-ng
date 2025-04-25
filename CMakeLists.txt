cmake_minimum_required(VERSION 3.6.0)
project(cpep VERSION 1.0.0 LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_subdirectory(extern)

add_executable(cpep-clt common.h common.c simple-client.c) 
target_link_libraries(cpep-clt PRIVATE quicly ev picotls)
target_compile_definitions(cpep-clt PRIVATE CPEP_VERSION="${PROJECT_VERSION}")
target_compile_options(cpep-clt PRIVATE
    -Werror=implicit-function-declaration
    -Werror=incompatible-pointer-types
    -Werror=shift-count-overflow
)

add_executable(cpep-srv common.h common.c simple-server.c) 
target_link_libraries(cpep-srv PRIVATE quicly ev picotls)
target_compile_definitions(cpep-srv PRIVATE CPEP_VERSION="${PROJECT_VERSION}")
target_compile_options(cpep-srv PRIVATE
    -Werror=implicit-function-declaration
    -Werror=incompatible-pointer-types
    -Werror=shift-count-overflow
)

