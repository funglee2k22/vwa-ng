cmake_minimum_required(VERSION 3.6.0)
project(cpep VERSION 1.0.0 LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(udp-clt
            uthash.h
            common.h common.c
            session.h session.c
            client.h client.c
            client_stream.h client_stream.c
            client_udp_stream.h client_udp_stream.c
            client_udp.h client_udp.c)

target_link_libraries(udp-clt PRIVATE quicly ev picotls)
target_compile_definitions(udp-clt PRIVATE CPEP_VERSION="${PROJECT_VERSION}")
target_compile_options(udp-clt PRIVATE
    -Werror=implicit-function-declaration
    -Werror=incompatible-pointer-types
    -Werror=shift-count-overflow)

add_executable(udp-srv
            uthash.h
            common.h common.c
            session.h session.c
            server.h server.c
            server_stream.h server_stream.c
            server_udp_stream.h server_udp_stream.c
            server_udp.h server_udp.c)

target_link_libraries(udp-srv PRIVATE quicly ev picotls)
target_compile_definitions(udp-srv PRIVATE CPEP_VERSION="${PROJECT_VERSION}")
target_compile_options(udp-srv PRIVATE
    -Werror=implicit-function-declaration
    -Werror=incompatible-pointer-types
    -Werror=shift-count-overflow)

