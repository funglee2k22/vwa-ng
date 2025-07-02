cmake_minimum_required(VERSION 3.6.0)
project(quicly-snd-emit-test VERSION 1.0.0 LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_executable(tcp_client simple_tcp_client.c)
add_executable(send_emit_test main.c
    client.h client.c
    client_stream.h client_stream.c
    server.h server.c
    server_stream.h server_stream.c
    common.h common.c)

target_link_libraries(send_emit_test PRIVATE quicly ev picotls)
target_compile_definitions(send_emit_test PRIVATE QPERF_VERSION="${PROJECT_VERSION}")
target_compile_options(send_emit_test PRIVATE
    -Werror=implicit-function-declaration
    -Werror=incompatible-pointer-types
    -Werror=shift-count-overflow
)

