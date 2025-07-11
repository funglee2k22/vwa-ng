cmake_minimum_required(VERSION 3.6.0)
project(cpep VERSION 1.0.0 LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_subdirectory(extern)

add_executable(new-clt
               src/uthash.h
               src/common.h src/common.c
               src/client.h src/client.c
               src/session.h src/session.c
               src/client_stream.h src/client_stream.c
               src/client_udp_stream.h src/client_udp_stream.c
               src/client_udp.h src/client_udp.c)
target_link_libraries(new-clt PRIVATE quicly ev picotls)
target_compile_definitions(new-clt PRIVATE CPEP_VERSION="${PROJECT_VERSION}")
target_compile_options(new-clt PRIVATE
    -Werror=implicit-function-declaration
    -Werror=incompatible-pointer-types
    -Werror=shift-count-overflow
)


add_executable(new-srv src/uthash.h src/common.h src/common.c src/server.h
            src/session.h src/session.c
                src/server_stream.h src/server_stream.c src/server.c)
target_link_libraries(new-srv PRIVATE quicly ev picotls)
target_compile_definitions(new-srv PRIVATE CPEP_VERSION="${PROJECT_VERSION}")
target_compile_options(new-srv PRIVATE
    -Werror=implicit-function-declaration
    -Werror=incompatible-pointer-types
    -Werror=shift-count-overflow
)

add_subdirectory(src)

#----------------
#tests and small poc
#---------------
add_subdirectory(test)
