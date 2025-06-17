cmake_minimum_required(VERSION 3.6.0)
project(cpep VERSION 1.0.0 LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_subdirectory(extern)

add_executable(new-clt src/uthash.h src/common.h src/common.c src/client.h
	        src/session.h src/session.c
                src/client_stream.h src/client_stream.c src/client.c)
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

#----------------
#tests and small poc
#---------------
add_executable(test-uthash src/uthash.h test/uthash-test/session.h test/uthash-test/test-uthash-session.c )
target_link_libraries(test-uthash PRIVATE quicly ev picotls)
target_compile_definitions(test-uthash PRIVATE CPEP_VERSION="${PROJECT_VERSION}")
target_compile_options(test-uthash PRIVATE
    -Werror=implicit-function-declaration
    -Werror=incompatible-pointer-types
    -Werror=shift-count-overflow
)

add_executable(test-udp-tproxy test/udp-tproxy-test/udp-tproxy-server.c )

#
add_executable(quic-test
    poc-remove-app-buf/main.c
    poc-remove-app-buf/client.h
    poc-remove-app-buf/client.c
    poc-remove-app-buf/client_stream.h
    poc-remove-app-buf/client_stream.c
    poc-remove-app-buf/server.h
    poc-remove-app-buf/server.c
    poc-remove-app-buf/server_stream.h
    poc-remove-app-buf/server_stream.c
    poc-remove-app-buf/common.h
    poc-remove-app-buf/common.c)

target_link_libraries(quic-test PRIVATE quicly ev picotls)
target_compile_definitions(quic-test PRIVATE CPEP_VERSION="${PROJECT_VERSION}")
target_compile_options(quic-test PRIVATE
    -Werror=implicit-function-declaration
    -Werror=incompatible-pointer-types
    -Werror=shift-count-overflow
) 

add_executable(quic-test-write
    poc-remove-app-buf-t2q/main.c
    poc-remove-app-buf-t2q/client.h
    poc-remove-app-buf-t2q/client.c
    poc-remove-app-buf-t2q/client_stream.h
    poc-remove-app-buf-t2q/client_stream.c
    poc-remove-app-buf-t2q/server.h
    poc-remove-app-buf-t2q/server.c
    poc-remove-app-buf-t2q/server_stream.h
    poc-remove-app-buf-t2q/server_stream.c
    poc-remove-app-buf-t2q/common.h
    poc-remove-app-buf-t2q/common.c)

target_link_libraries(quic-test-write PRIVATE quicly ev picotls)
target_compile_definitions(quic-test-write PRIVATE CPEP_VERSION="${PROJECT_VERSION}")
target_compile_options(quic-test-write PRIVATE
    -Werror=implicit-function-declaration
    -Werror=incompatible-pointer-types
    -Werror=shift-count-overflow
)
add_executable(tcp-simple-client poc-remove-app-buf-t2q/simple_tcp_client.c)
