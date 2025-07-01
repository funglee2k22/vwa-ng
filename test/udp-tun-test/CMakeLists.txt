cmake_minimum_required(VERSION 3.6.0)
project(cpep VERSION 1.0.0 LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


#----------------
#tests and small poc 
#---------------
#add_executable(test-tun-device-1 tun-test-1.c)
add_executable(test-tun-device tun-test.c)
#add_executable(test-tun-device-2 tun-test-2.c)
#target_link_libraries(test-tun-device PRIVATE quicly ev picotls)
target_compile_definitions(test-tun-device PRIVATE CPEP_VERSION="${PROJECT_VERSION}")
target_compile_options(test-tun-device PRIVATE
    -Werror=implicit-function-declaration
    -Werror=incompatible-pointer-types
    -Werror=shift-count-overflow
)

