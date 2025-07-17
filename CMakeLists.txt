cmake_minimum_required(VERSION 3.30)
project(AIMon C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED TRUE)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")
set(HOMEBREW_PREFIX "/opt/homebrew")
# 查找libpcap
# 查找 pkg-config 模块
find_package(PkgConfig REQUIRED)
find_path(PCAP_INCLUDE_DIR pcap/pcap.h REQUIRED)

# 使用 pkg-config 查找 libpcap
pkg_check_modules(PCAP REQUIRED libpcap)

# 打印查找结果用于调试
message(STATUS "PCAP_LIBRARIES: ${PCAP_LIBRARIES}")
message(STATUS "PCAP_INCLUDE_DIRS: ${PCAP_INCLUDE_DIRS}")

add_executable(AIMon main.c
#        pflow.c
#        pflow.h
        test.c
        test.h
        csvwriter.h
        csvwriter.c)
target_include_directories(AIMon PRIVATE "${HOMEBREW_PREFIX}/include")

# 包含libpcap的头文件目录
target_include_directories(AIMon PRIVATE ${PCAP_INCLUDE_DIRS})

# 链接libpcap库
target_link_libraries(AIMon PRIVATE ${PCAP_LIBRARIES})

# 添加编译选项
target_compile_options(AIMon PRIVATE -Wall -Wextra -pedantic)