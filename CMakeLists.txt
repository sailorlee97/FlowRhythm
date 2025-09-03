cmake_minimum_required(VERSION 3.30)
project(FlowRhythm C)

set(CMAKE_C_STANDARD 11)
find_package(PkgConfig REQUIRED)
find_path(PCAP_INCLUDE_DIR pcap/pcap.h REQUIRED)
# 使用 pkg-config 查找 libpcap
pkg_check_modules(PCAP REQUIRED libpcap)

# 打印查找结果用于调试
message(STATUS "PCAP_LIBRARIES: ${PCAP_LIBRARIES}")
message(STATUS "PCAP_INCLUDE_DIRS: ${PCAP_INCLUDE_DIRS}")
add_executable(FlowRhythm main.c
        csvwriter.h
        csvwriter.c
        computefunction.h
        computefunction.c
        parse_tls.c
        parse_tls.h
        parse_dns.c
        parse_dns.h
        parse_http.h
        parse_http.c)
# 包含libpcap的头文件目录
target_include_directories(FlowRhythm PRIVATE ${PCAP_INCLUDE_DIRS})

# 链接libpcap库
target_link_libraries(FlowRhythm PRIVATE ${PCAP_LIBRARIES})

# 添加编译选项
target_compile_options(FlowRhythm PRIVATE -Wall -Wextra -pedantic)