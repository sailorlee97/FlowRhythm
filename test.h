//
// Created by sailor on 2025/6/29.
//

#ifndef TEST_H
#define TEST_H
// #include <stdint.h>
#include <pcap.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "uthash.h"  // 下载 uthash.h 并包含

// 使用 __attribute__((packed)) 避免内存对齐填充
typedef struct __attribute__((packed)) {
    uint32_t src_ip;    // 源 IP（主机字节序）
    uint32_t dst_ip;    // 目的 IP（主机字节序）
    uint16_t src_port;  // 源端口（主机字节序）
    uint16_t dst_port;  // 目的端口（主机字节序）
    uint8_t protocol;   // 协议类型

} flow_key_t;

// 哈希表项结构
typedef struct {
    flow_key_t key;      // 作为键
    // 其他需要存储的数据（例如计数器、状态等）
    struct timeval   first_ts;      // 首包时间
    struct timeval   last_ts;       // 最近一包时间
    uint64_t         packet_count;  // 累计包数
    uint64_t         byte_count;    // 累计字节数
    // 正反向的特征
    uint64_t f_direct;    // 正方向
    uint64_t *f_pkt_lens;
    size_t f_pkt_lens_size, f_pkt_lens_capacity;
    uint64_t b_direct;    // 反方向
    uint64_t *b_pkt_lens;
    size_t b_pkt_lens_size, b_pkt_lens_capacity;
    //
    uint64_t *pkt_lens;
    size_t pkt_lens_size, pkt_lens_capacity;
    uint64_t *pkt_fw_times;
    size_t pkt_fw_times_size, pkt_fw_times_capacity;
    uint64_t *pkt_bw_times;
    size_t pkt_bw_times_size, pkt_bw_times_capacity;
    // 存储时间的列表
    double *pkt_tl_times;         // 存微秒为单位的时间戳数组
    size_t pkt_times_size;     // 当前包数
    size_t pkt_times_capacity; // 数组容量

    // int data;
    UT_hash_handle hh;  // uthash 必需字段
} flow_item_t;

// 这个没有用上
typedef struct flow_record {
    flow_key_t     key;         // 归一化后的五元组
    char           flow_id[64]; // "192.168.1.1-10.0.0.1-1234-80-6"
    uint64_t       fwd_packets, bwd_packets;
    struct timeval start, last;
    int            fin_seen;    // 是否见到 TCP FIN
    // packet_info_t *pkts;        // ← 新增：指向包信息链表
    struct flow_record *next;
} flow_record_t;
// 以太网帧头
typedef struct {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
} __attribute__((packed)) ethernet_header;

void process_packet(const struct pcap_pkthdr *header,
                    const struct ip *ip_hdr,
                    const struct tcphdr *tcp_hdr,
                    bool         is_last_packet);
void packet_lzy_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);
void flow_init(flow_item_t *f);
void flow_add_pkt_len(flow_item_t *f, uint64_t len);
void flow_stats(const flow_item_t *f,
                double *avg, uint64_t *min, uint64_t *max, double *stddev);
// flow_item_t *flow_table = NULL; // 全局哈希表指针
#endif //TEST_H
