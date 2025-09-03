//
// Created by sailor on 2025/8/11.
//

#ifndef COMPUTEFUNCTION_H
#define COMPUTEFUNCTION_H

#include <pcap.h>
#include <stdbool.h>
#include "uthash/uthash.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
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
    bool direct; // 反方向为true，正向为false
    uint64_t f_direct;    // 正方向
    uint64_t *f_pkt_lens;
    size_t f_pkt_lens_size, f_pkt_lens_capacity;
    uint64_t b_direct;    // 反方向
    uint64_t *b_pkt_lens;
    size_t b_pkt_lens_size, b_pkt_lens_capacity;
    //
    uint64_t *pkt_lens;
    size_t pkt_lens_size, pkt_lens_capacity;
    double *pkt_fw_times;
    size_t pkt_fw_times_size, pkt_fw_times_capacity;
    double *pkt_bw_times;
    size_t pkt_bw_times_size, pkt_bw_times_capacity;
    // 存储时间的列表
    double *pkt_tl_times;         // 存微秒为单位的时间戳数组
    size_t pkt_times_size;     // 当前包数
    size_t pkt_times_capacity; // 数组容量

    // 存的是域名
    char *sni;
    // int data;
    UT_hash_handle hh;  // uthash 必需字段
} flow_item_t;

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
void flow_stats(uint64_t *pkt_lens, size_t pkt_lens_size,
                double *avg, uint64_t *min, uint64_t *max, double *stddev);

#endif //COMPUTEFUNCTION_H
