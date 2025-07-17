//
// Created by sailor on 2025/5/20.
//

#ifndef PFLOW_H
#define PFLOW_H
#include <stddef.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "uthash.h"
typedef struct packet_info {
    struct timeval        ts;     // 包到达时间戳
    uint32_t              ip_len; // IP 报文总长度 (字节)
    int                   dir;    // 1=正向(src→dst)，0=反向(dst→src)
    struct packet_info   *next;
} packet_info_t;

typedef struct {
    uint32_t src_ip;    // 源 IPv4 地址
    uint32_t dst_ip;    // 目的 IPv4 地址
    uint16_t src_port;  // 源端口
    uint16_t dst_port;  // 目的端口
    uint8_t  proto;     // 协议号 (TCP=6, UDP=17 等)
} flow_key_t;

typedef struct flow_record {
    flow_key_t     key;         // 归一化后的五元组
    char           flow_id[64]; // "192.168.1.1-10.0.0.1-1234-80-6"
    uint64_t       fwd_packets, bwd_packets;
    struct timeval start, last;
    int            fin_seen;    // 是否见到 TCP FIN
    packet_info_t *pkts;        // ← 新增：指向包信息链表
    struct flow_record *next;
} flow_record_t;

flow_record_t *flow_find_or_create(const flow_key_t *key, const struct timeval *ts) ;
void expire_flows(const struct timeval *now);
double flow_duration(const flow_record_t *f);
extern flow_record_t *flow_table;
typedef struct {
    flow_key_t key;
    uint16_t vlan_id;     // VLAN 标识
    uint32_t tunnel_id;   // 隧道标识
} flow_key_ext_t;

// 以太网帧头
typedef struct {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
} __attribute__((packed)) ethernet_header;


void normalize_key(flow_key_t *k);

int flow_key_equal(const flow_key_t *a, const flow_key_t *b);

// flow_record_t *find_or_create_flow(const flow_key_t *k);
void flow_update(flow_record_t *f,
                        const u_char *ip_packet,
                        const struct timeval *ts);


void packet_lzy_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);

#endif //PFLOW_H
