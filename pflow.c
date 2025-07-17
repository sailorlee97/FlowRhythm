//
// Created by sailor on 2025/5/20.
//
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <stdint.h>
#include "pflow.h"
#include "uthash.h"
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <time.h>
#include <sys/time.h>

// #include <arpa/inet.h>
#define PPPoE_TYPE_DISCOVERY 0x8863
#define PPPoE_TYPE_SESSION   0x8864
#define IDLE_TIMEOUT_SEC  (200LL * 1000000LL)
// long t;
// struct timeval t1;
struct timeval create_time;  // time of first packet
struct timeval last_seen;    // time of last packet

flow_record_t *flow_table = NULL;

flow_record_t *flows = NULL;  // 全局链表头

size_t flow_hash(const flow_key_t *k) {
    return ((size_t)k->src_ip * 59) ^
           ((size_t)k->dst_ip) ^
           ((size_t)k->src_port << 16) ^
           ((size_t)k->dst_port) ^
           ((size_t)k->proto);
}
// 五元组比较（用于链表查找）
int flow_key_equal(const flow_key_t *a, const flow_key_t *b) {
    return a->src_ip   == b->src_ip   &&
           a->dst_ip   == b->dst_ip   &&
           a->src_port == b->src_port &&
           a->dst_port == b->dst_port &&
           a->proto    == b->proto;
}
// 根据五元组生成唯一字符串 ID
static void make_flow_id(const flow_key_t *k, char *buf, size_t len) {
    snprintf(buf, len,
             "%u.%u.%u.%u-%u.%u.%u.%u-%u-%u-%u",
             (k->src_ip>>24)&0xFF, (k->src_ip>>16)&0xFF,
             (k->src_ip>>8)&0xFF,  k->src_ip&0xFF,
             (k->dst_ip>>24)&0xFF, (k->dst_ip>>16)&0xFF,
             (k->dst_ip>>8)&0xFF,  k->dst_ip&0xFF,
             k->src_port, k->dst_port, k->proto);
}
/**
 * 返回 now 和 last 之间的时间差（单位：微秒）。
 */
// static inline int64_t timeval_diff_us(const struct timeval *now,
//                                        const struct timeval *last) {
//     int64_t sec_diff  = (int64_t)(now->tv_sec  - last->tv_sec);
//     int64_t usec_diff = (int64_t)(now->tv_usec - last->tv_usec);
//     return sec_diff * 1000000LL + usec_diff;
// }

// ----------------- 流特征计算函数 -----------------
// void compute_flow_features(flow_record_t *f) {
//     // 假定 f->pkts 已按时间顺序存入一个 packet_info_t 链表
//     // 先统计包数
//     int N = 0;
//     for (packet_info_t *p = f->pkts; p; p = p->next) N++;
//     if (N < 2) return;
//
//     // 分配数组
//     double *T    = malloc(sizeof(double) * N);
//     double *L    = malloc(sizeof(double) * N);
//     double *dt   = malloc(sizeof(double) * (N - 1));
//     // 为正/反向流先假定最多 N-1 个间隔
//     double *dt_fwd = malloc(sizeof(double) * (N - 1));
//     double *dt_bwd = malloc(sizeof(double) * (N - 1));
//     double *L_fwd  = malloc(sizeof(double) * N);
//     double *L_bwd  = malloc(sizeof(double) * N);
//
//     // 链表倒序→升序填 T[], L[]
//     int idx = N - 1;
//     for (packet_info_t *p = f->pkts; p; p = p->next) {
//         T[idx] = p->ts.tv_sec + p->ts.tv_usec / 1e6;
//         L[idx] = p->ip_len;
//         idx--;
//     }
//
//     // 计算总体 inter-packet（毫秒）
//     for (int i = 1; i < N; i++) {
//         dt[i - 1] = (T[i] - T[i - 1]) * 1e3;
//     }
//
//     // 分方向计算 dt_fwd, dt_bwd, 并收集包长度 L_fwd, L_bwd
//     int cnt_fwd = 0, cnt_bwd = 0;
//     double last_fwd_ts = -1, last_bwd_ts = -1;
//
//     idx = N - 1;
//     for (packet_info_t *p = f->pkts; p; p = p->next, idx--) {
//         double ts = T[idx];
//         if (p->dir == 1) {
//             L_fwd[cnt_fwd] = p->ip_len;
//             if (last_fwd_ts >= 0) {
//                 dt_fwd[cnt_fwd - 1] = (ts - last_fwd_ts) * 1e3;
//             }
//             last_fwd_ts = ts;
//             cnt_fwd++;
//         } else {
//             L_bwd[cnt_bwd] = p->ip_len;
//             if (last_bwd_ts >= 0) {
//                 dt_bwd[cnt_bwd - 1] = (ts - last_bwd_ts) * 1e3;
//             }
//             last_bwd_ts = ts;
//             cnt_bwd++;
//         }
//     }
//
//     // 计算并打印
//     double duration_ms = (T[N - 1] - T[0]) * 1e3;
//     printf("Flow %s Features:\n", f->flow_id);
//     printf("- Duration: %.3f ms\n", duration_ms);
//
//     compute_stats(dt,    N - 1,    "Inter-pkt (all)");
//     compute_stats(dt_fwd, cnt_fwd>1 ? cnt_fwd-1 : 0, "Inter-pkt fwd");
//     compute_stats(dt_bwd, cnt_bwd>1 ? cnt_bwd-1 : 0, "Inter-pkt bwd");
//
//     compute_stats(L,      N,       "Pkt size (all)");
//     compute_stats(L_fwd,  cnt_fwd, "Pkt size fwd");
//     compute_stats(L_bwd,  cnt_bwd, "Pkt size bwd");
//
//     // …如果需要还可以做 bytes/sec 之类的额外计算……
//
//     // 释放
//     free(T); free(L); free(dt);
//     free(dt_fwd); free(dt_bwd);
//     free(L_fwd); free(L_bwd);
// }

// void expire_flows(const struct timeval *now) {
//     flow_record_t **pp = &flows;
//     while (*pp) {
//         flow_record_t *f = *pp;
//         int64_t idle_us = timeval_diff_us(now, &f->last);
//         if (idle_us > FLOW_IDLE_TIMEOUT_US) {
//             printf("Flow %s expired (idle %.3f s)\n",
//                    f->flow_id,
//                    idle_us / 1e6);
//             *pp = f->next;
//             free(f);
//         } else {
//             pp = &f->next;
//         }
//     }
// }

void normalize_key(flow_key_t *k) {
    uint64_t a = ((uint64_t)k->src_ip << 16) | k->src_port;
    uint64_t b = ((uint64_t)k->dst_ip << 16) | k->dst_port;
    //  将源 IP 和源端口拼成一个 64 位整数 a，目的 IP 和目的端口拼成 b，再做大小比较，以决定“哪个方向更小”
    if (a > b) {
        // 交换 IP/端口
        uint32_t tmp_ip = k->src_ip; k->src_ip = k->dst_ip; k->dst_ip = tmp_ip;
        uint16_t tmp_port = k->src_port; k->src_port = k->dst_port; k->dst_port = tmp_port;
    }
}

static int tcp_has_fin(const u_char *payload, int ip_hl) {
    const struct tcphdr *th = (struct tcphdr *)(payload + ip_hl*4);
    return (ntohs(th->th_flags) & TH_FIN) != 0;
}
static int flow_key_reverse_equal(const flow_key_t *a,
                                  const flow_key_t *b)
{
    return a->src_ip   == b->dst_ip   &&
           a->dst_ip   == b->src_ip   &&
           a->src_port == b->dst_port &&
           a->dst_port == b->src_port &&
           a->proto    == b->proto;
}


// 微秒级时间差
static int64_t timeval_diff_us(const struct timeval *a,
                               const struct timeval *b)
{
    return (a->tv_sec - b->tv_sec) * 1000000LL
         + (a->tv_usec - b->tv_usec);
}

double flow_duration(const flow_record_t *f) {
    double s = f->start.tv_sec + f->start.tv_usec/1e6;
    double e = f->last .tv_sec + f->last .tv_usec/1e6;
    return e - s;
}

flow_record_t *flow_find_or_create(const flow_key_t *key, const struct timeval *ts) {
    // 1) 先查正向或反向都匹配的已有流
    for (flow_record_t *f = flows; f; f = f->next) {
        if (flow_key_equal(&f->key, key) ||
            flow_key_reverse_equal(&f->key, key))
        {
            return f;
        }
    }
    // 2) 都没找到，则新建流（方向以 key 所示为起点）
    // 不存在则创建新流
    flow_record_t *f = calloc(1, sizeof(*f));
    f->key = *key;
    make_flow_id(key, f->flow_id, sizeof(f->flow_id));
    f->start = f->last = *ts;
    f->pkts = NULL;
    // f->next = flows;
    flows = f;
    flows->next = NULL;
    return f;
}

// 计算并打印一组 double 数值的统计量
void compute_stats(const double *A, int M, const char *name) {
    if (M <= 0) {
        printf("  %-20s: no data\n", name);
        return;
    }
    double sum=0, sum2=0, mx=A[0], mn=A[0];
    for (int i = 0; i < M; i++) {
        double x = A[i];
        sum  += x; sum2 += x*x;
        if (x > mx) mx = x;
        if (x < mn) mn = x;
    }
    double mean = sum / M;
    double var  = sum2 / M - mean*mean;
    double std  = var>0 ? sqrt(var) : 0;
    printf("  %-20s: max=%.3f, min=%.3f, mean=%.3f, std=%.3f, sum=%.3f\n",
           name, mx, mn, mean, std, sum);
}

void compute_flow_features(flow_record_t *f) {
    // 1) 收包数
    int N = 0;
    for (packet_info_t *p=f->pkts; p; p=p->next) N++;
    if (N < 2) return;

    // 2) 分配数组
    double *T        = malloc(sizeof(double)*N);
    double *L        = malloc(sizeof(double)*N);
    double *dt_all   = malloc(sizeof(double)*(N-1));
    double *dt_fwd   = malloc(sizeof(double)*(f->fwd_packets>1?f->fwd_packets-1:0));
    double *dt_bwd   = malloc(sizeof(double)*(f->bwd_packets>1?f->bwd_packets-1:0));
    double *L_fwd    = malloc(sizeof(double)*f->fwd_packets);
    double *L_bwd    = malloc(sizeof(double)*f->bwd_packets);

    // 3) 链表倒序→升序填数据
    int idx = N-1;
    for (packet_info_t *p=f->pkts; p; p=p->next, idx--) {
        T[idx] = p->ts.tv_sec + p->ts.tv_usec/1e6;
        L[idx] = p->ip_len;
    }
    // 流持续时间
    double duration_ms = (T[N-1] - T[0]) * 1e3;

    // 4) 计算整体 inter-packet (ms)
    for (int i = 1; i < N; i++)
        dt_all[i-1] = (T[i] - T[i-1]) * 1e3;

    // 5) 分方向计算 dt 与 L
    double last_f = -1, last_b = -1;
    int cf=0, cb=0;
    idx = N-1;
    for (packet_info_t *p=f->pkts; p; p=p->next, idx--) {
        double ts = T[idx];
        if (p->dir) {
            L_fwd[cf] = p->ip_len;
            if (last_f >= 0) dt_fwd[cf-1] = (ts - last_f)*1e3;
            last_f = ts; cf++;
        } else {
            L_bwd[cb] = p->ip_len;
            if (last_b >= 0) dt_bwd[cb-1] = (ts - last_b)*1e3;
            last_b = ts; cb++;
        }
    }

    // 6) 输出统计
    printf("=== Flow %s ===\n", f->flow_id);
    printf("Duration(ms): %.3f\n", duration_ms);
    compute_stats(dt_all, N-1,       "Inter-pkt all");
    compute_stats(dt_fwd, cf>1?cf-1:0, "Inter-pkt fwd");
    compute_stats(dt_bwd, cb>1?cb-1:0, "Inter-pkt bwd");
    compute_stats(L,      N,          "Pkt size all");
    compute_stats(L_fwd,  cf,         "Pkt size fwd");
    compute_stats(L_bwd,  cb,         "Pkt size bwd");
    double total_bytes = 0.0;
    for (int i = 0; i < N; i++) {
        total_bytes += L[i];
    }
    // printf("Total bytes : %.0f\n",
    //        accumulate(L, L+N, 0.0));         // 累加全部包长
    // printf("Bytes/sec   : %.3f\n",
    //        accumulate(L, L+N, 0.0) /
    //        (T[N-1]-T[0]+1e-6));              // B/s

    // 7) 释放
    free(T); free(L);
    free(dt_all); free(dt_fwd); free(dt_bwd);
    free(L_fwd);   free(L_bwd);
}
void flow_update(flow_record_t *f,
                        const u_char *ip_packet,
                        const struct timeval *ts)
{
    // 更新方向计数与 last
    struct ip *ip_hdr = (struct ip *)ip_packet;
    int ip_hl = ip_hdr->ip_hl;
    flow_key_t *k = &f->key;

    // 判断正向/反向
    int is_fwd = (ip_hdr->ip_src.s_addr == htonl(k->src_ip) &&
                  ip_hdr->ip_dst.s_addr == htonl(k->dst_ip));
    if (is_fwd) f->fwd_packets++;
    else        f->bwd_packets++;
    f->last = *ts;

    // 记录包信息
    packet_info_t *pi = calloc(1, sizeof(*pi));
    pi->ts     = *ts;
    pi->dir    = is_fwd;
    pi->ip_len = ntohs(ip_hdr->ip_len);
    pi->next   = f->pkts;
    f->pkts    = pi;

    // 若是 TCP 且首次见到 FIN，则流结束，立即统计
    if (!f->fin_seen && f->key.proto==6 && tcp_has_fin(ip_packet, ip_hl)) {
        // 如果流结束的话，
        f->fin_seen = 1;
        compute_flow_features(f);
    }
}
// 先用当前包时间戳遍历 flows 链表，删除并统计超过 60 秒未见新包且未见 FIN 的流。
void expire_flows(const struct timeval *now) {
    flow_record_t **pp = &flows;
    while (*pp) {
        flow_record_t *f = *pp;
        if (!f->fin_seen &&
            timeval_diff_us(now, &f->last) > IDLE_TIMEOUT_SEC*1000000LL)
        {
            // 先算包数
            int pkt_count = 0;
            for (packet_info_t *p = f->pkts; p; p = p->next) pkt_count++;
            // 只有包数 ≥2 才做统计
            if (pkt_count > 1) {
                compute_flow_features(f);
            }

            // 删除流记录
            *pp = f->next;
            // 释放包链表
            packet_info_t *p = f->pkts;
            while (p) {
                packet_info_t *n = p->next;
                free(p);
                p = n;
            }
            // free(f);
        } else {
            pp = &f->next;
        }
    }
}

void packet_lzy_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    flow_record_t *flow = NULL;
    time_t  sec  = header->ts.tv_sec;   // 自 1970-01-01 起的秒数
    suseconds_t usec = header->ts.tv_usec; // 当秒内的微秒数

    if (header->caplen < sizeof(ethernet_header)) {
        fprintf(stderr, "数据包长度不足以包含以太网头部\n");
        return;
    }
    ethernet_header *eth_hdr = (ethernet_header *)packet;
    uint16_t ethertype = ntohs(eth_hdr->ethertype);
    if (ethertype == PPPoE_TYPE_SESSION) {
        const uint8_t *payload =packet + 14 + 6 + 2;
        uint8_t first_byte = payload[0];
        uint8_t ip_version = first_byte >> 4;

        uint16_t length = (payload[2]  << 8)| payload[3];
        if (ip_version == 4){
            // IPv4
            // parse_ip_and_transport_ipv4(payload, length);
        } else if (ip_version == 6) {
            // IPv6
            // parse_ip_and_transport_ipv6(payload, length);
        } else {
            //            printf("未知的 IP 版本: %d\n", ip_version);
            return;
        }
    } else{
        //        非pppoe的走这个逻辑
        //        printf("非pppoe的走这个逻辑\n");
        const uint8_t *payload = packet + 14;
        uint8_t first_byte = payload[0];
        uint8_t ip_version = first_byte >> 4;
        uint16_t length = (payload[4]  << 8)| payload[5];
        if (ip_version == 4){
            expire_flows(&header->ts);
            // t = header->ts.tv_sec + header->ts.tv_usec/1e6;;
            struct ip *ip_hdr = (struct ip*)(payload);
            struct tcphdr *t = (void*)payload + ip_hdr->ip_hl*4;
            // uint8_t *tcp = (ip_hdr + ip_hdr->ip_hl*4);
            // uint16_t th_sport = (tcp[0] << 4) | tcp[1];

            flow_key_t orig = {
                ntohl(ip_hdr->ip_src.s_addr), ntohl(ip_hdr->ip_dst.s_addr),
                0,0,
                ip_hdr->ip_p
            };
            orig.src_port = ntohs(t->th_sport);
            orig.dst_port = ntohs(t->th_dport);

            // 3) 找流、更新
            flow_record_t *f = flow_find_or_create(&orig, &header->ts);
            flow_update(f, payload, &header->ts);

            // if (!f->fin_seen) {
            //     compute_flow_features(f);
            // }
            free(f);


            // IPv4
            // parse_ip_and_transport_ipv4(payload, length);
            // process_packet(payload);
            /* 将秒和微秒格式化为浮点数时间 */
            // printf("Timestamp: %ld.%06ld seconds\n",
            //        header->ts.tv_sec,   /* 秒 */
            //        header->ts.tv_usec); /* 微秒 */

        } else if (ip_version == 6) {
            // IPv6
            // parse_ip_and_transport_ipv6(payload, length);
        } else {
            //            printf("未知的 IP 版本: %d\n", ip_version);
            return;
        }
    }
}
