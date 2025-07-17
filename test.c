//
// Created by sailor on 2025/6/29.
//
#include <stdio.h>
#include "test.h"
#include <stdbool.h>
#include <math.h>
#include <stdlib.h>
#include <stdint.h>
#include "csvwriter.h"
#include <arpa/inet.h>  // POSIX
#define PPPoE_TYPE_DISCOVERY 0x8863
#define PPPoE_TYPE_SESSION   0x8864
#define FLOW_TIMEOUT_SEC 120  // 流超时阈值（秒），可根据需要修改

flow_item_t *flow_table = NULL; // 全局哈希表指针
typedef struct {
    uint64_t total;  // 总包数
    uint64_t index;  // 当前已处理包数
} pkt_ctx_t;

static bool make_canonical_key(const struct ip *ip_hdr,
                               const struct tcphdr *tcp_hdr,
                               flow_key_t *key) {
    uint32_t src_ip  = ip_hdr->ip_src.s_addr;
    uint32_t dst_ip  = ip_hdr->ip_dst.s_addr;
    uint16_t src_pt  = ntohs(tcp_hdr->th_sport);
    uint16_t dst_pt  = ntohs(tcp_hdr->th_dport);
    key->protocol = ip_hdr->ip_p;
    // 按数值大小或字典序决定顺序
    if (src_ip > dst_ip ||
        (src_ip == dst_ip && src_pt > dst_pt)) {
        // 反向，交换后赋值 反向流数量+1
        key->src_ip   = dst_ip;
        key->dst_ip   = src_ip;
        key->src_port = dst_pt;
        key->dst_port = src_pt;
        return 1;
        } else {
            // 正向，直接赋值  这里需要在正向中+1
            key->src_ip   = src_ip;
            key->dst_ip   = dst_ip;
            key->src_port = src_pt;
            key->dst_port = dst_pt;
            return 0;
        }

}
void flow_init(flow_item_t *f) {
    f->pkt_lens = NULL;
    f->pkt_lens_size = f->pkt_lens_capacity = 0;
    f->f_pkt_lens = NULL;
    f->f_pkt_lens_size = f->f_pkt_lens_capacity =0;
    f->b_pkt_lens = NULL;
    f->b_pkt_lens_size = f->b_pkt_lens_capacity =0;
    f->pkt_tl_times = NULL;
    f->pkt_times_size = f->pkt_times_capacity = 0;
    f->pkt_fw_times = NULL;
    f->pkt_fw_times_size = f->pkt_fw_times_capacity = 0;
    f->pkt_bw_times = NULL;
    f->pkt_bw_times_size = f->pkt_bw_times_capacity = 0;
}

void flow_add_pkt_len(flow_item_t *f, uint64_t len) {
    if (f->pkt_lens_size == f->pkt_lens_capacity) {
        size_t new_cap = f->pkt_lens_capacity ? f->pkt_lens_capacity * 2 : 4;
        uint64_t *tmp = realloc(f->pkt_lens, new_cap * sizeof *tmp);
        if (!tmp) { perror("realloc"); exit(EXIT_FAILURE); }
        f->pkt_lens = tmp;
        f->pkt_lens_capacity = new_cap;
    }
    f->pkt_lens[f->pkt_lens_size++] = len;
}

// 添加到动态数组
void flow_add_pkt_time(flow_item_t *f, double t_us) {
    if (f->pkt_times_size == f->pkt_times_capacity) {
        size_t new_cap = f->pkt_times_capacity ? f->pkt_times_capacity * 2 : 4;
        double *tmp = realloc(f->pkt_tl_times, new_cap * sizeof *tmp);
        if (!tmp) exit(EXIT_FAILURE);
        f->pkt_tl_times = tmp;
        f->pkt_times_capacity = new_cap;
    }
    f->pkt_tl_times[f->pkt_times_size++] = t_us;
}

// 添加到前向动态数组
void flow_add_pkt_fw_time(flow_item_t *f, double t_us) {
    if (f->pkt_fw_times_size == f->pkt_fw_times_capacity) {
        size_t new_cap = f->pkt_fw_times_capacity ? f->pkt_fw_times_capacity * 2 : 4;
        double *tmp = realloc(f->pkt_fw_times, new_cap * sizeof *tmp);
        if (!tmp) exit(EXIT_FAILURE);
        f->pkt_fw_times = tmp;
        f->pkt_fw_times_capacity = new_cap;
    }
    f->pkt_fw_times[f->pkt_fw_times_size++] = t_us;
}

void flow_add_pkt_bw_time(flow_item_t *f, double t_us) {
    if (f->pkt_bw_times_size == f->pkt_bw_times_capacity) {
        size_t new_cap = f->pkt_bw_times_capacity ? f->pkt_bw_times_capacity * 2 : 4;
        double *tmp = realloc(f->pkt_bw_times, new_cap * sizeof *tmp);
        if (!tmp) exit(EXIT_FAILURE);
        f->pkt_bw_times = tmp;
        f->pkt_bw_times_capacity = new_cap;
    }
    f->pkt_bw_times[f->pkt_bw_times_size++] = t_us;
}

void flow_add_f_pkt_len(flow_item_t *f, uint64_t len) {
    if (f->f_pkt_lens_size == f->f_pkt_lens_capacity) {
        size_t new_cap = f->f_pkt_lens_capacity ? f->f_pkt_lens_capacity * 2 : 4;
        uint64_t *tmp = realloc(f->f_pkt_lens, new_cap * sizeof *tmp);
        if (!tmp) { perror("realloc"); exit(EXIT_FAILURE); }
        f->f_pkt_lens = tmp;
        f->f_pkt_lens_capacity = new_cap;
    }
    f->f_pkt_lens[f->f_pkt_lens_size++] = len;
}

void flow_add_b_pkt_len(flow_item_t *f, uint64_t len) {
    if (f->b_pkt_lens_size == f->b_pkt_lens_capacity) {
        size_t new_cap = f->b_pkt_lens_capacity ? f->b_pkt_lens_capacity * 2 : 4;
        uint64_t *tmp = realloc(f->b_pkt_lens, new_cap * sizeof *tmp);
        if (!tmp) { perror("realloc"); exit(EXIT_FAILURE); }
        f->b_pkt_lens = tmp;
        f->b_pkt_lens_capacity = new_cap;
    }
    f->b_pkt_lens[f->b_pkt_lens_size++] = len;
}

void compute_iat(const double *times, size_t n,
                double *fl_iat_avg, double *fl_iat_std,
                double *fl_iat_max, double *fl_iat_min) {

    // double *times = f->pkt_tl_times;
    // size_t n = f->pkt_times_size;

    if (n < 2) {
        *fl_iat_avg = *fl_iat_std = *fl_iat_min = *fl_iat_max = 0.0;
        return;
    }
    size_t cnt = n - 1;
    double sum = 0, sumsq = 0;
    *fl_iat_min = times[1] - times[0];
    *fl_iat_max = *fl_iat_min;

    for (size_t i = 1; i < n; ++i) {
        double d = times[i] - times[i - 1];
        if (d < *fl_iat_min) *fl_iat_min = d;
        if (d > *fl_iat_max) *fl_iat_max = d;
        sum += d;
        sumsq += d * d;
    }
    *fl_iat_avg = sum / cnt;
    double var = sumsq / cnt - (*fl_iat_avg) * (*fl_iat_avg);
    *fl_iat_std = sqrt(var);
}

void flow_stats(const flow_item_t *f,
                double *avg, uint64_t *min, uint64_t *max, double *stddev) {
    size_t n = f->pkt_lens_size;
    if (n == 0) {
        *avg = *stddev = 0.0;
        *min = *max = 0;
        return;
    }
    uint64_t sum = 0;
    *min = *max = f->pkt_lens[0];
    for (size_t i = 0; i < n; ++i) {
        uint64_t x = f->pkt_lens[i];
        sum += x;
        if (x < *min) *min = x;
        if (x > *max) *max = x;
    }
    *avg = (double)sum / n;
    double var = 0;
    for (size_t i = 0; i < n; ++i) {
        double d = f->pkt_lens[i] - *avg;
        var += d * d;
    }
    var /= n;
    *stddev = sqrt(var);
}

void flow_stats2(uint64_t *pkt_lens, size_t pkt_lens_size,
                double *avg, uint64_t *min, uint64_t *max, double *stddev) {
    size_t n = pkt_lens_size;
    if (n == 0) {
        *avg = *stddev = 0.0;
        *min = *max = 0;
        return;
    }
    uint64_t sum = 0;
    *min = *max = pkt_lens[0];
    for (size_t i = 0; i < n; ++i) {
        uint64_t x = pkt_lens[i];
        sum += x;
        if (x < *min) *min = x;
        if (x > *max) *max = x;
    }
    *avg = (double)sum / n;
    double var = 0;
    for (size_t i = 0; i < n; ++i) {
        double d = pkt_lens[i] - *avg;
        var += d * d;
    }
    var /= n;
    *stddev = sqrt(var);
}

void insert_flow(const struct pcap_pkthdr *header,
                 const struct ip *ip_hdr,
                 const struct tcphdr *tcp_hdr) {
    // 创建并初始化键
    // flow_key_t orig = {
    //     .src_ip   = ntohl(ip_hdr->ip_src.s_addr),
    //     .dst_ip   = ntohl(ip_hdr->ip_dst.s_addr),
    //     .src_port = ntohs(tcp_hdr->th_sport),
    //     .dst_port = ntohs(tcp_hdr->th_dport),
    //     .protocol = ip_hdr->ip_p
    // };
    // flow_item_t *item = NULL;
    // item = (flow_item_t*)malloc(sizeof(flow_item_t));
    // memcpy(&item->key, &orig, sizeof(flow_key_t));
    // HASH_ADD(hh, flow_table, key, sizeof(flow_key_t), item);

    //——————————————————第二次修改——————————————————
    // 构造“规范化”键
    flow_key_t ckey;
    // 先置换顺序
    bool direct = make_canonical_key(ip_hdr, tcp_hdr, &ckey);
    int ip_hdr_len = ip_hdr->ip_hl * 4;
    int tcp_hdr_len = tcp_hdr->th_off * 4;
    // 分配并初始化
    flow_item_t *item = malloc(sizeof(*item));
    memcpy(&item->key, &ckey, sizeof(ckey));
    item->first_ts     = header->ts;                  // 用 pcap 提供的秒+微秒
    item->last_ts      = header->ts;
    item->packet_count = 1;
    item->byte_count   = ntohs(ip_hdr->ip_len) - ip_hdr_len - tcp_hdr_len;
    item->f_direct = 0, item->b_direct = 0; // 初始化flow的正向包和反向包的个数
    flow_init(item);
    flow_add_pkt_len(item,item->byte_count);
    double t_us = (double)header->ts.tv_sec * 1e6 + (double)header->ts.tv_usec;
    flow_add_pkt_time(item,t_us);

    if (direct) {
        // 反方向
        item->b_direct +=1;
        flow_add_b_pkt_len(item,item->byte_count);
        flow_add_pkt_bw_time(item,t_us);
    }else {
        item->f_direct +=1;
        flow_add_f_pkt_len(item,item->byte_count);
        flow_add_pkt_fw_time(item,t_us);
    }

    // 加入哈希表
    HASH_ADD(hh, flow_table, key, sizeof(flow_key_t), item);
    //
    // 检查是否已存在
    // flow_item_t *item = NULL;
    // HASH_FIND(hh, flow_table, &orig, sizeof(flow_key_t), item);
    //
    // if (!item) {
    //     // 新建表项
    //     item = (flow_item_t*)malloc(sizeof(flow_item_t));
    //     memcpy(&item->key, &orig, sizeof(flow_key_t));
    //     // 初始化其他数据（如 item->data = 0）
    //
    //     // 添加到哈希表
    //     HASH_ADD(hh, flow_table, key, sizeof(flow_key_t), item);
    // }
    // 若已存在，可更新数据（如 item->data++）
}

flow_item_t* find_flow(const struct ip *ip_hdr, const struct tcphdr *tcp_hdr, double t_us) {
    // 构造搜索键 这个匹配没有考虑反向流
    flow_key_t ckey;
    bool direct = make_canonical_key(ip_hdr, tcp_hdr, &ckey);
    flow_item_t *item = NULL;
    HASH_FIND(hh, flow_table, &ckey, sizeof(flow_key_t), item);
    if (item) {
        // 如果找到这个包的话 我们先对其进行正向和反向的包进行计数
        if (direct) {
            // 反方向
            item->b_direct +=1;
            flow_add_b_pkt_len(item,item->byte_count);
            flow_add_pkt_bw_time(item,t_us);
        }else {
            item->f_direct +=1;
            flow_add_f_pkt_len(item,item->byte_count);
            flow_add_pkt_fw_time(item,t_us);

        }
    }
    return item;
}


// 处理收到的 IP 数据包
void process_packet(const struct pcap_pkthdr *header,
                    const struct ip *ip_hdr,
                    const struct tcphdr *tcp_hdr,
                    bool         is_last_packet) {

    // 1 这里的核心内容是处理时间
    //
    flow_item_t *cur, *tmp;
    HASH_ITER(hh, flow_table, cur, tmp) {
        // 先获取当前每个包的时间，然后遍历hash表中flow id的last，并用（当前时间-last），如果超过60s也进行对该flow ID 统计信息并删除
        //time_t      sec_diff  = header->ts.tv_sec  - cur->last_ts.tv_sec;
        //suseconds_t usec_diff = header->ts.tv_usec - cur->last_ts.tv_usec;
        time_t      dur_sec  = cur->last_ts.tv_sec  - cur->first_ts.tv_sec;
        suseconds_t dur_usec = cur->last_ts.tv_usec - cur->first_ts.tv_usec;
        if (dur_usec < 0) {
            dur_sec  -= 1;
            dur_usec += 1000000;
        }
        if (dur_sec >= FLOW_TIMEOUT_SEC) {
            // 计算并打印统计
            //time_t      dur_sec  = cur->last_ts.tv_sec  - cur->first_ts.tv_sec;
            //suseconds_t dur_usec = cur->last_ts.tv_usec - cur->first_ts.tv_usec;
            double total_sec = dur_sec + dur_usec * 1e-6;
            if (dur_usec < 0) {
                dur_sec  -= 1;
                dur_usec += 1000000;
            }
            if (cur->packet_count == 1 || total_sec == 0) {
                puts("use model packet");
            }else {
                // ————————————————显示IP地址——————————————————
                char src_ip_str[INET_ADDRSTRLEN];
                char dst_ip_str[INET_ADDRSTRLEN];

                struct in_addr src_addr = { cur->key.src_ip};
                struct in_addr dst_addr = { cur->key.dst_ip};

                inet_ntop(AF_INET, &src_addr, src_ip_str, sizeof src_ip_str);
                inet_ntop(AF_INET, &dst_addr, dst_ip_str, sizeof dst_ip_str);

                // ————————————————计算基础信息——————————————————
                // long dur_sec = dur_sec /* 你的 dur_sec */;
                // long dur_usec = dur_usec/* dur_usec */;

                double fl_pkt_s = (double)cur->packet_count / total_sec;
                double fl_byt_s = (double)cur->byte_count / total_sec;

                // 计算包的数量
                double avg;
                uint64_t min, max;
                double stddev;
                // flow_stats(cur, &avg, &min, &max, &stddev);
                flow_stats2(cur->pkt_lens, cur->pkt_lens_size, &avg, &min, &max, &stddev);

                double f_avg;
                uint64_t f_min, f_max;
                double f_stddev;
                flow_stats2(cur->f_pkt_lens, cur->f_pkt_lens_size, &f_avg, &f_min, &f_max, &f_stddev);
                unsigned long long tot_l_fw_pkt = 0;
                for (size_t i = 0; i < cur->f_pkt_lens_size; ++i) tot_l_fw_pkt += cur->f_pkt_lens[i];
                double fw_pkt_s = (double)tot_l_fw_pkt / total_sec;

                double b_avg;
                uint64_t b_min, b_max;
                double b_stddev;
                flow_stats2(cur->b_pkt_lens, cur->b_pkt_lens_size, &b_avg, &b_min, &b_max, &b_stddev);
                unsigned long long tot_l_bw_pkt = 0;
                for (size_t i = 0; i < cur->b_pkt_lens_size; ++i) tot_l_fw_pkt += cur->b_pkt_lens[i];
                double bw_pkt_s = (double)tot_l_bw_pkt / total_sec;

                //这里开始计算iat的时间差了
                double fl_iat_avg, fl_iat_std, fl_iat_min,fl_iat_max;
                compute_iat(cur->pkt_tl_times, cur->pkt_times_size, &fl_iat_avg, &fl_iat_std, &fl_iat_max, &fl_iat_min);

                //计算前向包的 fw_iat_tot
                double fw_iat_tot, fw_iat_avg, fw_iat_std, fw_iat_min,fw_iat_max;
                compute_iat(cur->pkt_fw_times, cur->pkt_fw_times_size, &fw_iat_avg, &fw_iat_std, &fw_iat_max, &fw_iat_min);
                fw_iat_tot = fw_iat_avg * (cur->pkt_fw_times_size-1);

                //计算反向包的 bw_iat_tot
                double bw_iat_tot, bw_iat_avg, bw_iat_std, bw_iat_min, bw_iat_max;
                compute_iat(cur->pkt_bw_times, cur->pkt_bw_times_size, &bw_iat_avg, &bw_iat_std, &bw_iat_max, &bw_iat_min);
                bw_iat_tot = bw_iat_avg * (cur->pkt_bw_times_size-1);

                append_flow(
                src_ip_str, cur->key.src_port,
                dst_ip_str, cur->key.dst_port,
                total_sec,
                cur->packet_count,
                cur->byte_count,
                fl_pkt_s,fl_byt_s,avg, (unsigned long long)min,
                (unsigned long long)max, stddev, (unsigned long long)cur->f_direct,(unsigned long long)cur->b_direct,
                f_avg, (unsigned long long)f_min,(unsigned long long)f_max, f_stddev,b_avg,b_min,b_max,b_stddev, fw_pkt_s, bw_pkt_s,
                fl_iat_avg, fl_iat_std, fl_iat_min,fl_iat_max,
                fw_iat_tot, fw_iat_avg, fw_iat_std, fw_iat_min,fw_iat_max,
                bw_iat_tot, bw_iat_avg, bw_iat_std, bw_iat_min, bw_iat_max
                );

                printf("Expired Flow %s:%u → %s:%u: duration %ld.%06lds s, "
                   "%llu pkts, %llu bytes,  %.2f pkts/s, %.2f bytes/s, avg=%.2f, min=%llu, max=%llu, stddev=%.2f, tot_fw_pk = %llu, tot_bw_pk = %llu, fw_pkt_l_avg=%.2f, fw_pkt_l_min=%llu, fw_pkt_l_max=%llu, fw_pkt_l_std=%.2f\n",
                   src_ip_str, cur->key.src_port,
                   dst_ip_str, cur->key.dst_port,
                   (long)dur_sec, (long)dur_usec,
                   (unsigned long long)cur->packet_count,
                   (unsigned long long)cur->byte_count,fl_pkt_s,fl_byt_s,avg, (unsigned long long)min,
                   (unsigned long long)max, stddev, (unsigned long long)cur->f_direct,(unsigned long long)cur->b_direct,
                   f_avg, (unsigned long long)f_min,(unsigned long long)f_max, f_stddev
                   );
                // 删除并释放

            }
            HASH_DEL(flow_table, cur);
            free(cur);
        }
    }
    // 解决掉一部分流之后，开始搜索流
    // 2 搜索流
    double t_us = (double)header->ts.tv_sec * 1e6 + (double)header->ts.tv_usec;
    flow_item_t *found = find_flow(ip_hdr, tcp_hdr,t_us);
    if (found) {
        // 计算两次包到达的时间差（秒 + 微秒）
        time_t  sec_diff  = header->ts.tv_sec  - found->last_ts.tv_sec;
        suseconds_t usec_diff = header->ts.tv_usec - found->last_ts.tv_usec;
        if (usec_diff < 0) {
            sec_diff  -= 1;
            usec_diff += 1000000;
        }
        // 如果找到该流id，则先判断这个包的时间，如果小于60s，则搜集他的统计信息
        // todo function
        //if (sec_diff < FLOW_TIMEOUT_SEC) {
        found->last_ts = header->ts;
        found->packet_count++;

        // uint16_t ip_total_len = ntohs(ip_hdr->ip_len);
        int ip_hdr_len = ip_hdr->ip_hl * 4;
        int tcp_hdr_len = tcp_hdr->th_off * 4;
        int tcp_payload_len =ntohs(ip_hdr->ip_len) - ip_hdr_len - tcp_hdr_len;
        found->byte_count += tcp_payload_len;
        flow_add_pkt_len(found,found->byte_count);
        double t_us = (double)header->ts.tv_sec * 1e6 + (double)header->ts.tv_usec;
        flow_add_pkt_time(found,t_us);

        if (is_last_packet) {

            time_t  dur_sec  = found->last_ts.tv_sec  - found->first_ts.tv_sec;
            suseconds_t dur_usec = found->last_ts.tv_usec - found->first_ts.tv_usec;

            if (dur_usec < 0) {
                dur_sec  -= 1;
                dur_usec += 1000000;
            }

            printf("Flow %u:%u → %u:%u ended: duration %ld.%06lds s, "
                   "%llu pkts, %llu bytes\n",
                   ntohl(found->key.src_ip), found->key.src_port,
                   ntohl(found->key.dst_ip), found->key.dst_port,
                   (long)dur_sec, (long)dur_usec,
                   (unsigned long long)found->packet_count,
                   (unsigned long long)found->byte_count);

            // 从哈希表删除并释放内存
            HASH_DEL(flow_table, found);
            free(found);
        }
        //}
        // 如果超过60s，我们则默认为该流结束
        //else {//找到了 但是超时了。这里存疑？ 可能不需要了
            // time_t  dur_sec  = found->last_ts.tv_sec - found->first_ts.tv_sec;
            // suseconds_t dur_usec = found->last_ts.tv_usec - found->first_ts.tv_usec;
            // if (dur_usec < 0) {
            //     dur_sec  -= 1;
            //     dur_usec += 1000000;
            // }
            //
            // printf("Flow %u:%u → %u:%u ended: duration %ld.%06lds s, "
            //        "%llu pkts, %llu bytes\n",
            //        ntohl(found->key.src_ip), found->key.src_port,
            //        ntohl(found->key.dst_ip), found->key.dst_port,
            //        (long)dur_sec, (long)dur_usec,
            //        (unsigned long long)found->packet_count,
            //        (unsigned long long)found->byte_count);

            // 从哈希表删除并释放内存
            // HASH_DEL(flow_table, found);
            // free(found);


            // 如果这包只是触发结束（sec_diff ≥ 60），
            // **且** 这包不是最后一包，就当作新流首包插入
            // if (sec_diff >= FLOW_TIMEOUT_SEC && !is_last_packet) {
            //     insert_flow(header, ip_hdr, tcp_hdr);
            // }
            // todo function 计算其统计信息，在hash中删除他的信息
            //printf("Flow found!\n");
        // 使用 found->data 或其他字段」
        }else {
        // 遇到新五元组
        insert_flow(header, ip_hdr, tcp_hdr);
        // struct timeval now = header->ts;
        // todo function：每次遍历这个包的时候，先获取时间，然后遍历hash表中flow id的last，并用（当前时间-last），如果超过60s也进行对该flow ID 统计信息并删除
    }
}

void packet_lzy_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    pkt_ctx_t *c = (pkt_ctx_t*)user;
    c->index++;
    bool is_last = (c->index == c->total);

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
            // expire_flows(&header->ts);
            // t = header->ts.tv_sec + header->ts.tv_usec/1e6;;
            struct ip *ip_hdr = (struct ip*)(payload);
            struct tcphdr *t = (void*)payload + ip_hdr->ip_hl*4;
            // uint8_t *tcp = (ip_hdr + ip_hdr->ip_hl*4);
            // uint16_t th_sport = (tcp[0] << 4) | tcp[1];
            process_packet(header, ip_hdr, t, is_last);
            // flow_key_t orig = {
            //     ntohl(ip_hdr->ip_src.s_addr), ntohl(ip_hdr->ip_dst.s_addr),
            //     0,0,
            //     ip_hdr->ip_p
            // };
            // orig.src_port = ntohs(t->th_sport);
            // orig.dst_port = ntohs(t->th_dport);

            // 3) 找流、更新
            //flow_record_t *f = flow_find_or_create(&orig, &header->ts);
            //flow_update(f, payload, &header->ts);

            // if (!f->fin_seen) {
            //     compute_flow_features(f);
            // }
            //free(f);


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
