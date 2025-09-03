//
// Created by sailor on 2025/8/11.
//
#include <stdio.h>
#include "computefunction.h"
#include <stdbool.h>
#include <math.h>
#include <stdlib.h>
#include <stdint.h>
#include "csvwriter.h"
#include "parse_tls.h"
#include "parse_dns.h"
#include "parse_http.h"
#include <arpa/inet.h>  // POSIX
#include <netinet/udp.h>
#define PPPoE_TYPE_DISCOVERY 0x8863
#define PPPoE_TYPE_SESSION   0x8864
#define FLOW_Segment_SEC 5  // 活跃流阈值（秒），可根据需要修改
#define FLOW_TIMEOUT_SEC 120  // 流超时阈值（秒），可根据需要修改
#define SubFlow_Timeout 1 //  子流的时间阈值1s

#if defined(__APPLE__) || defined(__FreeBSD__)
  #define UDP_SRC(h) ((h)->uh_sport)
  #define UDP_DST(h) ((h)->uh_dport)
#else
  #define UDP_SRC(h) ((h)->source)
  #define UDP_DST(h) ((h)->dest)
#endif


#if defined(__APPLE__) || defined(__FreeBSD__)
  #define UDP_LEN(h)  ((h)->uh_ulen)   // 含UDP头
#else
  #define UDP_LEN(h)  ((h)->len)
#endif

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

static bool make_canonical_key_udp(const struct ip *ip_hdr,
                                   const struct udphdr *udp_hdr,
                                   flow_key_t *key)
{
    uint32_t src_ip = ip_hdr->ip_src.s_addr;
    uint32_t dst_ip = ip_hdr->ip_dst.s_addr;
    uint16_t src_pt = ntohs(UDP_SRC(udp_hdr));
    uint16_t dst_pt = ntohs(UDP_DST(udp_hdr));

    key->protocol = ip_hdr->ip_p;   // 或者直接写 IPPROTO_UDP

    if (src_ip > dst_ip || (src_ip == dst_ip && src_pt > dst_pt)) {
        // 反向：交换成规范顺序
        key->src_ip   = dst_ip;
        key->dst_ip   = src_ip;
        key->src_port = dst_pt;
        key->dst_port = src_pt;
        return true;   // 与你原函数的“反向返回1”一致
    } else {
        // 正向：保持不变
        key->src_ip   = src_ip;
        key->dst_ip   = dst_ip;
        key->src_port = src_pt;
        key->dst_port = dst_pt;
        return false;  // 与你原函数的“正向返回0”一致
    }
}

void flow_init(flow_item_t *f) {
    // f->sni = NULL;
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
    double sum = 0, var = 0;
    *fl_iat_min = times[1] - times[0];
    *fl_iat_max = *fl_iat_min;

    for (size_t i = 1; i < n; ++i) {
        // printf("%.2f\n",times[i]);
        double d = times[i] - times[i - 1];
        if (d < *fl_iat_min) *fl_iat_min = d;
        if (d > *fl_iat_max) *fl_iat_max = d;
        sum += d;
        // sumsq += d * d;
    }
    *fl_iat_avg = sum / cnt;

    double var_sum = 0;
    for (size_t i = 1; i < n; ++i) {
        double d = times[i] - times[i - 1];
        var_sum += (d - (*fl_iat_avg)) * (d - (*fl_iat_avg));
    }
    if ((cnt-1)>0)  var = var_sum / (cnt-1) ;
    else var = 0;
    *fl_iat_std = sqrt(var);
}

void compute_subflow(const double *times, const uint64_t *lens, size_t n,
                     double *subfl_pk, double *subfl_byt,
                     double *subfl_pk_max, double *subfl_pk_min,
                     double *subfl_byt_max, double *subfl_byt_min) {

    if (n == 0) {
        *subfl_pk = *subfl_byt = 0.0;
        *subfl_pk_max = *subfl_pk_min = 0.0;
        *subfl_byt_max = *subfl_byt_min = 0.0;
        return;
    }

    size_t cur_pkts = 1;
    uint64_t cur_bytes = lens[0];
    size_t total_subflows = 0;
    size_t total_pkts = 0;
    uint64_t total_bytes = 0;

    size_t max_pkts = 0, min_pkts = SIZE_MAX;
    uint64_t max_bytes = 0, min_bytes = UINT64_MAX;

    for (size_t i = 1; i < n; ++i) {
        double delta = times[i] - times[i - 1];
        if (delta < SubFlow_Timeout) {
            cur_pkts++;
            cur_bytes += lens[i];
        } else {
            // 记录当前子流信息
            total_subflows++;
            total_pkts += cur_pkts;
            total_bytes += cur_bytes;

            if (cur_pkts > max_pkts) max_pkts = cur_pkts;
            if (cur_pkts < min_pkts) min_pkts = cur_pkts;
            if (cur_bytes > max_bytes) max_bytes = cur_bytes;
            if (cur_bytes < min_bytes) min_bytes = cur_bytes;

            // 新子流
            cur_pkts = 1;
            cur_bytes = lens[i];
        }
    }

    // 最后一个子流
    total_subflows++;
    total_pkts += cur_pkts;
    total_bytes += cur_bytes;

    if (cur_pkts > max_pkts) max_pkts = cur_pkts;
    if (cur_pkts < min_pkts) min_pkts = cur_pkts;
    if (cur_bytes > max_bytes) max_bytes = cur_bytes;
    if (cur_bytes < min_bytes) min_bytes = cur_bytes;

    *subfl_pk = (double)total_pkts / total_subflows;
    *subfl_byt = (double)total_bytes / total_subflows;
    *subfl_pk_max = (double)max_pkts;
    *subfl_pk_min = (double)min_pkts;
    *subfl_byt_max = (double)max_bytes;
    *subfl_byt_min = (double)min_bytes;
}

void compute_idle_active(const double *times, size_t n,
                 double *fl_act_avg, double *fl_act_std,
                 double *fl_act_max, double *fl_act_min,
                 double *fl_idle_avg, double *fl_idle_std,
                 double *fl_idle_max, double *fl_idle_min,
                 double threshold_s) {
    *fl_act_avg = *fl_act_std = *fl_act_min = *fl_act_max = 0.0;
    *fl_idle_avg = *fl_idle_std = *fl_idle_min = *fl_idle_max = 0.0;
    if (n < 2) return;

    // 分别累计活动和空闲间隔
    double sum_act = 0, sumsq_act = 0;
    double sum_idle = 0, sumsq_idle = 0;
    size_t cnt_act = 0, cnt_idle = 0;

    for (size_t i = 1; i < n; ++i) {
        double d = times[i] - times[i - 1];
        if (d <= threshold_s) {
            // 活跃段
            if (cnt_act == 0) *fl_act_min = *fl_act_max = d;
            else {
                *fl_act_min = fmin(*fl_act_min, d);
                *fl_act_max = fmax(*fl_act_max, d);
            }
            sum_act += d;
            sumsq_act += d * d;
            cnt_act++;
        } else {
            // 空闲段
            if (cnt_idle == 0) *fl_idle_min = *fl_idle_max = d;
            else {
                *fl_idle_min = fmin(*fl_idle_min, d);
                *fl_idle_max = fmax(*fl_idle_max, d);
            }
            sum_idle += d;
            sumsq_idle += d * d;
            cnt_idle++;
        }
    }

    if (cnt_act > 0) {
        *fl_act_avg = sum_act / cnt_act;
        *fl_act_std = sqrt(sumsq_act/cnt_act - (*fl_act_avg)*(*fl_act_avg));
    }
    if (cnt_idle > 0) {
        *fl_idle_avg = sum_idle / cnt_idle;
        *fl_idle_std = sqrt(sumsq_idle/cnt_idle - (*fl_idle_avg)*(*fl_idle_avg));
    }
}

void flow_stats(uint64_t *pkt_lens, size_t pkt_lens_size,
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

    int ip_hdr_len = ip_hdr->ip_hl * 4;
    int tcp_hdr_len = tcp_hdr->th_off * 4;
    int tcp_payload_len =ntohs(ip_hdr->ip_len) - ip_hdr_len - tcp_hdr_len;
    if (tcp_payload_len <= 0) return;
    const uint8_t *tcp_payload = (const uint8_t *)tcp_hdr + tcp_hdr_len;

    //——————————————————第二次修改——————————————————
    // 构造“规范化”键
    flow_key_t ckey;
    // 先置换顺序
    bool direct = make_canonical_key(ip_hdr, tcp_hdr, &ckey);
    // int ip_hdr_len = ip_hdr->ip_hl * 4;
    // int tcp_hdr_len = tcp_hdr->th_off * 4;
    // 分配并初始化
    flow_item_t *item = malloc(sizeof(*item));
    memcpy(&item->key, &ckey, sizeof(ckey));
    item->direct = direct;

    if ((ntohs(tcp_hdr->th_dport) == 443 || ntohs(tcp_hdr->th_sport) == 443) && (tcp_payload_len+20) > 32){
        char *sni = extract_sni(tcp_payload, tcp_payload_len);
        if (sni != NULL) {
            size_t n = strnlen(sni, 4096);
            item->sni = (char *)malloc(n + 1);
            if (item->sni) {
                memcpy(item->sni, sni, n+1);
                item->sni[n] = '\0';
            }
            free(sni);
        }
    }

    if ( (ntohs(tcp_hdr->th_dport) == 80 || ntohs(tcp_hdr->th_sport) == 80 || looks_like_http_req(tcp_payload, tcp_payload_len))
     && tcp_payload_len > 0 )
    {
        char *host = extract_http_host(tcp_payload, tcp_payload_len);
        if (host) {
            // 结构里建议加一个字段 char *http_host; （避免覆盖 sni）
            if (!item->sni) {
                item->sni = host; // 直接接管所有权
            } else {
                free(host); // 已有就丢弃，避免泄露
            }
        }
    }

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

}

void insert_flow_udp(const struct pcap_pkthdr *header,
                     const struct ip *ip_hdr,
                     const struct udphdr *udp_hdr)
{
    //—— 构造“规范化”键（与 TCP 版一致的字典序归一，返回是否反向）——
    flow_key_t ckey;
    bool direct = make_canonical_key_udp(ip_hdr, udp_hdr, &ckey);
    flow_item_t *item = (flow_item_t*)malloc(sizeof(*item));
    //—— 长度计算：payload = IP总长 - IP头长 - UDP头长(8) ——
    int ip_hdr_len       = ip_hdr->ip_hl * 4;
    int udp_hdr_len      = (int)sizeof(struct udphdr);
    int ip_total_len     = (int)ntohs(ip_hdr->ip_len);
    int l4_total_by_ip   = ip_total_len - ip_hdr_len;                 // IP口径
    int l4_total_by_udp  = (int)ntohs(UDP_LEN(udp_hdr));              // UDP口径(含头)
    int l4_total = l4_total_by_ip;
    if (l4_total_by_udp >= udp_hdr_len && l4_total_by_udp <= l4_total_by_ip)
        l4_total = l4_total_by_udp;

    int udp_payload_len  = ip_total_len - ip_hdr_len - udp_hdr_len;
    if (udp_payload_len < 0) udp_payload_len = 0;   // 防御性


    if ((ntohs(udp_hdr->uh_sport) == 53)||(ntohs(udp_hdr->uh_dport) == 53)) {
        const uint8_t *udp_bytes = (const uint8_t *)udp_hdr;            // start at UDP header
        char *dns_name = extract_udp_payload(udp_bytes, (uint32_t)l4_total);

        if ((dns_name!=NULL) && (item->sni == NULL)) {
            size_t n = strnlen(dns_name, 4096);
            item->sni = (char *)malloc(n + 1);
            if (item->sni) {
                memcpy(item->sni, dns_name, n+1);
                item->sni[n] = '\0';
            }
            free(dns_name);
        }

    }
    // 也可更“严格”用 UDP 自身长度（含头），与 IP 校验取 min：
    // int ulen = (int)ntohs(UDP_LEN(udp_hdr));
    // int l4_total = ulen > 0 ? ulen : (ip_total_len - ip_hdr_len);
    // int udp_payload_len = l4_total - udp_hdr_len; if (udp_payload_len < 0) udp_payload_len = 0;

    //—— 分配并初始化 ——

    memcpy(&item->key, &ckey, sizeof(ckey));

    item->first_ts     = header->ts;
    item->last_ts      = header->ts;
    item->packet_count = 1;
    item->byte_count   = udp_payload_len;

    item->f_direct = 0;
    item->b_direct = 0;

    flow_init(item);                         // 你已有的初始化
    flow_add_pkt_len(item, item->byte_count);

    double t_us = (double)header->ts.tv_sec * 1e6 + (double)header->ts.tv_usec;
    flow_add_pkt_time(item, t_us);

    if (direct) {
        // 反方向（make_canonical_key_udp 里发生了交换）
        item->b_direct += 1;
        flow_add_b_pkt_len(item, item->byte_count);
        flow_add_pkt_bw_time(item, t_us);
    } else {
        // 正方向
        item->f_direct += 1;
        flow_add_f_pkt_len(item, item->byte_count);
        flow_add_pkt_fw_time(item, t_us);
    }

    //—— 加入哈希表（与 TCP 相同）——
    HASH_ADD(hh, flow_table, key, sizeof(flow_key_t), item);
}

flow_item_t* find_flow(const struct ip *ip_hdr, const struct tcphdr *tcp_hdr) {
    // 构造搜索键 这个匹配没有考虑反向流
    flow_key_t ckey;
    bool direct = make_canonical_key(ip_hdr, tcp_hdr, &ckey);
    flow_item_t *item = NULL;
    HASH_FIND(hh, flow_table, &ckey, sizeof(flow_key_t), item);
    if (item) {
        // 如果找到这个包的话 我们先对其进行正向和反向的包进行计数
        if (direct) {
            // 反方向
            item->direct = true;
        }else {
            item->direct = false;
        }
    }
    return item;
}

flow_item_t* find_udp_flow(const struct ip *ip_hdr, const struct udphdr *udp_hdr) {
    // 构造搜索键 这个匹配没有考虑反向流
    flow_key_t ckey;
    bool direct = make_canonical_key_udp(ip_hdr, udp_hdr, &ckey);
    flow_item_t *item = NULL;
    HASH_FIND(hh, flow_table, &ckey, sizeof(flow_key_t), item);
    if (item) {
        // 如果找到这个包的话 我们先对其进行正向和反向的包进行计数
        if (direct) {
            // 反方向
            item->direct = true;
        }else {
            item->direct = false;
        }
    }
    return item;
}

void cal_write_csv(flow_item_t *cur) {
    time_t      dur_sec  = cur->last_ts.tv_sec  - cur->first_ts.tv_sec;
    suseconds_t dur_usec = cur->last_ts.tv_usec - cur->first_ts.tv_usec;
    double total_sec = dur_sec + dur_usec * 1e-6;
    if (dur_usec < 0) {
        dur_sec  -= 1;
        dur_usec += 1000000;
    }
    if (cur->packet_count == 1 || total_sec == 0) {
        // puts("use model packet");
        // return;
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
        flow_stats(cur->pkt_lens, cur->pkt_lens_size, &avg, &min, &max, &stddev);

        double f_avg;
        uint64_t f_min, f_max;
        double f_stddev;
        flow_stats(cur->f_pkt_lens, cur->f_pkt_lens_size, &f_avg, &f_min, &f_max, &f_stddev);
        unsigned long long tot_l_fw_pkt = 0;
        for (size_t i = 0; i < cur->f_pkt_lens_size; ++i) tot_l_fw_pkt += cur->f_pkt_lens[i];
        double fw_pkt_s = (double)tot_l_fw_pkt / total_sec;

        double b_avg;
        uint64_t b_min, b_max;
        double b_stddev;
        flow_stats(cur->b_pkt_lens, cur->b_pkt_lens_size, &b_avg, &b_min, &b_max, &b_stddev);
        unsigned long long tot_l_bw_pkt = 0;
        for (size_t i = 0; i < cur->b_pkt_lens_size; ++i) tot_l_fw_pkt += cur->b_pkt_lens[i];
        double bw_pkt_s = (double)tot_l_bw_pkt / total_sec;

        //这里开始计算iat的时间差了
        double tl_iat_avg, tl_iat_std, tl_iat_min,tl_iat_max, tl_cv, tl_Barabasi;
        compute_iat(cur->pkt_tl_times, cur->pkt_times_size, &tl_iat_avg, &tl_iat_std, &tl_iat_max, &tl_iat_min);
        if (tl_iat_avg>0.0001) tl_cv = tl_iat_std/tl_iat_avg;
        else tl_cv =0;
        if ((tl_iat_std+tl_iat_avg)>0.0001)  tl_Barabasi = (tl_iat_std-tl_iat_avg)/(tl_iat_std+tl_iat_avg);
        else tl_Barabasi =0;


        //计算前向包的 fw_iat_tot
        double fw_iat_tot, fw_iat_avg, fw_iat_std, fw_iat_min,fw_iat_max;
        compute_iat(cur->pkt_fw_times, cur->pkt_fw_times_size, &fw_iat_avg, &fw_iat_std, &fw_iat_max, &fw_iat_min);
        fw_iat_tot = fw_iat_avg * (cur->pkt_fw_times_size-1);

        //计算反向包的 bw_iat_tot
        double bw_iat_tot, bw_iat_avg, bw_iat_std, bw_iat_min, bw_iat_max;
        compute_iat(cur->pkt_bw_times, cur->pkt_bw_times_size, &bw_iat_avg, &bw_iat_std, &bw_iat_max, &bw_iat_min);
        bw_iat_tot = bw_iat_avg * (cur->pkt_bw_times_size-1);

        double atv_avg, atv_std, atv_max, atv_min,
            idl_avg, idl_std, idl_max, idl_min;
        compute_idle_active(cur->pkt_tl_times, cur->pkt_times_size,
            &atv_avg, &atv_std, &atv_max, &atv_min,
            &idl_avg, &idl_std, &idl_max, &idl_min,
            FLOW_Segment_SEC /* 活跃阈值（秒） */);

        double subfw_pk,  subfw_byt, subfw_pk_max, subfw_pk_min, subfw_byt_max, subfw_byt_min;
        compute_subflow(cur->pkt_fw_times, cur->f_pkt_lens, cur->pkt_fw_times_size,
            &subfw_pk,  &subfw_byt, &subfw_pk_max, &subfw_pk_min, &subfw_byt_max, &subfw_byt_min);

        double subbw_pk,  subbw_byt, subbw_pk_max, subbw_pk_min, subbw_byt_max, subbw_byt_min;
        compute_subflow(cur->pkt_bw_times, cur->b_pkt_lens, cur->pkt_bw_times_size,
            &subbw_pk,  &subbw_byt, &subbw_pk_max, &subbw_pk_min, &subbw_byt_max, &subbw_byt_min);

        if (!cur->sni) {
            cur->sni = "null";
        }



        append_flow(
        src_ip_str, cur->key.src_port,
        dst_ip_str, cur->key.dst_port,
        total_sec,
        cur->packet_count,
        cur->byte_count,
        fl_pkt_s,fl_byt_s,avg, (unsigned long long)min,
        (unsigned long long)max, stddev, (unsigned long long)cur->f_direct,(unsigned long long)cur->b_direct,
        f_avg, (unsigned long long)f_min,(unsigned long long)f_max, f_stddev,b_avg,b_min,b_max,b_stddev, fw_pkt_s, bw_pkt_s,
        tl_iat_avg, tl_iat_std, tl_iat_min,tl_iat_max,
        fw_iat_tot, fw_iat_avg, fw_iat_std, fw_iat_min,fw_iat_max,
        bw_iat_tot, bw_iat_avg, bw_iat_std, bw_iat_min, bw_iat_max,
        atv_avg, atv_std, atv_max, atv_min,
        idl_avg, idl_std, idl_max, idl_min,
        subfw_pk,  subfw_byt, subfw_pk_max, subfw_pk_min, subfw_byt_max, subfw_byt_min,
        subbw_pk,  subbw_byt, subbw_pk_max, subbw_pk_min, subbw_byt_max, subbw_byt_min,tl_cv, tl_Barabasi, cur->sni
        );
    }
}

void loop_process(const struct pcap_pkthdr *header) {
    flow_item_t *cur, *tmp;
    HASH_ITER(hh, flow_table, cur, tmp) {
        // 先获取当前每个包的时间，然后遍历hash表中flow id的last，并用（当前时间-last），如果超过60s也进行对该flow ID 统计信息并删除
        // 先获取当前每个包的时间，然后遍历hash表中flow id的last，并用（当前时间-last），如果超过60s也进行对该flow ID 统计信息并删除
        time_t      sec_diff  = header->ts.tv_sec  - cur->last_ts.tv_sec;
        suseconds_t usec_diff = header->ts.tv_usec - cur->last_ts.tv_usec;
        if (sec_diff < 0) {
            sec_diff  -= 1;
            usec_diff += 1000000;
        }
        if (sec_diff >= FLOW_TIMEOUT_SEC) {
            cal_write_csv(cur);
            // 从哈希表删除并释放内存
            HASH_DEL(flow_table, cur);
            free(cur);
        }
    }

}

void process_all_remain_flow() {
    flow_item_t *cur, *tmp;
    HASH_ITER(hh, flow_table, cur, tmp) {
        cal_write_csv(cur);
        HASH_DEL(flow_table, cur);
        free(cur);
    }
}

// 处理收到的 IP 数据包
void process_packet(const struct pcap_pkthdr *header,
                    const struct ip *ip_hdr,
                    const struct tcphdr *tcp_hdr,
                    bool         is_last_packet) {

    // 解决掉一部分流之后，开始搜索流
    // 1 搜索流
    double t_us = (double)header->ts.tv_sec * 1e6 + (double)header->ts.tv_usec;
    flow_item_t *found = find_flow(ip_hdr, tcp_hdr);

    // 2 这里先看看是不是tls，有没有sni号
    // tcp_length = payload_length - 20;
    // unsigned tcp_length = tcp_hdr->th_off * 4; // doff 以 4B 为单位
    int ip_hdr_len = ip_hdr->ip_hl * 4;
    int tcp_hdr_len = tcp_hdr->th_off * 4;
    int tcp_payload_len =ntohs(ip_hdr->ip_len) - ip_hdr_len - tcp_hdr_len;
    if (tcp_payload_len <= 0) return;
    const uint8_t *tcp_payload = (const uint8_t *)tcp_hdr + tcp_hdr_len;

    if (found) {

        if ((ntohs(tcp_hdr->th_dport) == 443 || ntohs(tcp_hdr->th_sport) == 443) && (tcp_payload_len+20) > 32){
            char *sni = extract_sni(tcp_payload, tcp_payload_len);
            if (sni!=NULL) {
                size_t n = strnlen(sni, 4096);
                found->sni = (char *)malloc(n + 1);
                if (found->sni) {
                    memcpy(found->sni, sni, n+1);
                    found->sni[n] = '\0';
                }
                free(sni);
            }
        }

        if ( (ntohs(tcp_hdr->th_dport) == 80 || ntohs(tcp_hdr->th_sport) == 80 || looks_like_http_req(tcp_payload, tcp_payload_len))
     && tcp_payload_len > 0 )
        {
            char *host = extract_http_host(tcp_payload, tcp_payload_len);
            if (host) {
                // 结构里建议加一个字段 char *http_host; （避免覆盖 sni）
                if (!found->sni) {
                    found->sni = host; // 直接接管所有权
                } else {
                    free(host); // 已有就丢弃，避免泄露
                }
            }
        }


        // 计算两次包到达的时间差（秒 + 微秒）
        time_t  dur_sec  = header->ts.tv_sec  - found->first_ts.tv_sec;
        suseconds_t dur_usec = header->ts.tv_usec - found->first_ts.tv_usec;

        if (dur_usec < 0) {
            dur_sec  -= 1;
            dur_usec += 1000000;
        }
        // 如果找到该流id，则先判断这个包的时间，如果小于120s，则搜集他的统计信息
        // todo function
        if (dur_sec < FLOW_TIMEOUT_SEC) {
            // ------ 后续的时间进行替换------
            found->last_ts = header->ts;
            found->packet_count++;
            // uint16_t ip_total_len = ntohs(ip_hdr->ip_len);

            found->byte_count += tcp_payload_len;
            // flow_add_pkt_len(found,found->byte_count);
            flow_add_pkt_len(found,tcp_payload_len);
            flow_add_pkt_time(found,t_us);

            if (found->direct==true) {
                // 反方向
                found->b_direct +=1;
                // flow_add_b_pkt_len(found,found->byte_count);
                flow_add_b_pkt_len(found,tcp_payload_len);
                flow_add_pkt_bw_time(found,t_us);
            }else {
                found->f_direct +=1;
                // flow_add_f_pkt_len(found,found->byte_count);
                flow_add_f_pkt_len(found,tcp_payload_len);
                flow_add_pkt_fw_time(found,t_us);
            }
            // ------如果结束了，就把table里面的东西全部算了------
            if (is_last_packet) {
                process_all_remain_flow(found);
            }

        }// 如果超过60s，我们则默认为该流结束
        else {//找到了 但是超时了

            // ————————————超时了就要把他算掉，但是这个包没有————————
            cal_write_csv(found);
            HASH_DEL(flow_table, found);
            free(found);
            insert_flow(header, ip_hdr, tcp_hdr);
            }
            // todo function 计算其统计信息，在hash中删除他的信息
        }
    else {
        // 遇到新五元组
        insert_flow(header, ip_hdr, tcp_hdr);
        // struct timeval now = header->ts;
        // todo function：每次遍历这个包的时候，先获取时间，然后遍历hash表中flow id的last，并用（当前时间-last），如果超过60s也进行对该flow ID 统计信息并删除
        loop_process(header);
    }


}

void process_udp_packet(const struct pcap_pkthdr *header,
                        const struct ip *ip_hdr,
                        const struct udphdr *udp_hdr,
                        bool         is_last_packet) {

    // 1 时间戳
    double t_us = (double)header->ts.tv_sec * 1e6 + (double)header->ts.tv_usec;

    int ip_hdr_len   = ip_hdr->ip_hl * 4;
    int udp_hdr_len  = (int)sizeof(struct udphdr);
    int ip_total_len = (int)ntohs(ip_hdr->ip_len);
    int l4_total_by_ip   = ip_total_len - ip_hdr_len;                 // IP口径
    int l4_total_by_udp  = (int)ntohs(UDP_LEN(udp_hdr));              // UDP口径(含头)
    int l4_total = l4_total_by_ip;
    if (l4_total_by_udp >= udp_hdr_len && l4_total_by_udp <= l4_total_by_ip)
        l4_total = l4_total_by_udp;
    // 2 搜索流（与 TCP 版对应的 find_flow_udp）

    flow_item_t *found = find_udp_flow(ip_hdr, udp_hdr);
    if (found) {

        if ((ntohs(udp_hdr->uh_sport) == 53)||(ntohs(udp_hdr->uh_dport) == 53)) {
            const uint8_t *udp_bytes = (const uint8_t *)udp_hdr;            // start at UDP header
            char *dns_name = extract_udp_payload(udp_bytes, (uint32_t)l4_total);

            if ((dns_name!=NULL) && (found->sni == NULL)) {
                size_t n = strnlen(dns_name, 4096);
                found->sni = (char *)malloc(n + 1);
                if (found->sni) {
                    memcpy(found->sni, dns_name, n+1);
                    found->sni[n] = '\0';
                }
                free(dns_name);
            }

        }
        // 计算与“首包”时间的差（保持你原来的语义）
        time_t      dur_sec  = header->ts.tv_sec  - found->first_ts.tv_sec;
        suseconds_t dur_usec = header->ts.tv_usec - found->first_ts.tv_usec;
        if (dur_usec < 0) { dur_sec -= 1; dur_usec += 1000000; }

        if (dur_sec < FLOW_TIMEOUT_SEC) {
            // 更新统计
            found->last_ts = header->ts;
            found->packet_count++;


            int udp_payload_len = l4_total - udp_hdr_len;
            if (udp_payload_len < 0) udp_payload_len = 0;

            found->byte_count += udp_payload_len;

            // 你原有的累计函数（保持调用口径不变）
            // flow_add_pkt_len(found, found->byte_count);
            flow_add_pkt_len(found, udp_payload_len);
            flow_add_pkt_time(found, t_us);

            if (found->direct == true) {
                // 反方向
                found->b_direct += 1;
                // flow_add_b_pkt_len(found, found->byte_count);
                flow_add_b_pkt_len(found, udp_payload_len);
                flow_add_pkt_bw_time(found, t_us);
            } else {
                // 正方向
                found->f_direct += 1;
                // flow_add_f_pkt_len(found, found->byte_count);
                flow_add_f_pkt_len(found, udp_payload_len);
                flow_add_pkt_fw_time(found, t_us);
            }

            if (is_last_packet) {
                process_all_remain_flow(found);
            }
        } else {
            // 超时：写出并重新按此包新建流
            cal_write_csv(found);
            HASH_DEL(flow_table, found);
            free(found);
            insert_flow_udp(header, ip_hdr, udp_hdr);
        }
    } else {
        // 新五元组：插入并做一次全表巡检
        insert_flow_udp(header, ip_hdr, udp_hdr);
        loop_process(header);
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
        //uint16_t length = (payload[4]  << 8)| payload[5];
        if (ip_version == 4){
            // expire_flows(&header->ts);
            // t = header->ts.tv_sec + header->ts.tv_usec/1e6;;
            struct ip *ip_hdr = (struct ip*)(payload);

            if (ip_hdr->ip_p == IPPROTO_TCP) {
                // 处理 TCP 包
                struct tcphdr *t = (void*)payload + ip_hdr->ip_hl*4;
                process_packet(header, ip_hdr, t, is_last);
            }
            else if (ip_hdr->ip_p == IPPROTO_UDP) {
                struct udphdr *u = (void*)payload + ip_hdr->ip_hl*4;
                process_udp_packet(header, ip_hdr, u, is_last);
                // 处理 UDP 包
                return;
            }
            else {
                // 其他协议，比如 ICMP 等
                return;
            }

        } else if (ip_version == 6) {
            // IPv6
            // parse_ip_and_transport_ipv6(payload, length);
        } else {
            //            printf("未知的 IP 版本: %d\n", ip_version);
            return;
        }
    }
}