//
// Created by sailor on 2025/8/11.
//

#ifndef CSVWRITER_H
#define CSVWRITER_H

#include <stdint.h>

void append_flow(
    const char * src_ip, uint16_t src_port,
    const char * dst_ip, uint16_t dst_port,
    double duration,                          // 流持续时间（秒）
    unsigned long long pkts,                  // 包数
    unsigned long long bytes,                 // 字节数
    double pkts_per_sec, double bytes_per_sec, // 速率
    double avg_pkt_len,                        // 包平均长度
    unsigned long long min_pkt_len,
    unsigned long long max_pkt_len,
    double pkt_len_stddev,
    unsigned long long tot_fw_pk,             // 正向包数
    unsigned long long tot_bw_pk,             // 反向包数
    double fw_pkt_l_avg,                       // 正向包平均长度
    unsigned long long fw_pkt_l_min,
    unsigned long long fw_pkt_l_max,
    double fw_pkt_l_stddev,
    double bw_pkt_l_avg,
    unsigned long long bw_pkt_l_min,
    unsigned long long bw_pkt_l_max,
    double bw_pkt_l_stddev,
    double fw_pkt_s,double bw_pkt_s,
    double fl_iat_avg,double fl_iat_std,double fl_iat_min,double fl_iat_max,
    double fw_iat_tot,double fw_iat_avg,double fw_iat_std,double fw_iat_min,double fw_iat_max,
    double bw_iat_tot,double bw_iat_avg,double bw_iat_std,double bw_iat_min,double bw_iat_max,
    double atv_avg, double atv_std, double atv_max, double atv_min,
    double idl_avg, double idl_std, double idl_max, double idl_min,
    double subfw_pk, double subfw_byt, double subfw_pk_max, double subfw_pk_min, double subfw_byt_max, double subfw_byt_min,
    double subbw_pk, double subbw_byt, double subbw_pk_max, double subbw_pk_min, double subbw_byt_max, double subbw_byt_min,
    double tl_cv, double tl_Barabasi, const char * url
);

void init_csv(const char *filename);
void close_csv(void);


#endif //CSVWRITER_H
