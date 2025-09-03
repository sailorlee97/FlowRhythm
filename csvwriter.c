//
// Created by sailor on 2025/8/11.
//
#include "csvwriter.h"
#include <stdlib.h>
#include <stdio.h>
FILE *fp = NULL;
#define SAFESTR(p) ((p) ? (p) : "null")
void init_csv(const char *filename) {
    fp = fopen(filename, "w");
    if (!fp) { perror("fopen"); exit(EXIT_FAILURE); }
    fprintf(fp, "Expired Flow,"
                "duration,tl_pkts,tl_bytes,pkts/s,bytes/s,"
                "avg,min,max,stddev,"
                "tot_fw_pk,tot_bw_pk,"
                "fw_pkt_l_avg,fw_pkt_l_min,fw_pkt_l_max,fw_pkt_l_std,"
                "bw_pkt_l_avg,bw_pkt_l_min,bw_pkt_l_max,bw_pkt_l_stddev,"
                "fw_pkt_s,bw_pkt_s,fl_iat_avg,fl_iat_std,fl_iat_min,fl_iat_max,"
                "fw_iat_tot,fw_iat_avg,fw_iat_std,fw_iat_min,fw_iat_max,"
                "bw_iat_tot,bw_iat_avg,bw_iat_std,bw_iat_min,bw_iat_max,"
                "atv_avg,atv_std,atv_max,atv_min,"
                "idl_avg,idl_std,idl_max,idl_min,"
                "subfw_pk,subfw_byt,subfw_pk_max,subfw_pk_min,subfw_byt_max,subfw_byt_min,"
                "subbw_pk,subbw_byt,subbw_pk_max,subbw_pk_min,subbw_byt_max,subbw_byt_min,"
                "tl_cv,tl_Barabasi,dns\n");
    fflush(fp);
}

void append_flow(
    const char *src_ip, uint16_t src_port,
    const char *dst_ip, uint16_t dst_port,
    double duration,
    unsigned long long pkts,
    unsigned long long bytes,
    double pkts_per_sec, double bytes_per_sec,
    double avg_pkt_len,
    unsigned long long min_pkt_len,
    unsigned long long max_pkt_len,
    double pkt_len_stddev,
    unsigned long long tot_fw_pk,
    unsigned long long tot_bw_pk,
    double fw_pkt_l_avg,
    unsigned long long fw_pkt_l_min,
    unsigned long long fw_pkt_l_max,
    double fw_pkt_l_stddev,
    double bw_pkt_l_avg,
    unsigned long long bw_pkt_l_min,
    unsigned long long bw_pkt_l_max,
    double bw_pkt_l_stddev,
    double fw_pkt_s,
    double bw_pkt_s,
    double fl_iat_avg,
    double fl_iat_std,
    double fl_iat_min,
    double fl_iat_max,
    double fw_iat_tot,
    double fw_iat_avg,
    double fw_iat_std,
    double fw_iat_min,
    double fw_iat_max,
    double bw_iat_tot,
    double bw_iat_avg,
    double bw_iat_std,
    double bw_iat_min,
    double bw_iat_max,
    double atv_avg, double atv_std, double atv_max, double atv_min,
    double idl_avg, double idl_std, double idl_max, double idl_min,
    double subfw_pk, double subfw_byt, double subfw_pk_max, double subfw_pk_min, double subfw_byt_max, double subfw_byt_min,
    double subbw_pk, double subbw_byt, double subbw_pk_max, double subbw_pk_min, double subbw_byt_max, double subbw_byt_min,
    double tl_cv, double tl_Barabasi, const char *url)
{
    fprintf(fp,
        "%s:%u→%s:%u,%.6f,%llu,%llu,%.2f,%.2f,"
        "%.2f,%llu,%llu,%.2f,%llu,%llu,%.2f, %llu, %llu,  %.2f, %.2f, %llu, %llu, %.2f,%.2f, %.2f ,  %.2f,%.2f, %.2f, %.2f,  %.2f,%.2f, %.2f, %.2f,  %.2f, %.2f,%.2f, %.2f, %.2f,  %.2f,  %.2f, %.2f,%.2f, %.2f,  %.2f, %.2f,%.2f, %.2f "
        ",%.2f, %.2f,  %.2f, %.2f,%.2f, %.2f,%.2f, %.2f,  %.2f, %.2f,%.2f, %.2f,  %.2f, %.2f,%s\n",
        src_ip, src_port, dst_ip, dst_port,
        duration, pkts, bytes,
        pkts_per_sec, bytes_per_sec,
        avg_pkt_len, min_pkt_len, max_pkt_len, pkt_len_stddev,
        tot_fw_pk, tot_bw_pk,
        fw_pkt_l_avg, fw_pkt_l_min, fw_pkt_l_max, fw_pkt_l_stddev,bw_pkt_l_avg, bw_pkt_l_min, bw_pkt_l_max, bw_pkt_l_stddev,fw_pkt_s,bw_pkt_s,
        fl_iat_avg, fl_iat_std, fl_iat_min,fl_iat_max,
        fw_iat_tot, fw_iat_avg, fw_iat_std, fw_iat_min,fw_iat_max,
        bw_iat_tot, bw_iat_avg, bw_iat_std, bw_iat_min, bw_iat_max,
        atv_avg, atv_std, atv_max, atv_min,
        idl_avg, idl_std, idl_max, idl_min,
        subfw_pk,  subfw_byt, subfw_pk_max, subfw_pk_min, subfw_byt_max, subfw_byt_min,
        subbw_pk,  subbw_byt, subbw_pk_max, subbw_pk_min, subbw_byt_max, subbw_byt_min,
        tl_cv, tl_Barabasi,url
    );
    fflush(fp);
}
void close_csv(void) {
    if (fp) fclose(fp);
}