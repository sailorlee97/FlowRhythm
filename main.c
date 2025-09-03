#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
// #include "pflow.h"
#include "computefunction.h"
#include "csvwriter.h"

void count_pkts(u_char *user, const struct pcap_pkthdr *h, const u_char *p) {
    uint64_t *cnt = (uint64_t*)user;
    (*cnt)++;
}
int main(int argc, char *argv[]) {
    // init_csv("/Users/lizeyi/Library/CloudStorage/OneDrive-个人/Documents/work_code/AIMon/csv/http.csv");
    if (argc != 3) {
        fprintf(stderr, "function: %s <pcap> <csv>\n", argv[0]);
        return 1;
    }

    char *pcap_file = argv[1];
    char *csv_file  = argv[2];

    init_csv(csv_file); // 不再写死路径
    uint64_t total_packets = 0;
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        printf("Current Work Directory: %s\n", cwd);
    } else {
        perror("Failed to obtain the current working directory");
        return 1;
    }
    // if (argc != 2) {
    //     fprintf(stderr, "用法: %s <pcap文件>\n", argv[0]);
    //     return 1;
    // }
    //char *pcap_file = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];
    printf("The pcap file was successfully opened: %s\n", pcap_file);

    pcap_t *h1 = pcap_open_offline(pcap_file, errbuf);
    if (h1 == NULL) {
        fprintf(stderr, "The pcap file cannot be opened %s: %s\n", pcap_file, errbuf);
        return 1;
    }
    pcap_loop(h1, 0, count_pkts, (u_char*)&total_packets);
    pcap_close(h1);

    typedef struct {
        uint64_t total;  // 总包数
        uint64_t index;  // 当前已处理包数
    } pkt_ctx_t;
    pkt_ctx_t ctx = { .total = total_packets, .index = 0 };

    pcap_t *handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "The pcap file cannot be opened %s: %s\n", pcap_file, errbuf);
        return 1;
    }
    // 迭代每个数据包并调用packet_handler
    if (pcap_loop(handle,0, packet_lzy_handler, (u_char*)&ctx) < 0) {
        fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    // pcap_t *h2 = pcap_open_offline(pcap_file, errbuf);

    pcap_close(handle);
    printf("\nfinished.\n");
    close_csv();
    return 0;
}