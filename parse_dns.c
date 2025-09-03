//
// Created by sailor on 2025/8/28.
//
#include <stdlib.h>
#include <stdint.h>
#include "parse_dns.h"
#include "parse_tls.h"
#include <string.h>
#define QUERY_TAG 256
#include <ctype.h>
char* bytes_to_compare (const uint8_t *data, uint16_t length) {
    char *result = (char *)malloc((length + 1) * sizeof(char));  // 多分配一个字节用于存放字符串结束符'\0'
    if (result == NULL) {
        return NULL;  // 内存分配失败，返回NULL
    }
    int j = 0;  // 用于记录结果字符串的索引
    for(uint16_t i = 0; i < length; i++) {
        if(isprint(data[i])) {
            result[j++] = (char)data[i];
        } else {
            result[j++] = '.';
        }
    }
    result[j] = '\0';  // 添加字符串结束符
}

char* extract_udp_payload(const uint8_t *packet, uint32_t len){
    //    const uint8_t *udp_packet = packet + 20;
    //   struct udp_header *udph = (struct udp_header *)(packet);
    //    size_t udp_header_length = sizeof(struct udp_header);
    //    uint16_t length = udph->len;
    if (!packet || len < 8) return NULL;

    // UDP 头的 length 字段（含头 8B），与上层传入的 l4_len 取最小可信
    uint16_t udp_len = (uint16_t)((packet[4] << 8) | packet[5]);
    if (udp_len >= 8 && udp_len <= len)len = udp_len;

    const uint8_t *dns = packet + 8;
    uint32_t dns_len = len - 8;
    if (dns_len < 12) return NULL; // DNS header 最小 12B

    // DNS 头
    uint16_t flags   = (uint16_t)((dns[2] << 8) | dns[3]);
    uint16_t qdcount = (uint16_t)((dns[4] << 8) | dns[5]);
    // uint16_t ancount = (uint16_t)((dns[6] << 8) | dns[7]);
    // uint16_t nscount = (uint16_t)((dns[8] << 8) | dns[9]);
    // uint16_t arcount = (uint16_t)((dns[10] << 8) | dns[11]);

    // 只解析“查询报文”的 Question；若需要也可放开响应
    if ((flags & 0x8000) != 0) { // QR==1 为响应
        // 如果也想从响应里取 QNAME，可以不返回而继续解析
        // return NULL;
    }
    if (qdcount == 0) return NULL;

    // 解析第一个 Question 的 QNAME（label-by-label，支持压缩指针）
    size_t pos = 12;           // DNS 头之后
    char   out[256];           // 域名输出缓冲（RFC 1035 最大 255 字节）
    size_t out_len = 0;

    // 为避免指针环，限制跳转次数
    int jumped = 0;
    size_t jumps = 0;
    size_t cur = pos;

    while (1) {
        if (cur >= dns_len) return NULL;
        uint8_t len = dns[cur++];

        if (len == 0) break;                   // 终止
        if ((len & 0xC0) == 0xC0) {            // 压缩指针
            if (cur >= dns_len) return NULL;
            uint16_t ptr = (uint16_t)(((len & 0x3F) << 8) | dns[cur++]);
            if (ptr >= dns_len) return NULL;
            if (++jumps > 16) return NULL;     // 防环
            if (!jumped) { pos = cur; jumped = 1; } // 第一次跳转，记住原位置
            cur = ptr;
            continue;
        }

        if (len > 63) return NULL;             // 非法 label
        if (cur + len > dns_len) return NULL;

        if (out_len) {                         // 添加点分隔
            if (out_len + 1 >= sizeof out) return NULL;
            out[out_len++] = '.';
        }
        if (out_len + len >= sizeof out)       // 防溢出
            len = (uint8_t)(sizeof(out) - 1 - out_len);

        memcpy(out + out_len, dns + cur, len);
        out_len += len;
        cur += len;
    }

    // 跳过 QTYPE/QCLASS
    if (!jumped) pos = cur;    // 若没有压缩跳转，pos 更新到 QNAME 末尾
    if (pos + 4 > dns_len) return NULL;

    out[out_len] = '\0';
    if (out_len == 0) return NULL;

    char *res = (char*)malloc(out_len + 1);
    if (!res) return NULL;
    memcpy(res, out, out_len + 1);
    return res;
}