//
// Created by sailor on 2025/8/26.
//
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <pcap.h>
#include "parse_tls.h"
#include <ctype.h>

#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 1
#define HANDSHAKE 22
#define MAX_LENGTH 100  // 定义一个足够大的长度，根据实际情况调整
#define TLS_EXT_SERVER_NAME 0x0000

char* bytes_to_return (const u_char *data, uint32_t length) {
    char *result = (char *)malloc((length + 1) * sizeof(char));  // 多分配一个字节用于存放字符串结束符'\0'
    if (result == NULL) {
        return NULL;  // 内存分配失败，返回NULL
    }
    int j = 0;  // 用于记录结果字符串的索引
    for(uint32_t i = 0; i < length; i++) {
        if(isprint(data[i])) {
            result[j++] = (char)data[i];
        } else {
            result[j++] = '.';
        }
    }
    result[j] = '\0';  // 添加字符串结束符
    return result;
}

const char* extract_sni(const uint8_t *handshake_msg, uint32_t msg_len) {
    if (msg_len < 4) { // Handshake header is 4 bytes
        return NULL;
    }

    uint8_t content_type = handshake_msg[0];
    if (content_type != HANDSHAKE) { // 1 = ClientHello
        return NULL;
    }
    //    handshake_msg+3;
    //    uint32_t record_length = ntohs(payload[3] << 8) | payload[4]
    //这个长度是由handshake 协议开始算
    //    uint32_t handshake_length = ntohs(handshake_msg[3] << 8) | handshake_msg[4];
    uint32_t handshake_length =  (unsigned short)(handshake_msg[3] << 8 | handshake_msg[4]);
    //    uint16_t handshake_length =handshake_msg[3]| handshake_msg[4];
    if (handshake_length + 5 > msg_len) {
        return NULL;
    }

    const uint8_t *ptr = handshake_msg + 5; // Move past handshake header
    const uint8_t *end = handshake_msg + handshake_length + 5;

    uint8_t handshake_type = ptr[0];
    if(handshake_type != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) return NULL;

    // Skip type length version random and session id len
    if (ptr +1 + 3 + 2 + 32 > end) return NULL;
    ptr += 1 + 3 + 2 + 32;

    //    session id len
    uint32_t session_length = ptr[0];
    if (ptr + 1 + session_length > end) return NULL;
    ptr += 1 + session_length;

    //    cipher suites len
    uint32_t suites_length = (ptr[0] << 8) | ptr[1];
    //    skip cipher suites
    if (ptr + 2 + suites_length > end) return NULL;
    ptr += 2 + suites_length;

    uint32_t compression_length = ptr[0];
    //    skip compression methods
    if (ptr + 1+compression_length  > end) return NULL;
    ptr += 1 + compression_length;

    //    skip extensions len
    if (ptr + 2  > end) return NULL;
    ptr += 2;
    uint32_t server_name = (ptr[0] << 8) | ptr[1];

    if (server_name != 0) return  NULL;
    //skip type len namelistlen nametype
    if (ptr + 2 + 2 +2+1  > end) return NULL;
    ptr += 2 + 2 +2+1;
    uint32_t server_name_length = (ptr[0] << 8) | ptr[1];
    if (ptr + 2 > end) return NULL;
    ptr += 2;
    char *result = bytes_to_return(ptr,server_name_length);
    return result;
}