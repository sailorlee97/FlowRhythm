//
// Created by sailor on 2025/8/27.
//

#ifndef PARSE_TLS_H
#define PARSE_TLS_H
const char* extract_sni(const uint8_t *handshake_msg, uint32_t msg_len);
#endif //PARSE_TLS_H
