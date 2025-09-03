//
// Created by sailor on 2025/9/3.
//

#ifndef PARSE_HTTP_H
#define PARSE_HTTP_H
#include <stdint.h>
#include <stdbool.h>

bool looks_like_http_req(const uint8_t *p, int len);
char* extract_http_host(const uint8_t *p, int len);
#endif //PARSE_HTTP_H
