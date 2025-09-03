//
// Created by sailor on 2025/9/3.
//
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "parse_http.h"

static int find_crlfcrlf(const uint8_t *p, int len) {
    for (int i = 0; i + 3 < len; ++i) {
        if (p[i] == '\r' && p[i+1] == '\n' && p[i+2] == '\r' && p[i+3] == '\n')
            return i + 4;
    }
    return -1; // 未找到完整头部结束
}

bool looks_like_http_req(const uint8_t *p, int len) {
    // 简单判断：以常见方法名开头
    const char *methods[] = {"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT "};
    for (size_t i = 0; i < sizeof(methods)/sizeof(methods[0]); ++i) {
        size_t mlen = strlen(methods[i]);
        if (len >= (int)mlen && strncasecmp((const char*)p, methods[i], mlen) == 0)
            return true;
    }
    return false;
}

static char* trim_copy(const char *beg, const char *end) {
    while (beg < end && (*beg == ' ' || *beg == '\t')) beg++;
    while (end > beg && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n')) end--;
    size_t n = (size_t)(end - beg);
    char *out = (char*)malloc(n + 1);
    if (!out) return NULL;
    memcpy(out, beg, n);
    out[n] = '\0';
    return out;
}

char* extract_http_host(const uint8_t *p, int len) {
    // 只在首个请求头部区域里搜 Host
    int hdr_end = find_crlfcrlf(p, len);
    if (hdr_end < 0) hdr_end = len; // 头可能不完整，尽最大可能搜

    const uint8_t *q = p;
    const uint8_t *qend = p + hdr_end;
    const char key[] = "host:";

    while (q < qend) {
        // 找到每一行的起止
        const uint8_t *line = q;
        const uint8_t *eol = memchr(line, '\n', (size_t)(qend - line));
        if (!eol) eol = qend;
        // 对比行首是否是 "Host:"（大小写不敏感，允许前面有少量空白）
        const uint8_t *s = line;
        while (s < eol && (*s == ' ' || *s == '\t' || *s == '\r')) s++;
        size_t remain = (size_t)(eol - s);
        if (remain >= sizeof(key)-1 && strncasecmp((const char*)s, key, sizeof(key)-1) == 0) {
            // 拿到冒号后的值
            const char *val_beg = (const char*)s + (sizeof(key)-1);
            while (val_beg < (const char*)eol && (*val_beg == ' ' || *val_beg == '\t')) val_beg++;
            const char *val_end = (const char*)eol;

            // 复制并修剪
            char *host = trim_copy(val_beg, val_end);
            if (!host) return NULL;

            // 去掉端口（例如 host: example.com:8080），但保留 [IPv6]:port 形式
            if (host[0] != '[') {
                char *colon = strrchr(host, ':');
                if (colon) {
                    // 仅当冒号后全是数字才视作端口
                    bool alldig = true;
                    for (char *t = colon + 1; *t; ++t) if (!isdigit((unsigned char)*t)) { alldig = false; break; }
                    if (alldig) *colon = '\0';
                }
            }
            return host;
        }
        q = eol + (eol < qend ? 1 : 0);
    }
    return NULL;
}