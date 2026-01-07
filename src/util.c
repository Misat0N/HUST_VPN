#include "util.h"
#include "logging.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

int run_cmd(const char *fmt, ...) {
    char cmd[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, ap);
    va_end(ap);

    LOG("cmd: %s", cmd);
    int rc = system(cmd);
    if (rc == -1) {
        LOG_ERR("system failed: %s", strerror(errno));
        return -1;
    }
    if (WIFEXITED(rc) && WEXITSTATUS(rc) == 0) {
        return 0;
    }
    LOG_ERR("command failed with rc=%d", rc);
    return -1;
}

uint32_t mask_from_prefix(uint8_t prefix) {
    if (prefix == 0) {
        return 0;
    }
    if (prefix >= 32) {
        return 0xFFFFFFFFu;
    }
    return 0xFFFFFFFFu << (32 - prefix);
}

int parse_cidr(const char *cidr, uint32_t *net_host, uint8_t *prefix) {
    if (!cidr || !net_host || !prefix) {
        return -1;
    }
    const char *slash = strchr(cidr, '/');
    if (!slash) {
        return -1;
    }
    char ip[64];
    size_t len = (size_t)(slash - cidr);
    if (len == 0 || len >= sizeof(ip)) {
        return -1;
    }
    memcpy(ip, cidr, len);
    ip[len] = '\0';

    char *end = NULL;
    long p = strtol(slash + 1, &end, 10);
    if (!end || *end != '\0' || p < 0 || p > 32) {
        return -1;
    }

    uint32_t addr;
    if (ipv4_from_str(ip, &addr) != 0) {
        return -1;
    }
    uint32_t mask = mask_from_prefix((uint8_t)p);
    *net_host = addr & mask;
    *prefix = (uint8_t)p;
    return 0;
}

int ipv4_from_str(const char *s, uint32_t *out_host) {
    struct in_addr addr;
    if (!s || !out_host) {
        return -1;
    }
    if (inet_pton(AF_INET, s, &addr) != 1) {
        return -1;
    }
    *out_host = ntohl(addr.s_addr);
    return 0;
}

void ipv4_to_str(uint32_t addr_host, char *buf, size_t len) {
    struct in_addr addr;
    addr.s_addr = htonl(addr_host);
    inet_ntop(AF_INET, &addr, buf, len);
}

int ip_in_subnet(uint32_t addr_host, uint32_t net_host, uint8_t prefix) {
    uint32_t mask = mask_from_prefix(prefix);
    return (addr_host & mask) == (net_host & mask);
}

int get_ipv4_dst(const uint8_t *pkt, size_t len, uint32_t *dst_host) {
    if (!pkt || len < 20 || !dst_host) {
        return -1;
    }
    uint8_t ver = pkt[0] >> 4;
    uint8_t ihl = pkt[0] & 0x0F;
    if (ver != 4 || ihl < 5) {
        return -1;
    }
    size_t hdr_len = (size_t)ihl * 4;
    if (len < hdr_len) {
        return -1;
    }
    uint32_t dst_nbo;
    memcpy(&dst_nbo, pkt + 16, sizeof(dst_nbo));
    *dst_host = ntohl(dst_nbo);
    return 0;
}

int get_ipv4_src(const uint8_t *pkt, size_t len, uint32_t *src_host) {
    if (!pkt || len < 20 || !src_host) {
        return -1;
    }
    uint8_t ver = pkt[0] >> 4;
    uint8_t ihl = pkt[0] & 0x0F;
    if (ver != 4 || ihl < 5) {
        return -1;
    }
    size_t hdr_len = (size_t)ihl * 4;
    if (len < hdr_len) {
        return -1;
    }
    uint32_t src_nbo;
    memcpy(&src_nbo, pkt + 12, sizeof(src_nbo));
    *src_host = ntohl(src_nbo);
    return 0;
}
