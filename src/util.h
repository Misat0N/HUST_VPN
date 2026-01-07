#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdint.h>

int run_cmd(const char *fmt, ...);
uint32_t mask_from_prefix(uint8_t prefix);
int parse_cidr(const char *cidr, uint32_t *net_host, uint8_t *prefix);
int ipv4_from_str(const char *s, uint32_t *out_host);
void ipv4_to_str(uint32_t addr_host, char *buf, size_t len);
int ip_in_subnet(uint32_t addr_host, uint32_t net_host, uint8_t prefix);
int get_ipv4_dst(const uint8_t *pkt, size_t len, uint32_t *dst_host);
int get_ipv4_src(const uint8_t *pkt, size_t len, uint32_t *src_host);

#endif
