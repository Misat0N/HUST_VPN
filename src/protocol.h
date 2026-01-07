#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/ssl.h>

#define VPN_PROTO_VERSION 1
#define VPN_HDR_LEN 8
#define VPN_MAX_PAYLOAD 4096

enum vpn_frame_type {
    FRAME_CLIENT_HELLO = 1,
    FRAME_SERVER_HELLO = 2,
    FRAME_AUTH_REQ = 3,
    FRAME_AUTH_RESP = 4,
    FRAME_CONFIG_PUSH = 5,
    FRAME_CONFIG_ACK = 6,
    FRAME_TUNNEL_START = 7,
    FRAME_DATA = 8,
    FRAME_KEEPALIVE = 9,
    FRAME_ERROR = 10
};

enum vpn_error_code {
    VPN_ERR_NONE = 0,
    VPN_ERR_BAD_VERSION = 1,
    VPN_ERR_BAD_STATE = 2,
    VPN_ERR_AUTH_FAILED = 3,
    VPN_ERR_NO_RESOURCES = 4,
    VPN_ERR_INTERNAL = 5,
    VPN_ERR_BAD_MESSAGE = 6
};

enum tlv_type {
    TLV_VERSION = 1,
    TLV_CAPS = 2,
    TLV_USERNAME = 3,
    TLV_PASSWORD = 4,
    TLV_STATUS = 5,
    TLV_ERROR = 6,
    TLV_MSG = 7,
    TLV_CLIENT_IP = 8,
    TLV_VPN_NET = 9,
    TLV_VPN_PREFIX = 10,
    TLV_ROUTE_NET = 11,
    TLV_ROUTE_PREFIX = 12,
    TLV_MTU = 13
};

struct vpn_frame_hdr {
    uint8_t version;
    uint8_t type;
    uint16_t length;
    uint32_t seq;
};

int vpn_send_frame(SSL *ssl, uint8_t type, uint32_t seq, const uint8_t *payload, uint16_t len);
int vpn_recv_frame(SSL *ssl, struct vpn_frame_hdr *hdr, uint8_t *payload, size_t payload_len, uint16_t *out_len);

int tlv_put_bytes(uint8_t *buf, size_t buf_len, size_t *off, uint8_t type, const uint8_t *data, uint16_t len);
int tlv_put_u32(uint8_t *buf, size_t buf_len, size_t *off, uint8_t type, uint32_t value);
int tlv_put_str(uint8_t *buf, size_t buf_len, size_t *off, uint8_t type, const char *str);
int tlv_put_ipv4(uint8_t *buf, size_t buf_len, size_t *off, uint8_t type, uint32_t ip_host);

int tlv_get_next(const uint8_t *buf, size_t buf_len, size_t *off, uint8_t *type, const uint8_t **val, uint16_t *len);
int tlv_get_u32(const uint8_t *buf, size_t buf_len, uint8_t type, uint32_t *out);
int tlv_get_str(const uint8_t *buf, size_t buf_len, uint8_t type, char *out, size_t out_len);
int tlv_get_ipv4(const uint8_t *buf, size_t buf_len, uint8_t type, uint32_t *ip_host);

#endif
