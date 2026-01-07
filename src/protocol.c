#include "protocol.h"
#include "logging.h"
#include "tls.h"

#include <arpa/inet.h>
#include <string.h>

static void build_header(uint8_t *hdr, uint8_t type, uint16_t len, uint32_t seq) {
    uint16_t nlen = htons(len);
    uint32_t nseq = htonl(seq);
    hdr[0] = VPN_PROTO_VERSION;
    hdr[1] = type;
    memcpy(hdr + 2, &nlen, sizeof(nlen));
    memcpy(hdr + 4, &nseq, sizeof(nseq));
}

int vpn_send_frame(SSL *ssl, uint8_t type, uint32_t seq, const uint8_t *payload, uint16_t len) {
    uint8_t hdr[VPN_HDR_LEN];
    build_header(hdr, type, len, seq);

    if (ssl_write_all(ssl, hdr, sizeof(hdr)) != 0) {
        return -1;
    }
    if (len > 0 && payload) {
        if (ssl_write_all(ssl, payload, len) != 0) {
            return -1;
        }
    }
    return 0;
}

int vpn_recv_frame(SSL *ssl, struct vpn_frame_hdr *hdr, uint8_t *payload, size_t payload_len, uint16_t *out_len) {
    uint8_t raw_hdr[VPN_HDR_LEN];
    if (ssl_read_all(ssl, raw_hdr, sizeof(raw_hdr)) != 0) {
        return -1;
    }
    hdr->version = raw_hdr[0];
    hdr->type = raw_hdr[1];
    uint16_t nlen;
    uint32_t nseq;
    memcpy(&nlen, raw_hdr + 2, sizeof(nlen));
    memcpy(&nseq, raw_hdr + 4, sizeof(nseq));
    hdr->length = ntohs(nlen);
    hdr->seq = ntohl(nseq);

    if (hdr->version != VPN_PROTO_VERSION) {
        LOG_ERR("protocol version mismatch: %u", hdr->version);
        return -1;
    }
    if (hdr->length > payload_len) {
        LOG_ERR("payload too large: %u", hdr->length);
        return -1;
    }
    if (hdr->length > 0) {
        if (ssl_read_all(ssl, payload, hdr->length) != 0) {
            return -1;
        }
    }
    if (out_len) {
        *out_len = hdr->length;
    }
    return 0;
}

int tlv_put_bytes(uint8_t *buf, size_t buf_len, size_t *off, uint8_t type, const uint8_t *data, uint16_t len) {
    if (!buf || !off || !data) {
        return -1;
    }
    size_t needed = 1 + 2 + len;
    if (*off + needed > buf_len) {
        return -1;
    }
    buf[*off] = type;
    uint16_t nlen = htons(len);
    memcpy(buf + *off + 1, &nlen, sizeof(nlen));
    memcpy(buf + *off + 3, data, len);
    *off += needed;
    return 0;
}

int tlv_put_u32(uint8_t *buf, size_t buf_len, size_t *off, uint8_t type, uint32_t value) {
    uint32_t nval = htonl(value);
    return tlv_put_bytes(buf, buf_len, off, type, (const uint8_t *)&nval, sizeof(nval));
}

int tlv_put_str(uint8_t *buf, size_t buf_len, size_t *off, uint8_t type, const char *str) {
    if (!str) {
        return -1;
    }
    size_t len = strlen(str);
    if (len > 0xFFFF) {
        return -1;
    }
    return tlv_put_bytes(buf, buf_len, off, type, (const uint8_t *)str, (uint16_t)len);
}

int tlv_put_ipv4(uint8_t *buf, size_t buf_len, size_t *off, uint8_t type, uint32_t ip_host) {
    uint32_t naddr = htonl(ip_host);
    return tlv_put_bytes(buf, buf_len, off, type, (const uint8_t *)&naddr, sizeof(naddr));
}

int tlv_get_next(const uint8_t *buf, size_t buf_len, size_t *off, uint8_t *type, const uint8_t **val, uint16_t *len) {
    if (!buf || !off || !type || !val || !len) {
        return -1;
    }
    if (*off >= buf_len) {
        return 0;
    }
    if (*off + 3 > buf_len) {
        return -1;
    }
    *type = buf[*off];
    uint16_t nlen;
    memcpy(&nlen, buf + *off + 1, sizeof(nlen));
    *len = ntohs(nlen);
    if (*off + 3 + *len > buf_len) {
        return -1;
    }
    *val = buf + *off + 3;
    *off += 3 + *len;
    return 1;
}

int tlv_get_u32(const uint8_t *buf, size_t buf_len, uint8_t type, uint32_t *out) {
    size_t off = 0;
    uint8_t t;
    const uint8_t *val;
    uint16_t len;
    while (1) {
        int rc = tlv_get_next(buf, buf_len, &off, &t, &val, &len);
        if (rc <= 0) {
            return -1;
        }
        if (t == type) {
            if (len != sizeof(uint32_t)) {
                return -1;
            }
            uint32_t nval;
            memcpy(&nval, val, sizeof(nval));
            *out = ntohl(nval);
            return 0;
        }
    }
}

int tlv_get_str(const uint8_t *buf, size_t buf_len, uint8_t type, char *out, size_t out_len) {
    if (!out || out_len == 0) {
        return -1;
    }
    size_t off = 0;
    uint8_t t;
    const uint8_t *val;
    uint16_t len;
    while (1) {
        int rc = tlv_get_next(buf, buf_len, &off, &t, &val, &len);
        if (rc <= 0) {
            return -1;
        }
        if (t == type) {
            if ((size_t)len + 1 > out_len) {
                return -1;
            }
            memcpy(out, val, len);
            out[len] = '\0';
            return 0;
        }
    }
}

int tlv_get_ipv4(const uint8_t *buf, size_t buf_len, uint8_t type, uint32_t *ip_host) {
    if (!ip_host) {
        return -1;
    }
    size_t off = 0;
    uint8_t t;
    const uint8_t *val;
    uint16_t len;
    while (1) {
        int rc = tlv_get_next(buf, buf_len, &off, &t, &val, &len);
        if (rc <= 0) {
            return -1;
        }
        if (t == type) {
            if (len != sizeof(uint32_t)) {
                return -1;
            }
            uint32_t naddr;
            memcpy(&naddr, val, sizeof(naddr));
            *ip_host = ntohl(naddr);
            return 0;
        }
    }
}
