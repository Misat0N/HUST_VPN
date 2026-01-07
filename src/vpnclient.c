#include "logging.h"
#include "protocol.h"
#include "tls.h"
#include "tun.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define DEFAULT_PORT 4433
#define DEFAULT_MTU 1400

struct vpn_config {
    uint32_t client_ip;
    uint32_t vpn_net;
    uint8_t vpn_prefix;
    uint32_t route_net;
    uint8_t route_prefix;
    uint32_t mtu;
};

static volatile sig_atomic_t g_stop = 0;
static int g_tun_fd = -1;
static char g_route_cidr[64];
static int g_route_set = 0;

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s -s <server> -p <port> -a <ca> -u <user> -w <pass>
", prog);
}

static void handle_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static int parse_port(const char *s) {
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (!end || *end != '\0' || v < 1 || v > 65535) {
        return -1;
    }
    return (int)v;
}

static int send_error_frame(SSL *ssl, uint32_t *seq, uint32_t err, const char *msg) {
    uint8_t payload[256];
    size_t off = 0;
    if (tlv_put_u32(payload, sizeof(payload), &off, TLV_ERROR, err) != 0) {
        return -1;
    }
    if (msg) {
        if (tlv_put_str(payload, sizeof(payload), &off, TLV_MSG, msg) != 0) {
            return -1;
        }
    }
    return vpn_send_frame(ssl, FRAME_ERROR, ++(*seq), payload, (uint16_t)off);
}

static int connect_tcp(const char *host, int port) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *rp = NULL;
    char portstr[16];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(portstr, sizeof(portstr), "%d", port);

    int rc = getaddrinfo(host, portstr, &hints, &res);
    if (rc != 0) {
        LOG_ERR("getaddrinfo failed: %s", gai_strerror(rc));
        return -1;
    }

    int fd = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static void cleanup(void) {
    if (g_route_set) {
        run_cmd("ip route del %s", g_route_cidr);
    }
    if (g_tun_fd >= 0) {
        close(g_tun_fd);
        g_tun_fd = -1;
        tun_delete("tun0");
    }
}

static int client_handshake(SSL *ssl, const char *user, const char *pass,
                            struct vpn_config *cfg, uint32_t *seq) {
    uint8_t payload[VPN_MAX_PAYLOAD];
    struct vpn_frame_hdr hdr;
    uint16_t len = 0;
    size_t off = 0;

    if (tlv_put_u32(payload, sizeof(payload), &off, TLV_VERSION, VPN_PROTO_VERSION) != 0 ||
        tlv_put_str(payload, sizeof(payload), &off, TLV_CAPS, "tun,tcp,tls") != 0) {
        return -1;
    }
    if (vpn_send_frame(ssl, FRAME_CLIENT_HELLO, ++(*seq), payload, (uint16_t)off) != 0) {
        return -1;
    }

    if (vpn_recv_frame(ssl, &hdr, payload, sizeof(payload), &len) != 0) {
        return -1;
    }
    if (hdr.type != FRAME_SERVER_HELLO) {
        send_error_frame(ssl, seq, VPN_ERR_BAD_STATE, "expected SERVER_HELLO");
        return -1;
    }
    uint32_t ver = 0;
    if (tlv_get_u32(payload, len, TLV_VERSION, &ver) != 0 || ver != VPN_PROTO_VERSION) {
        send_error_frame(ssl, seq, VPN_ERR_BAD_VERSION, "bad version");
        return -1;
    }

    off = 0;
    if (tlv_put_str(payload, sizeof(payload), &off, TLV_USERNAME, user) != 0 ||
        tlv_put_str(payload, sizeof(payload), &off, TLV_PASSWORD, pass) != 0) {
        return -1;
    }
    if (vpn_send_frame(ssl, FRAME_AUTH_REQ, ++(*seq), payload, (uint16_t)off) != 0) {
        return -1;
    }

    if (vpn_recv_frame(ssl, &hdr, payload, sizeof(payload), &len) != 0) {
        return -1;
    }
    if (hdr.type != FRAME_AUTH_RESP) {
        send_error_frame(ssl, seq, VPN_ERR_BAD_STATE, "expected AUTH_RESP");
        return -1;
    }
    uint32_t status = 0;
    if (tlv_get_u32(payload, len, TLV_STATUS, &status) != 0 || status != 0) {
        char msg[128] = "auth failed";
        tlv_get_str(payload, len, TLV_MSG, msg, sizeof(msg));
        LOG_ERR("authentication failed: %s", msg);
        return -1;
    }

    if (vpn_recv_frame(ssl, &hdr, payload, sizeof(payload), &len) != 0) {
        return -1;
    }
    if (hdr.type != FRAME_CONFIG_PUSH) {
        send_error_frame(ssl, seq, VPN_ERR_BAD_STATE, "expected CONFIG_PUSH");
        return -1;
    }

    uint32_t vpn_prefix = 0;
    uint32_t route_prefix = 0;
    if (tlv_get_ipv4(payload, len, TLV_CLIENT_IP, &cfg->client_ip) != 0 ||
        tlv_get_ipv4(payload, len, TLV_VPN_NET, &cfg->vpn_net) != 0 ||
        tlv_get_u32(payload, len, TLV_VPN_PREFIX, &vpn_prefix) != 0 ||
        tlv_get_ipv4(payload, len, TLV_ROUTE_NET, &cfg->route_net) != 0 ||
        tlv_get_u32(payload, len, TLV_ROUTE_PREFIX, &route_prefix) != 0) {
        send_error_frame(ssl, seq, VPN_ERR_BAD_MESSAGE, "bad CONFIG_PUSH");
        return -1;
    }
    if (vpn_prefix > 32 || route_prefix > 32) {
        LOG_ERR("invalid prefix in CONFIG_PUSH");
        return -1;
    }
    cfg->vpn_prefix = (uint8_t)vpn_prefix;
    cfg->route_prefix = (uint8_t)route_prefix;
    uint32_t mtu = 0;
    if (tlv_get_u32(payload, len, TLV_MTU, &mtu) != 0) {
        mtu = DEFAULT_MTU;
    }
    cfg->mtu = mtu;

    g_tun_fd = tun_create("tun0");
    if (g_tun_fd < 0) {
        return -1;
    }
    char ipbuf[32];
    char cidr[64];
    ipv4_to_str(cfg->client_ip, ipbuf, sizeof(ipbuf));
    snprintf(cidr, sizeof(cidr), "%s/%u", ipbuf, cfg->vpn_prefix);
    if (tun_setup("tun0", cidr, (int)cfg->mtu) != 0) {
        return -1;
    }

    char route_net[32];
    ipv4_to_str(cfg->route_net, route_net, sizeof(route_net));
    snprintf(g_route_cidr, sizeof(g_route_cidr), "%s/%u", route_net, cfg->route_prefix);
    if (run_cmd("ip route replace %s dev tun0", g_route_cidr) != 0) {
        return -1;
    }
    g_route_set = 1;

    if (vpn_send_frame(ssl, FRAME_CONFIG_ACK, ++(*seq), NULL, 0) != 0) {
        return -1;
    }

    if (vpn_recv_frame(ssl, &hdr, payload, sizeof(payload), &len) != 0) {
        return -1;
    }
    if (hdr.type != FRAME_TUNNEL_START) {
        send_error_frame(ssl, seq, VPN_ERR_BAD_STATE, "expected TUNNEL_START");
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    const char *server = NULL;
    const char *ca = NULL;
    const char *user = NULL;
    const char *pass = NULL;
    int port = DEFAULT_PORT;

    int opt;
    while ((opt = getopt(argc, argv, "s:p:a:u:w:h")) != -1) {
        switch (opt) {
        case 's':
            server = optarg;
            break;
        case 'p':
            port = parse_port(optarg);
            break;
        case 'a':
            ca = optarg;
            break;
        case 'u':
            user = optarg;
            break;
        case 'w':
            pass = optarg;
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (!server || !ca || port <= 0) {
        usage(argv[0]);
        return 1;
    }

    if (!user) {
        user = getenv("VPN_USER");
    }
    if (!pass) {
        pass = getenv("VPN_PASS");
    }
    if (!user || !pass) {
        LOG_ERR("username/password missing (use -u/-w or VPN_USER/VPN_PASS)");
        return 1;
    }

    if (geteuid() != 0) {
        LOG_ERR("must run as root");
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    atexit(cleanup);

    if (tls_init() != 0) {
        return 1;
    }

    int sock = connect_tcp(server, port);
    if (sock < 0) {
        LOG_ERR("connect failed");
        return 1;
    }

    SSL_CTX *ctx = tls_create_client_ctx(ca);
    if (!ctx) {
        close(sock);
        return 1;
    }

    SSL *ssl = tls_connect(ctx, sock, server);
    if (!ssl) {
        SSL_CTX_free(ctx);
        close(sock);
        return 1;
    }

    struct vpn_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    uint32_t seq = 1;
    if (client_handshake(ssl, user, pass, &cfg, &seq) != 0) {
        LOG_ERR("handshake failed");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
        return 1;
    }

    char ipbuf[32];
    ipv4_to_str(cfg.client_ip, ipbuf, sizeof(ipbuf));
    LOG("tunnel up, client ip %s", ipbuf);

    int ssl_fd = SSL_get_fd(ssl);
    while (!g_stop) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(g_tun_fd, &rfds);
        FD_SET(ssl_fd, &rfds);
        int maxfd = (g_tun_fd > ssl_fd) ? g_tun_fd : ssl_fd;

        struct timeval tv;
        tv.tv_sec = 15;
        tv.tv_usec = 0;

        int pending = SSL_pending(ssl) > 0;
        int ready = pending ? 1 : select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            LOG_ERR("select failed: %s", strerror(errno));
            break;
        }
        if (!pending && ready == 0) {
            vpn_send_frame(ssl, FRAME_KEEPALIVE, ++seq, NULL, 0);
            continue;
        }

        if (!pending && FD_ISSET(g_tun_fd, &rfds)) {
            uint8_t buf[VPN_MAX_PAYLOAD];
            int n = read(g_tun_fd, buf, sizeof(buf));
            if (n > 0) {
                vpn_send_frame(ssl, FRAME_DATA, ++seq, buf, (uint16_t)n);
            }
        }

        if (pending || FD_ISSET(ssl_fd, &rfds)) {
            uint8_t payload[VPN_MAX_PAYLOAD];
            struct vpn_frame_hdr hdr;
            uint16_t len = 0;
            if (vpn_recv_frame(ssl, &hdr, payload, sizeof(payload), &len) != 0) {
                LOG_ERR("server closed connection");
                break;
            }
            if (hdr.type == FRAME_DATA) {
                if (len > 0) {
                    int w = write(g_tun_fd, payload, len);
                    if (w != (int)len) {
                        LOG_ERR("tun write short: %d/%u", w, len);
                    }
                }
            } else if (hdr.type == FRAME_KEEPALIVE) {
                vpn_send_frame(ssl, FRAME_KEEPALIVE, ++seq, NULL, 0);
            } else if (hdr.type == FRAME_ERROR) {
                LOG_ERR("server error, closing");
                break;
            } else {
                send_error_frame(ssl, &seq, VPN_ERR_BAD_MESSAGE, "unexpected frame");
                break;
            }
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
    return 0;
}
