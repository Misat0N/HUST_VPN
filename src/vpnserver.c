#include "logging.h"
#include "protocol.h"
#include "tls.h"
#include "tun.h"
#include "util.h"

#include <arpa/inet.h>
#include <crypt.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <pthread.h>
#include <shadow.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MAX_CLIENTS 64
#define DEFAULT_PORT 4433
#define DEFAULT_MTU 1400
#define DEFAULT_VPN_SUBNET "192.168.53.0/24"
#define DEFAULT_TUN_CIDR "192.168.53.1/24"
#define DEFAULT_LISTEN_IP "0.0.0.0"
#define DEFAULT_ROUTE_NET "192.168.60.0/24"

struct server_state;

struct client_session {
    int in_use;
    int closing;
    int sock;
    SSL *ssl;
    pthread_t thread;
    pthread_mutex_t lock;
    uint32_t vaddr;
    uint32_t seq;
    time_t last_active;
    struct server_state *srv;
};

struct server_state {
    int tun_fd;
    SSL_CTX *ctx;
    uint32_t vpn_net;
    uint8_t vpn_prefix;
    uint32_t pool_start;
    uint32_t pool_end;
    uint32_t route_net;
    uint8_t route_prefix;
    int mtu;
    struct client_session clients[MAX_CLIENTS];
    pthread_mutex_t clients_lock;
    pthread_t tun_thread;
    int stop;
};

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s -l <listen_ip> -p <port> -c <cert> -k <key> -a <ca> \
"
            "          -s <vpn_subnet_cidr> -t <tun_cidr> -r <route_cidr> -m <mtu>\n",
            prog);
}

static int parse_port(const char *s) {
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (!end || *end != '\0' || v < 1 || v > 65535) {
        return -1;
    }
    return (int)v;
}

static int auth_user(const char *user, const char *pass, char *msg, size_t msg_len) {
    struct spwd *sp = getspnam(user);
    if (!sp || !sp->sp_pwdp) {
        snprintf(msg, msg_len, "user not found");
        return -1;
    }
    if (sp->sp_pwdp[0] == '!' || sp->sp_pwdp[0] == '*') {
        snprintf(msg, msg_len, "account locked");
        return -1;
    }
    char *crypt_pw = crypt(pass, sp->sp_pwdp);
    if (!crypt_pw) {
        snprintf(msg, msg_len, "crypt failed");
        return -1;
    }
    if (strcmp(crypt_pw, sp->sp_pwdp) != 0) {
        snprintf(msg, msg_len, "bad password");
        return -1;
    }
    return 0;
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

static struct client_session *alloc_session(struct server_state *s) {
    struct client_session *sess = NULL;
    pthread_mutex_lock(&s->clients_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!s->clients[i].in_use) {
            sess = &s->clients[i];
            sess->in_use = 1;
            sess->closing = 0;
            sess->sock = -1;
            sess->ssl = NULL;
            sess->vaddr = 0;
            sess->seq = 1;
            sess->last_active = time(NULL);
            sess->srv = s;
            break;
        }
    }
    pthread_mutex_unlock(&s->clients_lock);
    return sess;
}

static void close_session(struct server_state *s, struct client_session *sess) {
    sess->closing = 1;
    pthread_mutex_lock(&sess->lock);

    pthread_mutex_lock(&s->clients_lock);
    sess->in_use = 0;
    sess->vaddr = 0;
    pthread_mutex_unlock(&s->clients_lock);

    if (sess->ssl) {
        SSL_shutdown(sess->ssl);
        SSL_free(sess->ssl);
        sess->ssl = NULL;
    }
    if (sess->sock >= 0) {
        close(sess->sock);
        sess->sock = -1;
    }
    pthread_mutex_unlock(&sess->lock);
    sess->closing = 0;
}

static int allocate_ip(struct server_state *s, uint32_t *out_ip) {
    if (!out_ip) {
        return -1;
    }
    pthread_mutex_lock(&s->clients_lock);
    for (uint32_t ip = s->pool_start; ip <= s->pool_end; ip++) {
        int used = 0;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (s->clients[i].in_use && s->clients[i].vaddr == ip) {
                used = 1;
                break;
            }
        }
        if (!used) {
            *out_ip = ip;
            pthread_mutex_unlock(&s->clients_lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&s->clients_lock);
    return -1;
}

static struct client_session *find_session_by_ip(struct server_state *s, uint32_t ip) {
    struct client_session *sess = NULL;
    pthread_mutex_lock(&s->clients_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (s->clients[i].in_use && s->clients[i].vaddr == ip) {
            sess = &s->clients[i];
            break;
        }
    }
    pthread_mutex_unlock(&s->clients_lock);
    return sess;
}

static int handle_handshake(struct server_state *s, struct client_session *sess) {
    uint8_t payload[VPN_MAX_PAYLOAD];
    struct vpn_frame_hdr hdr;
    uint16_t len = 0;

    if (vpn_recv_frame(sess->ssl, &hdr, payload, sizeof(payload), &len) != 0) {
        LOG_ERR("failed to read CLIENT_HELLO");
        return -1;
    }
    if (hdr.type != FRAME_CLIENT_HELLO) {
        send_error_frame(sess->ssl, &sess->seq, VPN_ERR_BAD_STATE, "expected CLIENT_HELLO");
        return -1;
    }
    uint32_t ver = 0;
    if (tlv_get_u32(payload, len, TLV_VERSION, &ver) != 0 || ver != VPN_PROTO_VERSION) {
        send_error_frame(sess->ssl, &sess->seq, VPN_ERR_BAD_VERSION, "bad version");
        return -1;
    }

    size_t off = 0;
    tlv_put_u32(payload, sizeof(payload), &off, TLV_VERSION, VPN_PROTO_VERSION);
    tlv_put_str(payload, sizeof(payload), &off, TLV_MSG, "ok");
    if (vpn_send_frame(sess->ssl, FRAME_SERVER_HELLO, ++sess->seq, payload, (uint16_t)off) != 0) {
        return -1;
    }

    if (vpn_recv_frame(sess->ssl, &hdr, payload, sizeof(payload), &len) != 0) {
        return -1;
    }
    if (hdr.type != FRAME_AUTH_REQ) {
        send_error_frame(sess->ssl, &sess->seq, VPN_ERR_BAD_STATE, "expected AUTH_REQ");
        return -1;
    }

    char user[64];
    char pass[128];
    if (tlv_get_str(payload, len, TLV_USERNAME, user, sizeof(user)) != 0 ||
        tlv_get_str(payload, len, TLV_PASSWORD, pass, sizeof(pass)) != 0) {
        send_error_frame(sess->ssl, &sess->seq, VPN_ERR_BAD_MESSAGE, "bad auth payload");
        return -1;
    }

    char msg[128];
    if (auth_user(user, pass, msg, sizeof(msg)) != 0) {
        size_t off2 = 0;
        tlv_put_u32(payload, sizeof(payload), &off2, TLV_STATUS, 1);
        tlv_put_u32(payload, sizeof(payload), &off2, TLV_ERROR, VPN_ERR_AUTH_FAILED);
        tlv_put_str(payload, sizeof(payload), &off2, TLV_MSG, msg);
        vpn_send_frame(sess->ssl, FRAME_AUTH_RESP, ++sess->seq, payload, (uint16_t)off2);
        LOG_ERR("auth failed for user %s", user);
        return -1;
    }

    size_t off3 = 0;
    tlv_put_u32(payload, sizeof(payload), &off3, TLV_STATUS, 0);
    tlv_put_str(payload, sizeof(payload), &off3, TLV_MSG, "ok");
    if (vpn_send_frame(sess->ssl, FRAME_AUTH_RESP, ++sess->seq, payload, (uint16_t)off3) != 0) {
        return -1;
    }

    uint32_t client_ip = 0;
    if (allocate_ip(s, &client_ip) != 0) {
        send_error_frame(sess->ssl, &sess->seq, VPN_ERR_NO_RESOURCES, "no IP available");
        return -1;
    }

    size_t off4 = 0;
    tlv_put_ipv4(payload, sizeof(payload), &off4, TLV_CLIENT_IP, client_ip);
    tlv_put_ipv4(payload, sizeof(payload), &off4, TLV_VPN_NET, s->vpn_net);
    tlv_put_u32(payload, sizeof(payload), &off4, TLV_VPN_PREFIX, s->vpn_prefix);
    tlv_put_ipv4(payload, sizeof(payload), &off4, TLV_ROUTE_NET, s->route_net);
    tlv_put_u32(payload, sizeof(payload), &off4, TLV_ROUTE_PREFIX, s->route_prefix);
    tlv_put_u32(payload, sizeof(payload), &off4, TLV_MTU, (uint32_t)s->mtu);

    if (vpn_send_frame(sess->ssl, FRAME_CONFIG_PUSH, ++sess->seq, payload, (uint16_t)off4) != 0) {
        return -1;
    }

    if (vpn_recv_frame(sess->ssl, &hdr, payload, sizeof(payload), &len) != 0) {
        return -1;
    }
    if (hdr.type != FRAME_CONFIG_ACK) {
        send_error_frame(sess->ssl, &sess->seq, VPN_ERR_BAD_STATE, "expected CONFIG_ACK");
        return -1;
    }

    sess->vaddr = client_ip;
    if (vpn_send_frame(sess->ssl, FRAME_TUNNEL_START, ++sess->seq, NULL, 0) != 0) {
        return -1;
    }

    char ipbuf[32];
    ipv4_to_str(client_ip, ipbuf, sizeof(ipbuf));
    LOG("client authenticated user=%s ip=%s", user, ipbuf);
    return 0;
}

static void *client_thread(void *arg) {
    struct client_session *sess = (struct client_session *)arg;
    struct server_state *s = sess->srv;

    if (handle_handshake(s, sess) != 0) {
        close_session(s, sess);
        return NULL;
    }

    uint8_t payload[VPN_MAX_PAYLOAD];
    struct vpn_frame_hdr hdr;
    uint16_t len = 0;

    while (!s->stop) {
        if (vpn_recv_frame(sess->ssl, &hdr, payload, sizeof(payload), &len) != 0) {
            break;
        }
        sess->last_active = time(NULL);

        if (hdr.type == FRAME_DATA) {
            if (len > 0) {
                int w = write(s->tun_fd, payload, len);
                if (w != (int)len) {
                    LOG_ERR("tun write short: %d/%u", w, len);
                }
            }
        } else if (hdr.type == FRAME_KEEPALIVE) {
            pthread_mutex_lock(&sess->lock);
            if (!sess->closing && sess->ssl) {
                vpn_send_frame(sess->ssl, FRAME_KEEPALIVE, ++sess->seq, NULL, 0);
            }
            pthread_mutex_unlock(&sess->lock);
        } else if (hdr.type == FRAME_ERROR) {
            LOG_ERR("client reported error, closing session");
            break;
        } else {
            send_error_frame(sess->ssl, &sess->seq, VPN_ERR_BAD_MESSAGE, "unexpected frame");
            break;
        }
    }

    LOG("client disconnected");
    close_session(s, sess);
    return NULL;
}

static void *tun_thread(void *arg) {
    struct server_state *s = (struct server_state *)arg;
    uint8_t buf[VPN_MAX_PAYLOAD];

    while (!s->stop) {
        int n = read(s->tun_fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            LOG_ERR("tun read failed: %s", strerror(errno));
            break;
        }
        if (n == 0) {
            continue;
        }

        uint32_t dst_ip = 0;
        if (get_ipv4_dst(buf, (size_t)n, &dst_ip) != 0) {
            continue;
        }
        if (!ip_in_subnet(dst_ip, s->vpn_net, s->vpn_prefix)) {
            continue;
        }

        struct client_session *sess = find_session_by_ip(s, dst_ip);
        if (!sess) {
            continue;
        }

        pthread_mutex_lock(&sess->lock);
        if (!sess->closing && sess->ssl) {
            vpn_send_frame(sess->ssl, FRAME_DATA, ++sess->seq, buf, (uint16_t)n);
        }
        pthread_mutex_unlock(&sess->lock);
    }
    return NULL;
}

static int setup_listener(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG_ERR("socket failed: %s", strerror(errno));
        return -1;
    }
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        LOG_ERR("invalid listen ip: %s", ip);
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERR("bind failed: %s", strerror(errno));
        close(fd);
        return -1;
    }
    if (listen(fd, 16) < 0) {
        LOG_ERR("listen failed: %s", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

int main(int argc, char *argv[]) {
    const char *listen_ip = DEFAULT_LISTEN_IP;
    const char *cert = "cert/server.crt";
    const char *key = "cert/server.key";
    const char *ca = "cert/ca.crt";
    const char *vpn_subnet = DEFAULT_VPN_SUBNET;
    const char *tun_cidr = DEFAULT_TUN_CIDR;
    const char *route_cidr = DEFAULT_ROUTE_NET;
    int port = DEFAULT_PORT;
    int mtu = DEFAULT_MTU;

    int opt;
    while ((opt = getopt(argc, argv, "l:p:c:k:a:s:t:r:m:h")) != -1) {
        switch (opt) {
        case 'l':
            listen_ip = optarg;
            break;
        case 'p':
            port = parse_port(optarg);
            break;
        case 'c':
            cert = optarg;
            break;
        case 'k':
            key = optarg;
            break;
        case 'a':
            ca = optarg;
            break;
        case 's':
            vpn_subnet = optarg;
            break;
        case 't':
            tun_cidr = optarg;
            break;
        case 'r':
            route_cidr = optarg;
            break;
        case 'm':
            mtu = atoi(optarg);
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (port <= 0) {
        usage(argv[0]);
        return 1;
    }

    if (geteuid() != 0) {
        LOG_ERR("must run as root");
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);

    if (tls_init() != 0) {
        return 1;
    }

    uint32_t vpn_net = 0;
    uint8_t vpn_prefix = 0;
    if (parse_cidr(vpn_subnet, &vpn_net, &vpn_prefix) != 0) {
        LOG_ERR("invalid vpn subnet: %s", vpn_subnet);
        return 1;
    }
    uint32_t route_net = 0;
    uint8_t route_prefix = 0;
    if (parse_cidr(route_cidr, &route_net, &route_prefix) != 0) {
        LOG_ERR("invalid route cidr: %s", route_cidr);
        return 1;
    }

    int tun_fd = tun_create("tun0");
    if (tun_fd < 0) {
        return 1;
    }
    if (tun_setup("tun0", tun_cidr, mtu) != 0) {
        close(tun_fd);
        return 1;
    }

    SSL_CTX *ctx = tls_create_server_ctx(cert, key, ca);
    if (!ctx) {
        close(tun_fd);
        return 1;
    }

    int listen_fd = setup_listener(listen_ip, port);
    if (listen_fd < 0) {
        SSL_CTX_free(ctx);
        close(tun_fd);
        return 1;
    }

    struct server_state s;
    memset(&s, 0, sizeof(s));
    s.tun_fd = tun_fd;
    s.ctx = ctx;
    s.vpn_net = vpn_net;
    s.vpn_prefix = vpn_prefix;
    s.route_net = route_net;
    s.route_prefix = route_prefix;
    s.mtu = mtu;
    s.pool_start = vpn_net + 10;
    s.pool_end = vpn_net + 254;
    pthread_mutex_init(&s.clients_lock, NULL);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        pthread_mutex_init(&s.clients[i].lock, NULL);
    }

    if (pthread_create(&s.tun_thread, NULL, tun_thread, &s) == 0) {
        pthread_detach(s.tun_thread);
    }

    LOG("vpnserver listening on %s:%d", listen_ip, port);

    while (1) {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        int cfd = accept(listen_fd, (struct sockaddr *)&peer, &peer_len);
        if (cfd < 0) {
            if (errno == EINTR) {
                continue;
            }
            LOG_ERR("accept failed: %s", strerror(errno));
            break;
        }

        SSL *ssl = tls_accept(ctx, cfd);
        if (!ssl) {
            close(cfd);
            continue;
        }

        struct client_session *sess = alloc_session(&s);
        if (!sess) {
            uint32_t tmp_seq = 0;
            send_error_frame(ssl, &tmp_seq, VPN_ERR_NO_RESOURCES, "server busy");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(cfd);
            continue;
        }

        sess->sock = cfd;
        sess->ssl = ssl;
        if (pthread_create(&sess->thread, NULL, client_thread, sess) == 0) {
            pthread_detach(sess->thread);
        } else {
            LOG_ERR("pthread_create failed");
            close_session(&s, sess);
        }
    }

    close(listen_fd);
    SSL_CTX_free(ctx);
    close(tun_fd);
    return 0;
}
