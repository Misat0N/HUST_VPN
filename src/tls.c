#include "tls.h"
#include "logging.h"

#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <string.h>

static const SSL_METHOD *get_server_method(void) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    return TLS_server_method();
#else
    return SSLv23_server_method();
#endif
}

static const SSL_METHOD *get_client_method(void) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    return TLS_client_method();
#else
    return SSLv23_client_method();
#endif
}

static void set_min_tls12(SSL_CTX *ctx) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
#else
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                               SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
#endif
}

static int verify_hostname(SSL *ssl, const char *servername) {
    if (!servername || servername[0] == '\0') {
        return 0;
    }
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        return -1;
    }
    int ok = X509_check_host(cert, servername, 0, 0, NULL);
    X509_free(cert);
    return (ok == 1) ? 0 : -1;
#else
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        return -1;
    }
    char cn[256];
    int rc = X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, cn, sizeof(cn));
    X509_free(cert);
    if (rc < 0) {
        return -1;
    }
    cn[sizeof(cn) - 1] = '\0';
    return (strcmp(cn, servername) == 0) ? 0 : -1;
#endif
}

int tls_init(void) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    if (OPENSSL_init_ssl(0, NULL) != 1) {
        LOG_ERR("OpenSSL init failed");
        return -1;
    }
#else
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#endif
    return 0;
}

void tls_cleanup(void) {
}

void tls_log_errors(const char *msg) {
    if (msg) {
        LOG_ERR("%s", msg);
    }
    ERR_print_errors_fp(stderr);
}

int ssl_read_all(SSL *ssl, void *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        int ret = SSL_read(ssl, (char *)buf + off, (int)(len - off));
        if (ret > 0) {
            off += (size_t)ret;
            continue;
        }
        int err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            continue;
        }
        return -1;
    }
    return 0;
}

int ssl_write_all(SSL *ssl, const void *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        int ret = SSL_write(ssl, (const char *)buf + off, (int)(len - off));
        if (ret > 0) {
            off += (size_t)ret;
            continue;
        }
        int err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            continue;
        }
        return -1;
    }
    return 0;
}

SSL_CTX *tls_create_server_ctx(const char *cert, const char *key, const char *ca) {
    SSL_CTX *ctx = SSL_CTX_new(get_server_method());
    if (!ctx) {
        tls_log_errors("SSL_CTX_new failed");
        return NULL;
    }
    set_min_tls12(ctx);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);

    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) != 1) {
        tls_log_errors("loading server cert failed");
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
        tls_log_errors("loading server key failed");
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        tls_log_errors("private key check failed");
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (ca && SSL_CTX_load_verify_locations(ctx, ca, NULL) != 1) {
        tls_log_errors("loading CA failed");
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    return ctx;
}

SSL_CTX *tls_create_client_ctx(const char *ca) {
    SSL_CTX *ctx = SSL_CTX_new(get_client_method());
    if (!ctx) {
        tls_log_errors("SSL_CTX_new failed");
        return NULL;
    }
    set_min_tls12(ctx);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    if (!ca || SSL_CTX_load_verify_locations(ctx, ca, NULL) != 1) {
        tls_log_errors("loading CA failed");
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

SSL *tls_accept(SSL_CTX *ctx, int fd) {
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        return NULL;
    }
    SSL_set_fd(ssl, fd);
    if (SSL_accept(ssl) != 1) {
        tls_log_errors("SSL_accept failed");
        SSL_free(ssl);
        return NULL;
    }
    return ssl;
}

SSL *tls_connect(SSL_CTX *ctx, int fd, const char *servername) {
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        return NULL;
    }
    SSL_set_fd(ssl, fd);
    if (servername) {
        SSL_set_tlsext_host_name(ssl, servername);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        SSL_set1_host(ssl, servername);
#endif
    }
    if (SSL_connect(ssl) != 1) {
        tls_log_errors("SSL_connect failed");
        SSL_free(ssl);
        return NULL;
    }
    long verify = SSL_get_verify_result(ssl);
    if (verify != X509_V_OK) {
        const char *vmsg = X509_verify_cert_error_string(verify);
        if (verify == X509_V_ERR_CERT_HAS_EXPIRED) {
            LOG_ERR("certificate expired: %s", vmsg);
        } else if (verify == X509_V_ERR_CERT_NOT_YET_VALID) {
            LOG_ERR("certificate not yet valid: %s", vmsg);
        } else {
            LOG_ERR("certificate verify failed: %s", vmsg);
        }
        SSL_free(ssl);
        return NULL;
    }
    if (verify_hostname(ssl, servername) != 0) {
        LOG_ERR("hostname verification failed: %s", servername ? servername : "(null)");
        SSL_free(ssl);
        return NULL;
    }
    return ssl;
}
