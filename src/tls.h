#ifndef TLS_H
#define TLS_H

#include <openssl/ssl.h>

int tls_init(void);
void tls_cleanup(void);
void tls_log_errors(const char *msg);
SSL_CTX *tls_create_server_ctx(const char *cert, const char *key, const char *ca);
SSL_CTX *tls_create_client_ctx(const char *ca);
SSL *tls_accept(SSL_CTX *ctx, int fd);
SSL *tls_connect(SSL_CTX *ctx, int fd, const char *servername);
int ssl_read_all(SSL *ssl, void *buf, size_t len);
int ssl_write_all(SSL *ssl, const void *buf, size_t len);

#endif
