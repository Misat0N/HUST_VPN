CC=gcc
CFLAGS=-O2 -Wall -Wextra -pedantic -std=c11 -pthread -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
LIBS=-lssl -lcrypto -lpthread -lcrypt

COMMON_SRCS=src/tun.c src/tls.c src/protocol.c src/util.c
SERVER_SRCS=src/vpnserver.c $(COMMON_SRCS)
CLIENT_SRCS=src/vpnclient.c $(COMMON_SRCS)

all: vpnserver vpnclient

vpnserver: $(SERVER_SRCS)
	$(CC) $(CFLAGS) -o $@ $(SERVER_SRCS) $(LIBS)

vpnclient: $(CLIENT_SRCS)
	$(CC) $(CFLAGS) -o $@ $(CLIENT_SRCS) $(LIBS)

clean:
	rm -f vpnserver vpnclient
