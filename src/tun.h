#ifndef TUN_H
#define TUN_H

int tun_create(const char *devname);
int tun_setup(const char *devname, const char *cidr, int mtu);
int tun_delete(const char *devname);

#endif
