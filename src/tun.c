#include "tun.h"
#include "logging.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int tun_create(const char *devname) {
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        LOG_ERR("open /dev/net/tun failed: %s", strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (devname && devname[0] != '\0') {
        strncpy(ifr.ifr_name, devname, IFNAMSIZ - 1);
    }

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        LOG_ERR("TUNSETIFF failed: %s", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

int tun_setup(const char *devname, const char *cidr, int mtu) {
    if (!devname || !cidr) {
        return -1;
    }
    if (run_cmd("ip addr replace %s dev %s", cidr, devname) != 0) {
        return -1;
    }
    if (run_cmd("ip link set dev %s up mtu %d", devname, mtu) != 0) {
        return -1;
    }
    return 0;
}

int tun_delete(const char *devname) {
    if (!devname) {
        return -1;
    }
    return run_cmd("ip link del %s", devname);
}
