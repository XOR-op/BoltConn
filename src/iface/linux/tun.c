#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/unistd.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#define MAX_SIZE 32

/// name should be at most MAX_SIZE bytes long
int ffi_open_tun(char* name) {
    struct ifreq req;
    bzero(req, sizeof(req));
    req.ifr_ifru.ifru_flags = IFF_TUN | IFF_NO_PI;

    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)return -1;

    if (ioctl(fd, TUNSETIFF, (void*) &req)) {
        close(fd);
        return -1;
    }
    strncpy(name, req.ifr_ifrn.ifrn_name, MAX_SIZE);
    return fd;
}