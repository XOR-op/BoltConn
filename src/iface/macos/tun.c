#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if_utun.h>
#include <sys/sys_domain.h>
#include <sys/kern_control.h>

#define UTUN_CONTROL_NAME "com.apple.net.utun_control"
#define TRY(stmt) {if((err = stmt)){close(fd);return -1;}}

/// name should be at least 32 bytes long
int ffi_open_tun(char* name) {
    int fd;
    int err = 0;
    for (int open_at = 0; open_at < 256; ++open_at) {
        struct sockaddr_ctl sock_ctl;
        struct ctl_info ctl_info;
        socklen_t name_len = 32;
        bzero(&ctl_info, sizeof(ctl_info));
        strncpy(ctl_info.ctl_name, UTUN_CONTROL_NAME, MAX_KCTL_NAME);

        fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        if (fd < 0) return -1;
        TRY(ioctl(fd, CTLIOCGINFO, &ctl_info));

        sock_ctl.sc_id = ctl_info.ctl_id;
        sock_ctl.ss_sysaddr = AF_SYS_CONTROL;
        sock_ctl.sc_len = sizeof(sock_ctl);
        sock_ctl.sc_family = AF_SYSTEM;
        sock_ctl.sc_unit = open_at;
        bzero(sock_ctl.sc_reserved, sizeof(sock_ctl.sc_reserved));

        if (connect(fd, (struct sockaddr*) &sock_ctl, sizeof(sock_ctl))) {
            continue;
        }
        TRY(getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name, &name_len));
        return fd;
    }
    return -1;
}