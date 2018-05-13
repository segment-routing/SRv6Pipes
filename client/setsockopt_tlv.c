#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#ifndef __u8
#define __u8 uint8_t
#endif

#ifndef __u16
#define __u16 uint16_t
#endif

#define SR6_TLV_RETPATH 6

struct ipv6_sr_hdr {
        __u8    nexthdr;
        __u8    hdrlen;
        __u8    type;
        __u8    segments_left;
        __u8    first_segment;
        __u8    flags;
        __u16   tag;

        struct in6_addr segments[0];
};

struct sr6_tlv {
        __u8 type;
        __u8 len;
        __u8 data[0];
};

struct sr6_tlv_retpath {
        struct sr6_tlv tlvhdr;
        __u8 reserved[5];
        __u8 segments_left;
        struct in6_addr segments[0];
};

int test_sr(const char *bindaddr, const char *dst, short port, const char *segment)
{
    int fd, err, srh_len;
    struct ipv6_sr_hdr *srh;
    struct sockaddr_in6 sin6, sin6_bind;
    struct sr6_tlv_retpath *rt_tlv;
    static char buf[] = "Hello with Segment Routing :)\n";

    srh_len = sizeof(*srh) + 2 * sizeof(struct in6_addr) + sizeof(struct sr6_tlv_retpath) + 2 * sizeof(struct in6_addr);
    srh = calloc(1, srh_len);
    if (!srh)
        return -1;

    srh->nexthdr = 0;
    srh->hdrlen = (srh_len >> 3) - 1;
    srh->type = 4;
    srh->segments_left = 1;
    srh->first_segment = 1;
    srh->flags = 0;
    srh->tag = 0;

    memset(&srh->segments[0], 0, sizeof(struct in6_addr));
    inet_pton(AF_INET6, segment, &srh->segments[1]);

    rt_tlv = (struct sr6_tlv_retpath *)((unsigned char *)srh + sizeof(*srh) + 2 * sizeof(struct in6_addr));
    rt_tlv->tlvhdr.type = SR6_TLV_RETPATH;
    rt_tlv->tlvhdr.len = 6 + 2 * sizeof(struct in6_addr);
    rt_tlv->segments_left = 0;
    inet_pton(AF_INET6, segment, &rt_tlv->segments[1]);
    inet_pton(AF_INET6, bindaddr, &rt_tlv->segments[0]);

    fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    err = setsockopt(fd, IPPROTO_IPV6, IPV6_RTHDR, srh, srh_len);
    if (err < 0) {
        perror("setsockopt");
        close(fd);
        return -1;
    }

    memset(&sin6_bind, 0, sizeof(sin6_bind));
    sin6_bind.sin6_family = AF_INET6;
    inet_pton(AF_INET6, bindaddr, &sin6_bind.sin6_addr);

    err = bind(fd, (struct sockaddr *)&sin6_bind, sizeof(sin6_bind));
    if (err < 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(port);
    inet_pton(AF_INET6, dst, &sin6.sin6_addr);

    err = connect(fd, (struct sockaddr *)&sin6, sizeof(sin6));
    if (err < 0) {
        perror("connect");
        close(fd);
        return -1;
    }

    err = send(fd, buf, sizeof(buf), 0);
    if (err < 0) {
        perror("send");
        close(fd);
        return -1;
    }

    sleep(5);

    close(fd);
    return 0;
}

int main(int ac, char **av)
{
    if (ac < 5) {
        fprintf(stderr, "Usage: %s bindaddr dst port segment\n", av[0]);
        return -1;
    }

    return test_sr(av[1], av[2], atoi(av[3]), av[4]);
}
