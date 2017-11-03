#define _LINUX_IN_H
#include <linux/mroute.h>
#include <linux/types.h>
#include <netinet/igmp.h>
#include <netinet/ip.h>
#include <sys/types.h>

#define IGMP_V3_MEMBERSHIP_REPORT 0x22

#define INADDR_ALLIGMPV3_GROUP ((in_addr_t)0xe0000016)

static inline unsigned short ip_data_len(const struct ip *ip) {
    return ntohs(ip->ip_len) - (ip->ip_hl << 2);
}

static inline void ip_set_len(struct ip *ip, unsigned short len) {
    ip->ip_len = htons(len);
}
