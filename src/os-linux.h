#define _LINUX_IN_H
#define _GNU_SOURCE
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <linux/types.h>
#include <linux/mroute.h>
#include "igmp.h"

#define IGMP_MEMBERSHIP_QUERY IGMP_HOST_MEMBERSHIP_QUERY
#define IGMP_V1_MEMBERSHIP_REPORT IGMP_v1_HOST_MEMBERSHIP_REPORT
#define IGMP_V2_MEMBERSHIP_REPORT IGMP_v2_HOST_MEMBERSHIP_REPORT
#define IGMP_V2_LEAVE_GROUP IGMP_HOST_LEAVE_MESSAGE
#define IGMP_V3_MEMBERSHIP_REPORT IGMP_v3_HOST_MEMBERSHIP_REPORT

static inline unsigned short ip_data_len(const struct ip *ip)
{
    return ntohs(ip->ip_len) - (ip->ip_hl << 2);
}

static inline void ip_set_len(struct ip *ip, unsigned short len)
{
    ip->ip_len = htons(len);
}
