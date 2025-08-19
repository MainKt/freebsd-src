/*
 * Copyright (c) 1983, 1993
 *  The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <sys/param.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netlink/netlink_snl.h>
#include <netlink/netlink_snl_route.h>
#include <netlink/route/common.h>
#include <netlink/route/ifaddrs.h>

#include <errno.h>
#include <ifaddrs.h>
#include <string.h>
#include <strings.h>

#include "libifconfig.h"
#include "libifconfig_internal.h"

static int ifconfig_inet6_exec_nl(ifconfig_handle_t *h, int action,
    const char *ifname, const struct ifconfig_inet6_addr *addr);

static int
inet6_prefixlen(struct in6_addr *addr)
{
	int prefixlen = 0;
	int i;

	for (i = 0; i < 4; i++) {
		int x = ffs(ntohl(addr->__u6_addr.__u6_addr32[i]));
		prefixlen += x == 0 ? 0 : 33 - x;
		if (x != 1) {
			break;
		}
	}
	return (prefixlen);
}

int
ifconfig_inet6_get_addrinfo(ifconfig_handle_t *h,
    const char *name, struct ifaddrs *ifa, struct ifconfig_inet6_addr *addr)
{
	struct sockaddr_in6 *netmask;
	struct in6_ifreq ifr6;

	bzero(addr, sizeof(*addr));

	/* Set the address */
	addr->sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;

	/* Set the destination address */
	if (ifa->ifa_flags & IFF_POINTOPOINT) {
		addr->dstin6 = (struct sockaddr_in6 *)ifa->ifa_dstaddr;
	}

	/* Set the prefixlen */
	netmask = (struct sockaddr_in6 *)ifa->ifa_netmask;
	addr->prefixlen = inet6_prefixlen(&netmask->sin6_addr);

	/* Set the flags */
	strlcpy(ifr6.ifr_name, name, sizeof(ifr6.ifr_name));
	ifr6.ifr_addr = *addr->sin6;
	if (ifconfig_ioctlwrap(h, AF_INET6, SIOCGIFAFLAG_IN6, &ifr6) < 0) {
		return (-1);
	}
	addr->flags = ifr6.ifr_ifru.ifru_flags6;

	/* Set the lifetimes */
	memset(&addr->lifetime, 0, sizeof(addr->lifetime));
	ifr6.ifr_addr = *addr->sin6;
	if (ifconfig_ioctlwrap(h, AF_INET6, SIOCGIFALIFETIME_IN6, &ifr6) < 0) {
		return (-1);
	}
	addr->lifetime = ifr6.ifr_ifru.ifru_lifetime; /* struct copy */

	/* Set the vhid */
	if (ifa->ifa_data) {
		addr->vhid = ((struct if_data *)ifa->ifa_data)->ifi_vhid;
	}

	return (0);
}

static int
ifconfig_inet6_exec_nl(ifconfig_handle_t *h, int action, const char *ifname,
    const struct ifconfig_inet6_addr *addr)
{
	int ret = 0, nested_offset = 0;
	struct snl_state ss;
	struct snl_writer nw = { 0 };
	struct nlmsghdr *hdr;
	struct ifaddrmsg *ifahdr;
	struct ifa_cacheinfo ci = { 0 };
	struct snl_errmsg_data e = { 0 };

	assert(addr != NULL);

	if (!snl_init(&ss, NETLINK_ROUTE)) {
		ifconfig_error(h, NETLINK, ENOTSUP);
		return (-1);
	}

	snl_init_writer(&ss, &nw);
	hdr = snl_create_msg_request(&nw, action);
	ifahdr = snl_reserve_msg_object(&nw, struct ifaddrmsg);

	ifahdr->ifa_family = AF_INET6;
	ifahdr->ifa_prefixlen = addr->prefixlen;

	ifahdr->ifa_index = if_nametoindex(ifname);
	if (ifahdr->ifa_index == 0) {
		ifconfig_error(h, OTHER, EADDRNOTAVAIL);
		ret = -1;
		goto out;
	}

	if (addr->sin6 != NULL)
		snl_add_msg_attr_ip6(&nw, IFA_LOCAL, &addr->sin6->sin6_addr);
	if (addr->dstin6 != NULL)
		snl_add_msg_attr_ip6(&nw, IFA_ADDRESS,
		    &addr->dstin6->sin6_addr);

	ci.ifa_prefered = addr->lifetime.ia6t_pltime;
	ci.ifa_valid = addr->lifetime.ia6t_vltime;
	snl_add_msg_attr(&nw, IFA_CACHEINFO, sizeof(ci), &ci);

	nested_offset = snl_add_msg_attr_nested(&nw, IFA_FREEBSD);
	snl_add_msg_attr_u32(&nw, IFAF_FLAGS, addr->flags);
	if (addr->vhid != 0)
		snl_add_msg_attr_u32(&nw, IFAF_VHID, addr->vhid);
	snl_end_attr_nested(&nw, nested_offset);

	if ((hdr = snl_finalize_msg(&nw)) == NULL) {
		ifconfig_error(h, NETLINK, ENOMEM);
		ret = -1;
		goto out;
	}

	if (!snl_send_message(&ss, hdr)) {
		ifconfig_error(h, NETLINK, EIO);
		ret = -1;
		goto out;
	}

	if (!snl_read_reply_code(&ss, hdr->nlmsg_seq, &e)) {
		ifconfig_error(h, NETLINK, e.error);
		ret = -1;
		goto out;
	}

out:
	snl_free(&ss);
	return (ret);
}

int
ifconfig_add_inet6(ifconfig_handle_t *h, const char *ifname,
    const struct ifconfig_inet6_addr *addr)
{
	return (ifconfig_inet6_exec_nl(h, NL_RTM_NEWADDR, ifname, addr));
}

int
ifconfig_del_inet6(ifconfig_handle_t *h, const char *ifname,
    const struct ifconfig_inet6_addr *addr)
{
	return (ifconfig_inet6_exec_nl(h, NL_RTM_DELADDR, ifname, addr));
}
