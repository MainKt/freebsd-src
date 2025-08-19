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

static const struct sockaddr_in NULL_SIN;

static int ifconfig_inet_exec_nl(ifconfig_handle_t *h, int action,
    const char *ifname, const struct ifconfig_inet_addr *addr);

static int
inet_prefixlen(const struct in_addr *addr)
{
	int x;

	x = ffs(ntohl(addr->s_addr));
	return (x == 0 ? 0 : 33 - x);
}

int
ifconfig_inet_get_addrinfo(ifconfig_handle_t *h __unused,
    const char *name __unused, struct ifaddrs *ifa,
    struct ifconfig_inet_addr *addr)
{
	bzero(addr, sizeof(*addr));

	/* Set the address */
	if (ifa->ifa_addr == NULL) {
		return (-1);
	} else {
		addr->sin = (struct sockaddr_in *)ifa->ifa_addr;
	}

	/* Set the destination address */
	if (ifa->ifa_flags & IFF_POINTOPOINT) {
		if (ifa->ifa_dstaddr) {
			addr->dst = (struct sockaddr_in *)ifa->ifa_dstaddr;
		} else {
			addr->dst = &NULL_SIN;
		}
	}

	/* Set the netmask and prefixlen */
	if (ifa->ifa_netmask) {
		addr->netmask = (struct sockaddr_in *)ifa->ifa_netmask;
	} else {
		addr->netmask = &NULL_SIN;
	}
	addr->prefixlen = inet_prefixlen(&addr->netmask->sin_addr);

	/* Set the broadcast */
	if (ifa->ifa_flags & IFF_BROADCAST) {
		addr->broadcast = (struct sockaddr_in *)ifa->ifa_broadaddr;
	}

	/* Set the vhid */
	if (ifa->ifa_data) {
		addr->vhid = ((struct if_data *)ifa->ifa_data)->ifi_vhid;
	}

	return (0);
}

static int
ifconfig_inet_exec_nl(ifconfig_handle_t *h, int action, const char *ifname,
    const struct ifconfig_inet_addr *addr)
{
	int ret = 0, nested_offset = 0;
	struct snl_state ss;
	struct snl_writer nw = { 0 };
	struct nlmsghdr *hdr;
	struct ifaddrmsg *ifahdr;
	struct snl_errmsg_data e = { 0 };

	assert(addr != NULL);

	if (!snl_init(&ss, NETLINK_ROUTE)) {
		ifconfig_error(h, NETLINK, ENOTSUP);
		return (-1);
	}

	snl_init_writer(&ss, &nw);
	hdr = snl_create_msg_request(&nw, action);
	ifahdr = snl_reserve_msg_object(&nw, struct ifaddrmsg);

	ifahdr->ifa_family = AF_INET;
	ifahdr->ifa_prefixlen = addr->prefixlen;

	ifahdr->ifa_index = if_nametoindex(ifname);
	if (ifahdr->ifa_index == 0) {
		ifconfig_error(h, OTHER, EADDRNOTAVAIL);
		ret = -1;
		goto out;
	}

	if (addr->sin != NULL)
		snl_add_msg_attr_ip4(&nw, IFA_LOCAL, &addr->sin->sin_addr);
	if (addr->dst != NULL)
		snl_add_msg_attr_ip4(&nw, IFA_ADDRESS, &addr->dst->sin_addr);
	if (addr->broadcast != NULL)
		snl_add_msg_attr_ip4(&nw, IFA_BROADCAST,
		    &addr->broadcast->sin_addr);

	nested_offset = snl_add_msg_attr_nested(&nw, IFA_FREEBSD);
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
ifconfig_add_inet(ifconfig_handle_t *h, const char *ifname,
    const struct ifconfig_inet_addr *addr)
{
	return (ifconfig_inet_exec_nl(h, NL_RTM_NEWADDR, ifname, addr));
}

int
ifconfig_del_inet(ifconfig_handle_t *h, const char *ifname,
    const struct ifconfig_inet_addr *addr)
{
	return (ifconfig_inet_exec_nl(h, NL_RTM_DELADDR, ifname, addr));
}
