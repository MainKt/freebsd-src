/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <net/if.h>
#include <net/if_arp.h>
#include <netlink/netlink.h>
#include <netlink/netlink_snl.h>
#include <netlink/netlink_snl_route_parsers.h>
#include <netlink/route/common.h>
#include <netlink/route/interface.h>

#include <errno.h>

#include "libifconfig.h"
#include "libifconfig_internal.h"

static int ifconfig_modify_flags(ifconfig_handle_t *h, const char *ifname,
    int ifi_flags, int ifi_change);

static int
ifconfig_modify_flags(ifconfig_handle_t *h, const char *ifname, int ifi_flags,
    int ifi_change)
{
	int ret = 0;
	struct snl_state ss;
	struct snl_writer nw;
	struct nlmsghdr *hdr;
	struct ifinfomsg *ifi;
	struct snl_errmsg_data e = { 0 };

	if (!snl_init(&ss, NETLINK_ROUTE)) {
		ifconfig_error(h, NETLINK, ENOTSUP);
		return (-1);
	}

	snl_init_writer(&ss, &nw);
	hdr = snl_create_msg_request(&nw, NL_RTM_NEWLINK);
	ifi = snl_reserve_msg_object(&nw, struct ifinfomsg);
	snl_add_msg_attr_string(&nw, IFLA_IFNAME, ifname);

	ifi->ifi_flags = ifi_flags;
	ifi->ifi_change = ifi_change;

	hdr = snl_finalize_msg(&nw);
	if (hdr == NULL) {
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
ifconfig_if_up(ifconfig_handle_t *h, const char *ifname)
{
	return (ifconfig_modify_flags(h, ifname, IFF_UP, IFF_UP));
}

int
ifconfig_if_down(ifconfig_handle_t *h, const char *ifname)
{
	return (ifconfig_modify_flags(h, ifname, ~IFF_UP, IFF_UP));
}

int
ifconfig_get_mac(ifconfig_handle_t *h, const char *ifname,
    struct ether_addr *addr)
{
	int ret = 0;
	uint32_t nlmsg_seq = 0;
	struct snl_state ss;
	struct snl_writer nw = { 0 };
	struct nlmsghdr *hdr;
	struct snl_parsed_link link = { 0 };
	struct snl_errmsg_data e = { 0 };

	assert(addr != NULL);

	if (!snl_init(&ss, NETLINK_ROUTE)) {
		ifconfig_error(h, NETLINK, ENOTSUP);
		return (-1);
	}

	snl_init_writer(&ss, &nw);
	hdr = snl_create_msg_request(&nw, RTM_GETLINK);
	(void)snl_reserve_msg_object(&nw, struct ifinfomsg);

	snl_add_msg_attr_string(&nw, IFLA_IFNAME, ifname);

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

	nlmsg_seq = hdr->nlmsg_seq;
	while ((hdr = snl_read_reply_multi(&ss, nlmsg_seq, &e)) != NULL) {
		if (!snl_parse_nlmsg(&ss, hdr, &snl_rtm_link_parser, &link))
			continue;

		if (link.ifla_address != NULL &&
		    NLA_DATA_LEN(link.ifla_address) == ETHER_ADDR_LEN) {
			memcpy(addr, NLA_DATA(link.ifla_address),
			    ETHER_ADDR_LEN);
			goto out;
		}
	}
	ifconfig_error(h, NETLINK, ENOENT);
	ret = -1;

out:
	snl_free(&ss);
	return (ret);
}
