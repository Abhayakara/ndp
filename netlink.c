/* netlink.c
 *
 * Copyright (c) Nominum, Inc 2013
 * All Rights Reserved
 */

/*
 * This file is part of NDP.
 * 
 * NDP is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * NDP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with NDP.  If not, see <http://www.gnu.org/licenses/>.
 */

#define __APPLE_USE_RFC_3542 1 /* lame */

#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <syslog.h>
#include <time.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "ndp.h"
#include "netlink.h"
	     
int netlink_socket;
int sequence = 1;

void
gendump(struct nlmsghdr *header, ssize_t bytes, const char *name)
{
#ifdef NETLINK_DEBUG
  printf("netlink message %s\n"
	 "\tlen %d(%lu) type %d flags %x seq %d pid %d\n",
	 name, header->nlmsg_len, bytes, header->nlmsg_type,
	 header->nlmsg_flags, header->nlmsg_seq, header->nlmsg_pid);
#endif
}

void
handle_link(struct nlmsghdr *header, ssize_t bytes, const char *name)
{
  struct rtattr *rta;
  struct ifinfomsg *ifi;
  int len;
  char ifname[IF_NAMESIZE + 1];
  len = header->nlmsg_len - sizeof *header;
#ifdef LINK_DEBUG
  gendump(header, bytes, name);
  printf("\tpayload len: %d\n", len);
  for (i = 0; i < len; i++)
    {
      if (!(i % 20))
	printf("\n\t%08x:", (int)(((unsigned char *)(header + 1))) + i);
      printf(" %02x", ((unsigned char *)(header + 1))[i]);
    }
  printf("\n");
  if (len < sizeof *ifi)
    {
      printf("\ttoo short\n");
      return;
    }
#endif
  ifi = (struct ifinfomsg *)NLMSG_DATA(header);
  rta = (struct rtattr *)((char *)ifi + NLMSG_ALIGN(sizeof(*ifi)));
  len = NLMSG_PAYLOAD(header, sizeof *ifi);
#ifdef LINK_DEBUG
  printf("header: %p ifi: %p offset: %lu  size: %lu  rta %p  len %d\n",
	 header, ifi, (char *)ifi - (char *)header, sizeof *header,
	 rta, len);
  printf("\tfamily: %d type: %d index: %d flags: %x change: %x\n",
	 ifi->ifi_family,
	 ifi->ifi_type, ifi->ifi_index, ifi->ifi_flags, ifi->ifi_change);
#endif
  ifname[0] = 0;
  for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len))
    {
      int namelen;
      const char *np;
      switch(rta->rta_type)
	{
	case IFLA_IFNAME:
	  namelen = RTA_PAYLOAD(rta);
	  if (namelen > IF_NAMESIZE)
	    namelen = IF_NAMESIZE;
	  np = RTA_DATA(rta);
	  memcpy(ifname, np, namelen);
	  ifname[namelen] = 0;
	}
    }
  syslog(LOG_INFO, "%s: %s index %d\n", name, ifname, ifi->ifi_index);
}

void
handle_addr(struct nlmsghdr *header, ssize_t bytes, const char *name)
{
#ifdef ADDR_DEBUG
  struct rtattr *rta;
  int len;
  gendump(header, bytes, name);
  len = NLMSG_PAYLOAD(header, sizeof *header);
  printf("\tpayload len: %d\n", len);
  for (rta = (struct rtattr *)NLMSG_DATA(header);
       RTA_OK(rta, len);
       rta = RTA_NEXT(rta, len))
    {
      printf("\trta type: %d len %d\n", rta->rta_type, rta->rta_len);
    }
#endif
}

void
handle_route(struct nlmsghdr *header, ssize_t bytes, const char *name)
{
  struct rtattr *rta;
  struct rtmsg *rtm;
  int len;
  address_t addr;
  interface_t *ifp;
#ifdef ROUTE_DEBUG
  int i;
  const char *np = "unknown";
#endif
  int ifid;
  int have_ifid = 0;
  memset(&addr, 0, sizeof addr);
  len = header->nlmsg_len - sizeof *header;
#ifdef ROUTE_DEBUG
  gendump(header, bytes, name);
  printf("\tpayload len: %d\n", len);
  for (i = 0; i < len; i++)
    {
      if (!(i % 20))
	printf("\n\t%08x:", (int)(((unsigned char *)(header + 1))) + i);
      printf(" %02x", ((unsigned char *)(header + 1))[i]);
    }
  printf("\n");
  if (len < sizeof *rtm)
    {
      printf("\ttoo short\n");
      return;
    }
#endif
  rtm = (struct rtmsg *)NLMSG_DATA(header);
  rta = (struct rtattr *)((char *)rtm + NLMSG_ALIGN(sizeof(*rtm)));
  len = NLMSG_PAYLOAD(header, sizeof *rtm);
#ifdef ROUTE_DEBUG
  switch(rtm->rtm_type)
    {
    case RTN_UNICAST:
      np = "RTN_UNICAST";
      break;
    case RTN_LOCAL:
      np = "RTN_LOCAL";
      break;
    case RTN_BROADCAST:
      np = "RTN_BROADCAST";
      break;
    case RTN_ANYCAST:
      np = "RTN_ANYCAST";
      break;
    case RTN_MULTICAST:
      np = "RTN_MULTICAST";
      break;
    case RTN_BLACKHOLE:
      np = "RTN_BLACKHOLE";
      break;
    case RTN_UNREACHABLE:
      np = "RTN_UNREACHABLE";
      break;
    case RTN_PROHIBIT:
      np = "RTN_PROHIBIT";
      break;
    case RTN_THROW:
      np = "RTN_THROW";
      break;
    case RTN_NAT:
      np = "RTN_NAT";
      break;
    case RTN_XRESOLVE:
      np = "RTN_XRESOLVE";
      break;
    }

  printf("%s fam: %d  dl: %d  sl: %d  type: %s  flags: %x:",
	 name, rtm->rtm_family, rtm->rtm_dst_len, rtm->rtm_src_len,
	 np, rtm->rtm_flags);
#endif
  for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len))
    {
      uint32_t val = 0;
#if defined(ROUTE_DEBUG)
      char abuf[256];
#if defined(ROUTE_DEBUG_INTENSIVELY)
      int tl = RTA_PAYLOAD(rta);
#endif
      unsigned char *ap = 0;
      int have_val = 0;
      np = "unknown";
#endif
      switch(rta->rta_type)
	{
	case RTA_DST:
#ifdef ROUTE_DEBUG
	  np = "RTA_DST";
	  ap = RTA_DATA(rta);
#endif
	  break;
	case RTA_SRC:
#ifdef ROUTE_DEBUG
	  np = "RTA_SRC";
	  ap = RTA_DATA(rta);
#endif
	  break;
	case RTA_IIF:
	  memcpy(&val, RTA_DATA(rta), sizeof val);
#ifdef ROUTE_DEBUG
	  np = "RTA_IIF";
	  have_val = 1;
#endif
	  break;
	case RTA_OIF:
#ifdef ROUTE_DEBUG
	  np = "RTA_OIF";
#endif
	  memcpy(&ifid, RTA_DATA(rta), sizeof val);
	  have_ifid = 1;
	  break;
	case RTA_GATEWAY:
#ifdef ROUTE_DEBUG
	  np = "RTA_GATEWAY";
	  ap = RTA_DATA(rta);
#endif
	  break;
	case RTA_PRIORITY:
	  memcpy(&val, RTA_DATA(rta), sizeof val);
#ifdef ROUTE_DEBUG
	  np = "RTA_PRIORITY";
	  have_val = 1;
#endif
	  break;
	case RTA_PREFSRC:
#ifdef ROUTE_DEBUG
	  np = "RTA_PREFSRC";
#endif
	  break;
	case RTA_METRICS:
#ifdef ROUTE_DEBUG
	  np = "RTA_METRICS";
#endif
	  break;
	case RTA_MULTIPATH:
#ifdef ROUTE_DEBUG
	  np = "RTA_MULTIPATH";
#endif
	  break;
	case RTA_PROTOINFO:
#ifdef ROUTE_DEBUG
	  np = "RTA_PROTOINFO";
#endif
	  break;
	case RTA_FLOW:
#ifdef ROUTE_DEBUG
	  np = "RTA_FLOW";
#endif
	  break;
	case RTA_CACHEINFO:
#ifdef ROUTE_DEBUG
	  np = "RTA_CACHEINFO";
#endif
	  break;
	case RTA_SESSION:
#ifdef ROUTE_DEBUG
	  np = "RTA_SESSION";
#endif
	  break;
	case RTA_MP_ALGO:
#ifdef ROUTE_DEBUG
	  np = "RTA_MP_ALGO";
#endif
	  break;
	case RTA_TABLE:
#ifdef ROUTE_DEBUG
	  np = "RTA_TABLE";
#endif
	  memcpy(&val, RTA_DATA(rta), sizeof val);
#ifdef ROUTE_DEBUG
	  have_val = 1;
#endif
	  break;
#ifdef RTA_MARK
	case RTA_MARK:
#ifdef ROUTE_DEBUG
	  np = "RTA_MARK";
#endif
	  break;
#endif
	}
#ifdef ROUTE_DEBUG
      if (ap)
	inet_ntop(rtm->rtm_family, ap, abuf, sizeof abuf);
      else if (have_val)
	sprintf(abuf, "%u", val);
      else
	{
#if ROUTE_DEBUG_INTENSIVELY
	  ap = RTA_DATA(rta);
	  snprintf(abuf, sizeof abuf,
		   "<%d %d: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x>",
		   rta->rta_type, tl, ap[0], ap[1], ap[2], ap[3], ap[4],
		   ap[5], ap[6], ap[7], ap[8], ap[9], ap[10], ap[11], ap[12],
		   ap[13], ap[14], ap[15]);
#else
	  abuf[0] = 0;
#endif
	}
      printf(" %s(%s)", np, abuf);
#endif
    }
#ifdef ROUTE_DEBUG
  printf("\n");
#endif
  if (have_ifid && rtm->rtm_family == AF_INET && rtm->rtm_dst_len == 0)
    {
      for (ifp = interfaces; ifp; ifp = ifp->next)
	  if (ifp->index == ifid)
	    break;
      if (ifp && strcmp(ifp->name, "lo") && exclude_default_route)
	ifp->excluded = header->nlmsg_type == RTM_NEWROUTE ? 1 : 0;
      printf("Default route for IPv4 %s on interface %s%s\n",
	     header->nlmsg_type == RTM_NEWROUTE ? "added" : "removed",
	     ifp ? ifp->name : "<unknown interface>",
	     ifp ? (ifp->excluded ? " (border)" : " (internal)") : "");
    }
  else if (have_ifid && rtm->rtm_family == AF_INET6 && rtm->rtm_dst_len == 0)
    {
      for (ifp = interfaces; ifp; ifp = ifp->next)
	  if (ifp->index == ifid)
	    break;
      if (ifp && strcmp(ifp->name, "lo") && exclude_default_route)
	ifp->excluded = header->nlmsg_type == RTM_NEWROUTE ? 1 : 0;
      printf("Default route for IPv6 %s on interface %s%s\n",
	     header->nlmsg_type == RTM_NEWROUTE ? "added" : "removed",
	     ifp ? ifp->name : "<unknown interface>",
	     ifp ? (ifp->excluded ? " (border)" : " (internal)") : "");
    }
}

void
netlink_setup()
{
  struct sockaddr_nl sa;
  int rbsize = 1048576;
  struct {
    struct nlmsghdr header;
    struct rtgenmsg gen;
  } rtmsg;

  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;
  sa.nl_groups = (RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE |
		  RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE);
  netlink_socket = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  setsockopt(netlink_socket, SOL_SOCKET, SO_RCVBUF, &rbsize, sizeof rbsize);
  bind(netlink_socket, (struct sockaddr *) &sa, sizeof(sa));

  // Get the current IPv4 routing table
  memset(&rtmsg, 0, sizeof rtmsg);
  rtmsg.header.nlmsg_type = RTM_GETROUTE;
  rtmsg.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  rtmsg.header.nlmsg_seq = sequence++;
  rtmsg.header.nlmsg_len = sizeof rtmsg;
  rtmsg.gen.rtgen_family = AF_INET;

  //* Write the message and read the immediate result.
  write(netlink_socket, &rtmsg, sizeof rtmsg);
  netlink_read();

  // Get the current IPv6 routing table
  memset(&rtmsg, 0, sizeof rtmsg);
  rtmsg.header.nlmsg_type = RTM_GETROUTE;
  rtmsg.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  rtmsg.header.nlmsg_seq = sequence++;
  rtmsg.header.nlmsg_len = sizeof rtmsg;
  rtmsg.gen.rtgen_family = AF_INET6;

  //* Write the message and read the immediate result.
  write(netlink_socket, &rtmsg, sizeof rtmsg);
  netlink_read();
}

void
netlink_read()
{
  char nlbuf[4096];
  struct nlmsghdr *header;
  ssize_t bytes;

  bytes = read(netlink_socket, nlbuf, sizeof nlbuf);
  if (bytes < 0)
    {
      perror("netlink socket read");
      exit(1);
    }
  
  for (header = (struct nlmsghdr *)nlbuf;
       NLMSG_OK(header, bytes);
       header = NLMSG_NEXT(header, bytes))
    {
      switch(header->nlmsg_type)
	{
	case RTM_NEWLINK:
	  handle_link(header, bytes, "RTM_NEWLINK");
	  break;

	case RTM_DELLINK:
	  handle_link(header, bytes, "RTM_DELLINK");
	  break;

	case RTM_NEWADDR:
	  handle_addr(header, bytes, "RTM_NEWADDR");
	  break;

	case RTM_DELADDR:
	  handle_addr(header, bytes, "RTM_DELADDR");
	  break;

	case RTM_NEWROUTE:
	  handle_route(header, bytes, "RTM_NEWROUTE");
	  break;

	case RTM_DELROUTE:
	  handle_route(header, bytes, "RTM_DELROUTE");
	  break;

	case RTM_NEWNEIGH:
	  handle_neighbor(header, bytes, "RTM_NEWNEIGH");
	  break;

	case RTM_DELNEIGH:
	  handle_neighbor(header, bytes, "RTM_DELNEIGH");
	  break;

	default:
#ifdef NETLINK_DEBUG
	  printf("\tunknown/unsupported %d\n", header->nlmsg_type);
#endif
	  break;
	}
    }
}

/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */

