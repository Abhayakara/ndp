/* ndp.c
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

#define _GNU_SOURCE 1 /* lame */
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
#include <poll.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <ctype.h>
#include <netinet/in.h>

#include "ndp.h"
	     
int exclude_default_route = 1;
interface_t *interfaces;
struct pollfd *pollfds;
query_t **queries;
int num_pollfds;
int pollfd_max;
int query_base; // first pollfd that relates to a query.
nameserver_t *nameservers, *stale_nameservers;
int sock4, sock6;
time_t cycle;
time_t resolv_conf_when, resolv_conf_checked;

int
ntop(char *buf, size_t buflen, address_t *address)
{
  if (address->sa.sa_family == AF_INET)
    {
      inet_ntop(AF_INET, &address->in.sin_addr, buf, buflen);
      return ntohs(address->in.sin_port);
    }
  else if (address->sa.sa_family == AF_INET6)
    {
      inet_ntop(AF_INET6, &address->in6.sin6_addr, buf, buflen);
      return ntohs(address->in6.sin6_port);
    }
  sprintf(buf, "unknown family: %d", address->sa.sa_family);
  return 0;	
}


// Fetch the contents of the resolve.conf file and set up the nameservers
// list on that basis.   In order to avoid leaving dangling pointers, we
// overwrite the existing nameserver structures, rather than allocating new
// ones.   If there aren't enough, we add more; if there are too many,
// we zero the addresses in the remaining ones and hang them off of
// stale_nameservers for possible later use.

// BTW, there's something a bit broken about relying on /etc/resolv.conf
// for configuration information.   We do it because that's how OpenWRT
// communicates the name servers that it gets from the upstream service,
// but that's really broken and I would prefer it if there were some
// other way to get this information.   This is why there's code that
// deliberately excludes the loopback address down below, but that's not
// a complete solution, since in principle /etc/resolv.conf could contain
// any of the host's IP addresses and still create a packet storm.
// XXX Future work.

static int
check_resolv_conf(void)
{
  nameserver_t *ns, *nsp = nameservers, *prev = 0;
  struct stat stb;
  FILE *rcfile;
  char rcline[256];
#ifdef NSDEBUG
  int nsmax;
#endif

  time(&resolv_conf_checked);
  if (stat(RESOLV_CONF_NAME, &stb) < 0)
    {
      resolv_conf_when = 0;
      return 0;
    }

  // File hasn't changed since last read.
  if (resolv_conf_when == stb.st_mtime)
    return 0;

  // This code isn't able to notice that nameservers
  // are being reused, so a reread of the resolv.conf
  // file triggers a flush of all nameserver statistics.
  // Arguably this is suboptimal, but fixing it adds
  // some complexity.
  for (ns = nameservers; ns; ns = ns->next)
    {
      memset(&ns->nqueries, 0, sizeof ns->nqueries);
      memset(&ns->ncomplete, 0, sizeof ns->ncomplete);
      memset(&ns->ndropped, 0, sizeof ns->ndropped);
      memset(&ns->address, 0, sizeof ns->address);

      if (ns->next == nameservers)
	break;
    }

  // If there are stale nameservers, add them back to the nameserver
  // list.
  if (ns)
    {
      if (stale_nameservers)
	{
	  ns->next = stale_nameservers;
	  stale_nameservers = 0;
	}
      else
	ns->next = 0;
    }
  else
    nameservers = stale_nameservers;
      
  resolv_conf_when = stb.st_mtime;
  rcfile = fopen(RESOLV_CONF_NAME, "r");
  if (!rcfile)
    {
      if (errno != ENOENT)
	syslog(LOG_ERR, RESOLV_CONF_NAME ": can't open: %m");
      return 0;
    }

#ifdef NSDEBUG
  for (nsmax = 0, ns = nameservers;
       nsmax < 10 && ns; nsmax++, ns = ns->next)
    {
      char obuf[128];
      int port = ntop(obuf, sizeof obuf, &ns->address);
      syslog(LOG_INFO, "%p %d A NS: %s#%d", ns, nsmax, obuf, port);
      if (ns->next == nameservers)
	break;
    }
  
  if (nsmax == 10)
    abort();
#endif
  
  while (fgets(rcline, sizeof rcline, rcfile))
    {
      char *s;
      for (s = rcline; *s && isascii(*s) && isspace(*s); s++)
	;
      if (*s && !strncmp(s, "nameserver", 10))
	{
	  for (s += 10; *s && isascii(*s) && isspace(*s); s++)
	    ;
	  if (*s)
	    {
	      char *t;
	      address_t sockaddr;
	      int port = 0;
	      memset(&sockaddr, 0, sizeof sockaddr);

	      // Find the end of the string and NUL-terminate it.
	      for (t = s; *t && *t != '#' && isascii(*t) && !isspace(*t); t++)
		;
	      if (*t == '#')
		{
		  port = atoi(t + 1);
		}
	      *t = 0;
	      if (port == 0)
		port = 53;

	      if (inet_pton(AF_INET, s, &sockaddr.in.sin_addr))
		{
		  syslog(LOG_INFO, "NS  INET: %s#%d", s, port);
		  if (port != 53 ||
		      sockaddr.in.sin_addr.s_addr != htonl(INADDR_LOOPBACK))
		    {
		      sockaddr.in.sin_family = AF_INET;
		      sockaddr.in.sin_port = htons(port);
		    }
		}
	      else if (inet_pton(AF_INET6, s, &sockaddr.in6.sin6_addr))
		{
		  syslog(LOG_INFO, "NS INET6: %s#%d", s, port);
		  if (port != 53 ||
		      memcmp(&sockaddr.in6.sin6_addr,
			     &in6addr_loopback, sizeof in6addr_loopback))
		    {
		      sockaddr.in6.sin6_family = AF_INET6;
		      sockaddr.in6.sin6_port = htons(port);
		    }
		}
	      else
		{
		  syslog(LOG_ERR, "Bad nameserver entry in "
			 RESOLV_CONF_NAME ": %s", s);
		}
	      if (sockaddr.sa.sa_family)
		{
		  if (nsp)
		    {
		      prev = nsp;
		      ns = nsp;
		      if (nsp->next == nameservers)
			nsp = 0;
		      else
			nsp = nsp->next;
		    }
		  else
		    {
		      ns = malloc(sizeof *ns);
		      if (!ns)
			{
			  syslog(LOG_CRIT,
				 "no memory for nameserver");
			  exit(1);
			}
		      memset(ns, 0, sizeof *ns);
		      
		      if (prev)
			{
			  ns->next = nameservers;
			  prev->next = ns;
			}
		      else
			{
			  ns->next = ns;
			  nameservers = ns;
			}
		      prev = ns;
		    }
		  ns->address = sockaddr;
		}
	    }
	  
#ifdef NSDEBUG
	  for (nsmax = 0, ns = nameservers;
	       nsmax < 10 && ns; nsmax++, ns = ns->next)
	    {
	      char obuf[128];
	      int port = ntop(obuf, sizeof obuf, &ns->address);
	      syslog(LOG_INFO, "%p %d B NS: %s#%d", ns, nsmax, obuf, port);
	      if (ns->next == nameservers)
		break;
	    }
	  
	  if (nsmax == 10)
	    abort();
#endif
	}
    }
  fclose(rcfile);

  // Re-circularize the list.
  if (prev)
    prev->next = nameservers;
  else
    nameservers = 0;

  // Any remaining nameservers are stale, and so we stash them
  // against later need, but keep them out of the nameserver
  // cycle.

  if (nsp)
    {
      stale_nameservers = nsp;
      while (nsp)
	{
	  memset(&nsp->address, 0, sizeof nsp->address);
	  if (nsp->next == nameservers)
	    nsp->next = 0;
	  nsp = nsp->next;
	}
    }

#ifdef NSDEBUG
  for (nsmax = 0, ns = nameservers;
       nsmax < 10 && ns; nsmax++, ns = ns->next)
    {
      char obuf[128];
      int port = ntop(obuf, sizeof obuf, &ns->address);
      syslog(LOG_INFO, "%p %d B NS: %s#%d", ns, nsmax, obuf, port);
      if (ns->next == nameservers)
	break;
    }
	  
  if (nsmax == 10)
    abort();

  // Make sure we have a valid name server list.
  for (nsp = nameservers; nsp; nsp = nsp->next)
    {
      if (!nsp->next)
	abort();
      if (nsp->next == nameservers)
	break;
    }
#endif

  return 1;
}

int
main(int argc, char **argv)
{
  // enumerate interfaces
  struct ifaddrs *ifa, *ifp;
  interface_t *ip;
  struct ifreq ifr;
  int salen;
  struct sockaddr_in6 s6;
  struct sockaddr_in s4;
  int flag;
  int i, j, result;
  nameserver_t *nsp = 0;
  char *hashmark;
  int port;
  time_t host_dumped;
  time_t last_ns_blip;

  time(&host_dumped);
  last_ns_blip = host_dumped;

  openlog("ndp", LOG_NDELAY|LOG_PID|LOG_PERROR, LOG_DAEMON);

  for (i = 1; i < argc; i++)
    {
      nameserver_t *ns;

      if (!strcmp(argv[i], "-d"))
	{
	  // Daemonize.
	  closelog();
	  openlog("ndp", LOG_NDELAY|LOG_PID, LOG_DAEMON);
	}
      else if (!strcmp(argv[i], "-x"))
	{
	  if (i + 1 == argc)
	    syslog(LOG_CRIT, "-x <interface name>");
	  ip = malloc(sizeof *ip);
	  if (ip)
	    {
	      memset(ip, 0, sizeof *ip);
	      ip->name = strdup(argv[i + 1]);
	    }
	  if (!ip || !ip->name)
	    {
	      syslog(LOG_CRIT, "Out of memory allocating interface %s",
		      argv[i + 1]);
	      exit(1);
	    }
	  if (strlen(ip->name) >= IFNAMSIZ)
	    {
	      syslog(LOG_CRIT, "Interface name too long: %s", ip->name);
	      exit(0);
	    }
	  ip->excluded = 1;
	  ip->index = -1;
	  ip->next = interfaces;
	  interfaces = ip;
	  i++;
	}
      else if (!strcmp(argv[i], "-a"))
	{
	  exclude_default_route = 0;
	}
      else
	{
	  // Not an option, must be a DNS server address.
	  ns = malloc(sizeof *ns);
	  if (!ns)
	    {
	      syslog(LOG_CRIT, "no memory for nameserver");
	      exit(1);
	    }
	  memset(ns, 0, sizeof *ns);

	  // Look for a port in the server identifier.
	  hashmark = strchr(argv[i], '#');
	  if (hashmark)
	    {
	      port = atoi(hashmark + 1);
	      *hashmark = 0;
	    }
	  else
	    port = 53;
	  
	  // Try scanning address as IPv4 address and then IPv6 address
	  if (inet_pton(AF_INET, argv[i], &ns->address.in.sin_addr))
	    {
	      syslog(LOG_INFO, "NS  INET: %s#%d", argv[i], port);
	      ns->address.in.sin_family = AF_INET;
	      ns->address.in.sin_port = htons(port);
	    }
	  else if (inet_pton(AF_INET6, argv[i], &ns->address.in6.sin6_addr))
	    {
	      syslog(LOG_INFO, "NS INET6: %s#%d", argv[i], port);
	      ns->address.in.sin_family = AF_INET6;
	      ns->address.in.sin_port = htons(port);
	    }
	  else
	    {
	      if (hashmark)
		*hashmark = '#';
	      syslog(LOG_CRIT, "invalid nameserver IP address: %s", argv[i]);
	      exit(1);
	    }
	  if (!nsp)
	    nsp = ns;
	  ns->next = nameservers;
	  nameservers = ns;
	}
    }

  if (nsp)
    nsp->next = nameservers;

  // If no nameservers were specified on the command line, we're using
  // resolv.conf.
  if (!nameservers)
      check_resolv_conf();

  // Get a socket; we will be listening on it, but for now just using it
  // for ioctls.
  if ((sock6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
      syslog(LOG_CRIT, "socket: %m");
      exit(1);
    }

  // Get the interface address list.
  if (getifaddrs(&ifa) < 0)
    {
      syslog(LOG_CRIT, "getifaddrs: %m");
      exit(1);
    }

  // Go through the list; don't assume it's sorted by name.
  for (ifp = ifa; ifp; ifp = ifp->ifa_next)
    {
      /* Already seen this name? */
      for (ip = interfaces; ip; ip = ip->next)
	{
	  if (!strcmp(ip->name, ifp->ifa_name))
	    break;
	}
      /* No; make a new entry. */
      if (!ip)
	{
	  ip = malloc(sizeof *ip);
	  if (ip)
	    {
	      memset(ip, 0, sizeof *ip);
	      ip->name = strdup(ifp->ifa_name);
	    }
	  if (!ip || !ip->name)
	    {
	      syslog(LOG_CRIT, "Out of memory allocating interface %s",
		      ifp->ifa_name);
	      exit(1);
	    }
	  if (strlen(ip->name) >= IFNAMSIZ)
	    {
	      syslog(LOG_CRIT, "Interface name too long: %s", ip->name);
	      exit(0);
	    }
	  ip->index = -1;
	  ip->next = interfaces;
	  interfaces = ip;
	}
      if (ip->index == -1)
	{
	  memset(&ifr, 0, sizeof ifr);
	  strcpy(ifr.ifr_name, ip->name);
	  if (ioctl(sock6, SIOCGIFINDEX, &ifr) < 0)
	    {
	      syslog(LOG_CRIT, "SIOCGIFINDEX: %m");
	      exit(1);
	    }
	  ip->index = ifr.ifr_ifindex;
	}
      // Does this entry have an address we care about?
      if (ifp->ifa_addr)
	{
	  if (ifp->ifa_addr->sa_family == AF_INET ||
	      ifp->ifa_addr->sa_family == AF_INET6)
	    {
	      if (ip->numaddrs == ip->maxaddrs)
		{
		  int newmax = ip->maxaddrs * 2;
		  address_t **na;
		  if (newmax == 0)
		    newmax = 5;
		  na = malloc(newmax * sizeof *na);
		  if (!na)
		    {
		      syslog(LOG_CRIT,
			      "Out of memory expanding address list for %s",
			      ip->name);
		      exit(1);
		    }
		  memset(&na[ip->maxaddrs], 0, newmax * sizeof *na);
		  if (ip->addresses)
		    {
		      memcpy(na, ip->addresses, ip->maxaddrs * sizeof *na);
		      free(ip->addresses);
		    }
		  ip->addresses = na;
		}
	      if (ifp->ifa_addr->sa_family == AF_INET)
		salen = sizeof (struct sockaddr_in);
	      else if (ifp->ifa_addr->sa_family == AF_INET6)
		salen = sizeof (struct sockaddr_in6);
	      else
		{
		  syslog(LOG_CRIT, "coding error in sa_len simulator.");
		  exit(1);
		}
	      ip->addresses[ip->numaddrs] = malloc(salen);
	      if (!ip->addresses[ip->numaddrs])
		{
		  syslog(LOG_CRIT, "Out of memory adding address for %s",
			  ip->name);
		  exit(1);
		}
	      memcpy(ip->addresses[ip->numaddrs], ifp->ifa_addr, salen);
	      ip->numaddrs++;
	    }
	}
    }

#define IFLIST_DEBUG 1
#ifdef IFLIST_DEBUG
  for (ip = interfaces; ip; ip=ip->next)
    {
      syslog(LOG_INFO, "Interface %s index %d; %d addresses",
	     ip->name, ip->index, ip->numaddrs);
      for (i = 0; i < ip->numaddrs; i++)
	{
	  char obuf[256];
	  print_address(obuf, sizeof obuf, ip->addresses[i]);
	  syslog(LOG_INFO, "  address %d: %s", i, obuf);
	}
    }
#endif

  netlink_setup();

  // parse arguments so we know what interface(s) to exclude
  // XXX if no exclude interface specified, heuristic to guess which
  // XXX one to exclude will be required.   Future work.
  // XXX actually this is pretty easy--the netlink code can see if
  // XXX there is a default route on that interface; if so, don't
  // XXX accept queries from it.

  // open ipv6 socket, listen on IN6ADDR_ANY
  // This lets us bind to port 53 on two sockets.
  flag = 1;
  if (setsockopt(sock6, SOL_IPV6, IPV6_V6ONLY, &flag, sizeof flag) < 0)
    {
      syslog(LOG_CRIT, "IPV6_V6ONLY");
      exit(1);
    }

  /* Request the ip_recvif socket data. */
  flag = 1;
  if (setsockopt(sock6, IPPROTO_IPV6,
		 IPV6_RECVPKTINFO, &flag, sizeof flag) < 0)
    {
      syslog(LOG_CRIT, "Unable to set IP_RECVIF sockopt: %m");
      exit(1);
    }

  memset(&s6, 0, sizeof s6);
  s6.sin6_family = AF_INET6;
  s6.sin6_port = htons(53); // domain
  if (bind(sock6, (struct sockaddr *)&s6, sizeof s6) < 0)
    {
      syslog(LOG_CRIT, "bind (IPv6 port 53): %m");
      exit(1);
    }

  // open ipv4 socket, listen on INADDR_ANY
  sock4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock4 < 0)
    {
      syslog(LOG_CRIT, "socket (IPv4): %m");
      exit(1);
    }

#ifdef IP_PKTINFO
  /* Request the ip_pktinfo socket data. */
  flag = 1;
  if (setsockopt(sock4, IPPROTO_IP, IP_PKTINFO, &flag, sizeof flag) < 0)
    {
      syslog(LOG_CRIT, "Unable to set IP_PKTINFO sockopt: %m");
      exit(1);
    }
#else
  /* Request the ip_recvif socket data. */
  flag = 1;
  if (setsockopt(sock4, IPPROTO_IP, IP_RECVIF, &flag, sizeof flag) < 0)
    {
      syslog(LOG_CRIT, "Unable to set IP_RECVIF sockopt: %m");
      exit(1);
    }
  
  /* Request the ip_recvif socket data. */
  flag = 1;
  if (setsockopt(sock4, IPPROTO_IP, IP_RECVDSTADDR, &flag, sizeof flag) < 0)
    {
      syslog(LOG_CRIT, "Unable to set IP_RECVIF sockopt: %m");
      exit(1);
    }
#endif           

  memset(&s4, 0, sizeof s4);
  s4.sin_family = AF_INET;
  s4.sin_port = htons(53);
  if (bind(sock4, (struct sockaddr *)&s4, sizeof s4) < 0)
    {
      syslog(LOG_CRIT, "bind (IPv4 port 53): %m");
      exit(1);
    }

  pollfd_max = 10;
  pollfds = malloc(10 * sizeof *pollfds);
  queries = malloc(10 * sizeof *queries);
  if (!pollfds || !queries)
    {
      syslog(LOG_CRIT, "No memory for pollfds!");
      exit(1);
    }
  memset(queries, 0, 10 * sizeof *queries);
  num_pollfds = 3;
  pollfds[0].fd = netlink_socket;
  pollfds[0].events = POLLIN | POLLERR | POLLHUP;
  pollfds[1].fd = sock6;
  pollfds[1].events = POLLIN;
  pollfds[2].fd = sock4;
  pollfds[2].events = POLLIN;
  query_base = 3;

  // Start receive loop
  while (1)
    {
      int count;

      count = poll(pollfds, num_pollfds, 1000 * (10 - cycle - last_ns_blip));
      if (count < 0)
	{
	  syslog(LOG_CRIT, "poll: %m");
	  exit(1);
	}
      time(&cycle);

      // If we are relying on the resolv.conf file, check it every five
      // seconds to see if it has changed.
      if (resolv_conf_checked != 0 && cycle - resolv_conf_checked > 5)
	{
	  if (check_resolv_conf())
	    last_ns_blip = cycle;
	}

      // Cycle the nameserver statistics
      if (cycle - last_ns_blip >= 10)
	{
	  int i;
	  if (nameservers)
	    {
	      nameserver_t *nsp = nameservers;

	      do {
#ifdef DEBUG_CYCLE
		printf("nameserver %04x:", ((int)(long)nsp) & 0xffff);
#endif
		for (i = 4; i > 0; i--)
		  {
#ifdef DEBUG_CYCLE
		    printf(" <%d %d %d>", nsp->nqueries[i],
			   nsp->ncomplete[i], nsp->ndropped[i]);
#endif
		    nsp->nqueries[i] = nsp->nqueries[i - 1];
		    nsp->ncomplete[i] = nsp->ncomplete[i - 1];
		    nsp->ndropped[i] = nsp->ndropped[i - 1];
		  }
#ifdef DEBUG_CYCLE
		printf(" <%d %d %d>",
		       nsp->nqueries[0], nsp->ncomplete[0], nsp->ndropped[0]);
#endif
		nsp->nqueries[0] = nsp->ncomplete[0] = nsp->ndropped[0] = 0;

		nsp = nsp->next;
#ifdef DEBUG_CYCLE
		printf("\n");
#endif
	      } while (nsp != nameservers);
	    }
	  last_ns_blip = cycle;
	}

      // Periodically dump the host table.
      if (cycle - host_dumped > 60)
	{
	  host_dumped = cycle;
	  dump_ntes();
	}

      // Cycle through all the pending queries looking for input.
      // If a query either finishes or times out, close the socket
      // and free the data structure.   J is kept as an index that
      // increments only for kept queries, so as we advance through
      // the list we copy down the good entries, overwriting the
      // expired ones.
      j = query_base;
      for (i = query_base; i < num_pollfds; i++)
	{
	  // If the socket was closed due to an earlier error, skip
	  // over it and let it be garbage-collected.
	  if (queries[i]->socket == -1)
	    result = -1;

	  // Otherwise, if the socket has an input event on it, process
	  // the input.
	  else if (pollfds[i].revents & POLLIN)
	    {
#ifdef DEBUG_POLL
	      printf("read %d, cycle %ld\n",
		     queries[i]->socket, (long)(cycle - queries[i]->cycle));
#endif
	      result = response_read(queries[i]);
	    }

	  // Otherwise, if the query is less than 90 seconds old, keep it.
	  else if (cycle - queries[i]->cycle < 90)
	    result = 1;

	  // Otherwise, drop it.
	  else
	    result = -1;

	  if (result < 0)
	    {
	      if (queries[i]->socket != -1)
		close(queries[i]->socket);
	      queries[i]->socket = -1;
	      free(queries[i]);
	      queries[i] = 0;
	      pollfds[i].fd = -1;
#ifdef DEBUG_POLL
	      printf("delete %d\n", i);
#endif
	    }
	  else
	    {
	      if (j != i)
		{
#ifdef DEBUG_POLL
		  printf("keep %d\n", i);
#endif
		  pollfds[j] = pollfds[i];
		  queries[j] = queries[i];
		}
	      j++;
	    }
	}
#ifdef DEBUG_POLL
      printf("num_pollfds %d -> %d\n", num_pollfds, j);
#endif
      num_pollfds = j;

      // Now do the fixed sockets.   We do these last because
      // they can trigger the addition of new queries to poll, and
      // it's easier to do that after we've rippled away any stale
      // and/or completed queries.
      if (pollfds[0].revents & (POLLERR | POLLHUP))
	{
	  syslog(LOG_CRIT, "netlink socket error event: %x",
		  pollfds[0].revents);
	  exit(1);
	}
      if (pollfds[0].revents & POLLIN)
	netlink_read();
      if (pollfds[1].revents & POLLIN)
	query_read(AF_INET6, sock6);
      if (pollfds[2].revents & POLLIN)
	query_read(AF_INET, sock4);
    }
  return 0;
}

int
response_read(query_t *query)
{
  unsigned char buf[4096];	// XXX arbitrary limit
  ssize_t len;
  address_t src_addr;
  socklen_t srclen = sizeof src_addr;
  int sock;
  int result;
  query_t *response;
  
  len = recvfrom(query->socket, buf, sizeof buf, 0, &src_addr.sa, &srclen);
  if (len < 0)
    {
      syslog(LOG_ERR, "response socket (%d) read fail: %m", query->socket);
      return 0;
    }
  if (len < 12)
    {
      syslog(LOG_DEBUG, "short DNS packet: %ld", (long)len);
      return 0;
    }

  /* Allocate a query structure. */
  response = query_allocate(buf, len);
  if (!response)
    {
      syslog(LOG_ERR, "out of memory for response data structure.");
      return 0;
    }

  // If the result is bogus, just ignore it; if the query is never going
  // to succeed, it will time out.
  result = query_parse(response, buf, len);
  if (result < 0)
    {
      free(response);
      return 0;
    }

  // Get rid of the EDNS0 option coming back.
  result = drop_edns0(response, query->added_edns0);
  if (result < 0)
    {
      free(response);
      return 0;
    }

  if (query->src.sa.sa_family == AF_INET)
    sock = sock4;
  else if (query->src.sa.sa_family == AF_INET6)
    sock = sock6;
  else
    {
      syslog(LOG_ERR, "can't forward query response to family %d",
	      query->src.sa.sa_family);
      free(response);
      return -1;
    }

  sendto(sock, response->query, response->qlength, 0,
	 &query->src.sa, query->srclen);
  free(response);
  query->cur_nameserver->ncomplete[0]++;
  return -1;
}

void
query_read(int family, int sock)
{
  unsigned char buf[4096];	// XXX arbitrary limit
  unsigned char cmsg_buf[1024];
  ssize_t len;
  int result;
  address_t src_addr;
  socklen_t srclen = sizeof src_addr;
  query_t *query;
  nte_t *nte;
  int i;
  int added = 0;
  int ifindex, got_ifindex = 0;
  interface_t *ifp;
  struct cmsghdr *cmh;

  struct iovec iov;
  struct msghdr mh;

  /* Set up msgbuf. */
  memset(&iov, 0, sizeof iov);
  memset(&mh, 0, sizeof mh);

  /* This is equivalent to the from argument in recvfrom. */
  mh.msg_name = (caddr_t)&src_addr;
  mh.msg_namelen = sizeof src_addr;
                   
  /* This is equivalent to the buf argument in recvfrom. */
  mh.msg_iov = &iov;
  mh.msg_iovlen = 1;
  iov.iov_base = (caddr_t)&buf;
  iov.iov_len = sizeof buf;

  /* This is where additional headers get stuffed. */
  mh.msg_control = cmsg_buf;
  mh.msg_controllen = sizeof cmsg_buf;

  len = recvmsg(sock, &mh, 0);
  if (len < 0)
    {
      if (family == AF_INET)
	syslog(LOG_ERR, "INET socket read fail: %m");
      else
	syslog(LOG_ERR, "INET6 socket read fail: %m");
      return;
    }
  if (len < 12)
    {
      syslog(LOG_ERR, "short DNS packet: %ld", (long)len);
      return;
    }

  /* Loop through the control message headers looking for
   * the IPV6_PKTINFO or IP_PKTINFO data.
   */
  for (cmh = CMSG_FIRSTHDR(&mh); cmh; cmh = CMSG_NXTHDR(&mh, cmh))
    {
      if (cmh->cmsg_level == IPPROTO_IPV6 &&
	  cmh->cmsg_type == IPV6_PKTINFO)
	{
	  struct in6_pktinfo pktinfo;
	  
	  /* The sockaddr should be right after the cmsg_hdr. */
	  memcpy(&pktinfo, CMSG_DATA(cmh), sizeof pktinfo);
	  ifindex = pktinfo.ipi6_ifindex;
	  got_ifindex = 1;
#ifdef IP_PKTINFO
	}
      else if (cmh->cmsg_level == IPPROTO_IP &&
	       cmh->cmsg_type == IP_PKTINFO)
	{
	  struct in_pktinfo pktinfo;
	  
	  /* The sockaddr should be right after the cmsg_hdr. */
	  memcpy(&pktinfo, CMSG_DATA(cmh), sizeof pktinfo);
	  ifindex = pktinfo.ipi_ifindex;
	  got_ifindex = 1;
#endif
#ifdef IP_RECVIF
	}
      else if (cmh->cmsg_level == IPPROTO_IP &&
	       cmh->cmsg_type == IP_RECVIF)
	{
	  struct sockaddr_dl *sdl = (struct sockaddr_dl *)CMSG_DATA(cmh);
	  /* The sockaddr should be right after the cmsg_hdr. */
	  ifindex = sdl->sdl_index;
	  got_ifindex = 1;
#endif
	}
    }
  
  // If we didn't get an interface index, we probably shouldn't answer
  // the query.
  if (!got_ifindex)
    {
      syslog(LOG_ERR, "Unable to determine receive interface.");
      return;
    }

  for (ifp = interfaces; ifp; ifp = ifp->next)
    {
      if (ifp->index == ifindex)
	break;
    }
  if (!ifp)
    {
#if 0
      syslog(LOG_ERR, "Unknown interface index: %d", ifindex);
      return;
#endif
    }
  else
  // Don't answer queries on excluded interfaces.
  if (ifp->excluded)
    return;


  /* Allocate a query structure. */
  query = query_allocate(buf, len);
  if (query)
    {
      // See if there is another nameserver we can switch to.
      if (nameservers && nameservers != nameservers->next)
	{
	  nameserver_t *next = nameservers->next;
	  int qcur, qnext, dcur, dnext, ccur, cnext;
	  int i;

	  while (nameservers != next)
	    {
	      qcur = qnext = dcur = dnext = ccur = cnext = 0;
	      
	      for (i = 0; i < 5; i++)
		{
		  qcur += nameservers->nqueries[i];
		  qnext += next->nqueries[i];
		  dcur += nameservers->ndropped[i];
		  dnext += next->ndropped[i];
		  ccur += nameservers->ncomplete[i];
		  cnext += next->ncomplete[i];
		}
	  
	      // If either nameserver has no track record, switch.
	      if (!qcur)
		{
#ifdef DEBUG_CYCLE
		  printf("current has no track record.\n");
#endif
		  nameservers = next;
		  break;
		}
	      // ...
	      else if (!qnext)
		{
#ifdef DEBUG_CYCLE
		  printf("next has no track record.\n");
#endif
		  nameservers = next;
		  break;
		}
	      // If this name server is sucking a lot, switch.
	      else if (qcur && dcur && !ccur)
		{
#ifdef DEBUG_CYCLE
		  printf("current sucks.\n");
#endif
		  nameservers = next;
		  break;
		}
	      // If neither one is sucking, alternate.
	      else if (!dcur && !dnext)
		{
#ifdef DEBUG_CYCLE
		  printf("neither sucks.\n");
#endif
		  nameservers = next;
		  break;
		}
	      next = next->next;
	    }
	}
      
      // If there are no nameservers, we can't send the query.
      if (!nameservers)
	{
	  free(query);
	  return;
	}

      // Whichever name server we landed on, use.
      query->cur_nameserver = nameservers;

      query->src = src_addr;
      query->srclen = srclen;

      // Open a socket on which to forward the query.
      query->socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
      if (query->socket < 0)
	{
	  syslog(LOG_ERR, "query socket: %m");
	  free(query);
	  return;
	}

      // Parse and validate the query.
      result = query_parse(query, buf, len);
      if (result < 0)
	{
	bogus:
	  SET_RCODE(buf, -result);
	  SET_QR(buf, 1);
	  sendto(sock, buf, len, 0, &src_addr.sa, srclen);
	  free(query);
	  return;
	}

      // Get a neighbor table entry for this IP address, and see if there
      // is a filter class attached to the host referenced by the nte.
      nte = fetch_nte(&src_addr);
      if (nte && nte->host >= 0)
	{
	  host_t *host = fetch_host(nte->host);
	  query->host = nte->host;
	  if (host->filter_class >= 0)
	    {
	      const char *filter_class =
		fetch_filter_class(host->filter_class);

	      // If there is a filter class, hack it in to the EDNS0 option
	      if (filter_class)
		result = add_opt_id(query, filter_class, strlen(filter_class));
	      if (result < 0)
		goto bogus;
	    }
	}
      else
	query->host = -1;

      // See if this query is a repeat.
      for (i = query_base; i < num_pollfds; i++)
	{
	  nameserver_t *ns;

	  // If the host and the transaction ID match, we assume it's the same
	  // query without checking the content.
	  // The expectation is that a repeated query is the result of a
	  // timeout, so we just drop the old query on the floor if the
	  // response comes in later.
	  if (queries[i]->host != -1 &&
	      queries[i]->xid == query->xid && queries[i]->host == query->host)
	    {
#ifdef DEBUG_DROPS
	      printf("matched query, xid=%d host=%d index=%d\n",
		     query->xid, query->host, i);
#endif
	      ns = queries[i]->cur_nameserver;
	      if (ns)
		{
		  ns->ndropped[0]++;

		  // cycle to the next name server in sequence.
		  if (ns->next && ns->next->address.sa.sa_family)
		    query->cur_nameserver = queries[i]->cur_nameserver->next;

		  // if this nameserver has gone stale, skip it.
		  else
		    query->cur_nameserver = nameservers;
		}
	      else
		query->cur_nameserver = 0;
	      close(queries[i]->socket);
	      pollfds[i].fd = query->socket;
	      pollfds[i].revents = 0;
	      free(queries[i]);
	      queries[i] = query;
	      added = 1;
	    }
	}

      // Forward the query to a name server
      if (query->cur_nameserver)
	{
	  query->cur_nameserver->nqueries[0]++;
	  len = sendto(query->socket, query->query, query->qlength, 0,
		       &query->cur_nameserver->address.sa,
		       sizeof query->cur_nameserver->address);
	  if (len < 0)
	    {
	      char obuf[128];
	      int port = ntop(obuf, sizeof obuf,
			      &query->cur_nameserver->address);

	      syslog(LOG_ERR, "sendto (%s#%d): %m", obuf, port);
	      close(query->socket);
	      if (added)
		query->socket = -1;
	      else
		free(query);
	    }
	  else if (!added && add_query(query) < 0)
	    {
	      close(query->socket);
	      free(query);
	    }
	}
      else
	{
	  close(query->socket);
	  if (added)
	    query->socket = -1;
	  else
	    free(query);
	}
    }
}

int
add_query(query_t *query)
{
  if (num_pollfds == pollfd_max)
    {
      int max = pollfd_max * 2;
      query_t **nq;
      struct pollfd *npfd;
      syslog(LOG_INFO, "allocating more slots: %d -> %d.\n", num_pollfds, max);
      nq = malloc(max * sizeof *nq);
      npfd = malloc(max * sizeof *npfd);
      if (!nq || !npfd)
	{
	  syslog(LOG_ERR, "No memory for pollfds!");
	  return -1;
	}
      memset(nq + pollfd_max, 0, pollfd_max * sizeof *nq);
      memcpy(nq, queries, pollfd_max * sizeof *nq);
      memcpy(npfd, pollfds, pollfd_max * sizeof *npfd);
      free(queries);
      free(pollfds);
      queries = nq;
      pollfds = npfd;
      pollfd_max = max;
    }
  pollfds[num_pollfds].fd = query->socket;
  pollfds[num_pollfds].events = POLLIN;
  queries[num_pollfds] = query;
#ifdef DEBUG_POLL
  printf("num_pollfds %d -> %d\n", num_pollfds, num_pollfds + 1);
#endif
  num_pollfds++;
  return 1;
}

query_t *
query_allocate(const unsigned char *buf, ssize_t len)
{
  ssize_t qmax = len + 64; // space for OPT RR and then some.
  query_t *query;
  query = malloc(qmax - 1 + sizeof *query);
  if (!query)
    {
      syslog(LOG_ERR, "out of memory on query");
      return 0;
    }
  memset(query, 0, (sizeof *query) - 1);
  memcpy(query->query, buf, len);
  query->qlength = len;
  query->qmax = qmax;
  query->cycle = cycle;
  return query;
}

/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */
