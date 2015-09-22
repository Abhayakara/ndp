/* neighbor.c
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
#include <sys/stat.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "ndp.h"
#include "netlink.h"
	     
nte_t *ntes;
int num_ntes;
int max_ntes;
host_t *hosts;
int num_hosts;
int max_hosts;
char **filter_classes;
int num_filter_classes;
int max_filter_classes;

int send_mac_as_filter_class = 1;

static int
find_host(unsigned char *lladdr, int llal)
{
  int i;
  for (i = 0; i < num_hosts; i++)
    {
      if (hosts[i].lladdr.len == llal &&
	  !memcmp(hosts[i].lladdr.data, lladdr, llal))
	return i;
    }
  return -1;
}

static int
find_nte(address_t *address)
{
  int i;

  if (address->sa.sa_family == AF_INET)
    {
      for (i = 0; i < num_ntes; i++)
	if (ntes[i].address.sa.sa_family == AF_INET &&
	    ntes[i].address.in.sin_addr.s_addr == address->in.sin_addr.s_addr)
	  return i;
    }
  else if (address->sa.sa_family == AF_INET6)
    {
      for (i = 0; i < num_ntes; i++)
	if (ntes[i].address.sa.sa_family == AF_INET6 &&
	    !memcmp(ntes[i].address.in6.sin6_addr.s6_addr,
		    address->in6.sin6_addr.s6_addr, 16))
	  return i;
    }
  return -1;
}

void
handle_neighbor(struct nlmsghdr *header, ssize_t bytes, const char *name)
{
  struct rtattr *rta;
  struct ndmsg *ndm;
  int len, i;
  address_t addr;
  unsigned char *lladdr = 0;
  int lladdr_len = 0;
  memset(&addr, 0, sizeof addr);
  len = header->nlmsg_len - sizeof *header;
#ifdef NEIGHBOR_DEBUG
  gendump(header, bytes, name);
  printf("\tpayload len: %d\n", len);
  for (i = 0; i < len; i++)
    {
      if (!(i % 20))
	printf("\n\t%8p:", (((unsigned char *)(header + 1))) + i);
      printf(" %02x", ((unsigned char *)(header + 1))[i]);
    }
  printf("\n");
  if (len < sizeof *ndm)
    {
      printf("\ttoo short\n");
      return;
    }
#endif
  ndm = (struct ndmsg *)NLMSG_DATA(header);
  rta = (struct rtattr *)((char *)ndm + NLMSG_ALIGN(sizeof(*ndm)));
  len = NLMSG_PAYLOAD(header, sizeof *ndm);
  for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len))
    {
      switch(rta->rta_type)
	{
	case NDA_DST:
	  addr.sa.sa_family = ndm->ndm_family;
	  if (addr.sa.sa_family == AF_INET)
	    memcpy(&addr.in.sin_addr,
		   RTA_DATA(rta), sizeof addr.in.sin_addr);
	  else if (addr.sa.sa_family == AF_INET6)
	    memcpy(&addr.in6.sin6_addr,
		   RTA_DATA(rta), sizeof addr.in6.sin6_addr);
	  break;
	case NDA_LLADDR:
	  lladdr = (unsigned char *)RTA_DATA(rta);
	  lladdr_len = RTA_PAYLOAD(rta);
	  break;
	}
    }
  if (lladdr && addr.sa.sa_family)
    {
#ifdef NEIGHBOR_DEBUG
      char abuf[256];
      if (addr.sa.sa_family == AF_INET)
	inet_ntop(addr.sa.sa_family, &addr.in.sin_addr, abuf, sizeof abuf);
      else if (addr.sa.sa_family == AF_INET6)
	inet_ntop(addr.sa.sa_family, &addr.in6.sin6_addr, abuf, sizeof abuf);
      else
	snprintf(abuf, sizeof abuf, "AF_%d", addr.sa.sa_family);
      printf("%s: %s lladdr %x", name, abuf, lladdr[0]);
      for (i = 1; i < lladdr_len; i++)
	printf(":%x", lladdr[i]);
      if (ndm->ndm_flags & NTF_USE)
	printf(" use");
      if (ndm->ndm_flags & NTF_PROXY)
	printf(" proxy");
      if (ndm->ndm_flags & NTF_ROUTER)
	printf(" router");
      if (ndm->ndm_state & NUD_INCOMPLETE)
	printf(" incomplete");
      if (ndm->ndm_state & NUD_REACHABLE)
	printf(" reachable");
      if (ndm->ndm_state & NUD_STALE)
	printf(" stale");
      if (ndm->ndm_state & NUD_DELAY)
	printf(" delay");
      if (ndm->ndm_state & NUD_PROBE)
	printf(" probe");
      if (ndm->ndm_state & NUD_FAILED)
	printf(" failed");
      printf("\n");
#endif
      if (header->nlmsg_type == RTM_NEWNEIGH &&
	  !(ndm->ndm_state & (NUD_NOARP |
			      NUD_INCOMPLETE |
			      NUD_FAILED)))
	{
#ifdef NEIGHBOR_DEBUG
	  printf("Added neighbor: %s flags %x state %x lladdr %x",
		 abuf, ndm->ndm_flags, ndm->ndm_state, lladdr[0]);

	  for (i = 1; i < lladdr_len; i++)
	    printf(":%x", lladdr[i]);
	  printf("\n");
#endif
	  i = find_nte(&addr);
	  if (i < 0)
	    add_nte(&addr, lladdr, lladdr_len);
	  else
	    ntes[i].cycle = cycle;
	}
    }
}

int
add_host(unsigned char *lladdr, int llal)
{
  // We can't save a host if its link-local address is greater than
  // LLADDR_MAXLEN; however, it's unlikely that this will happen.
  if (llal > LLADDR_MAXLEN)
    {
      syslog(LOG_ERR,
	     "LLADDR_MAXLEN (%d) too short to accommodate lladdr (%d)",
	     LLADDR_MAXLEN, llal);
      return -1;
    }

  if (num_hosts == max_hosts)
    {
      host_t *nh;
      int max = max_hosts * 2;
      if (max == 0)
	max = 10;
      nh = malloc (max * sizeof *nh);
      if (!nh)
	{
	  syslog(LOG_ERR, "no memory to expand neighbor table.");
	  return -1;
	}
      memcpy(nh, hosts, num_hosts * sizeof *hosts);
      memset(nh + num_hosts, 0, num_hosts * sizeof *hosts);
      free(hosts);
      hosts = nh;
      max_hosts = max;
      syslog(LOG_INFO, "Expanded host table to %d entries\n", max);
    }
  memset(&hosts[num_hosts], 0, sizeof hosts[num_hosts]);
  hosts[num_hosts].lladdr.len = llal;
  hosts[num_hosts].filter_class = -1;	// XXX
  memcpy(hosts[num_hosts].lladdr.data, lladdr, llal);
  hosts[num_hosts].ntes = -1;
  num_hosts++;
  return num_hosts - 1;
}

void
add_nte(address_t *address, unsigned char *lladdr, int llal)
{
  int i;

  if (num_ntes == max_ntes)
    {
      nte_t *nn;
      int max = max_ntes * 2;
      if (max == 0)
	max = 40;
      nn = malloc (max * sizeof *nn);
      if (!nn)
	{
	  syslog(LOG_ERR, "no memory to expand neighbor table.");
	  return;
	}
      memcpy(nn, ntes, num_ntes * sizeof *ntes);
      memset(nn + num_ntes, 0, num_ntes * sizeof *ntes);
      free(ntes);
      ntes = nn;
      max_ntes = max;
      syslog(LOG_INFO, "Expanded neighbor table to %d entries\n", max);
    }
  ntes[num_ntes].cycle = cycle;
  ntes[num_ntes].address = *address;
  i = find_host(lladdr, llal);
  if (i < 0)
    i = add_host(lladdr, llal);
  if (i < 0)
    return;
  ntes[num_ntes].next = hosts[i].ntes;
  ntes[num_ntes].host = i;
  hosts[i].ntes = num_ntes;
  num_ntes++;
  return;
}

nte_t *
fetch_nte(address_t *address)
{
  struct {
    struct nlmsghdr header;
    struct rtgenmsg gen;
  } rtmsg;
    
  int i = find_nte(address);

  // If we already have a cached entry that's not too old, use it.
  if (i >= 0 && cycle - ntes[i].cycle < 90)
    goto have;

  // No such luck, so fetch the neighbor table.

  // The linux kernel currently doesn't support fetching individual
  // neighbor table entries, as far as I can tell.

  // So trigger a fetch of the complete neighbor table for the address
  // family of the address we've been asked to identify.

  memset(&rtmsg, 0, sizeof rtmsg);
  rtmsg.header.nlmsg_type = RTM_GETNEIGH;
  rtmsg.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_MATCH | NLM_F_ROOT;
  rtmsg.header.nlmsg_seq = sequence++;
  rtmsg.header.nlmsg_len = sizeof rtmsg;
  rtmsg.gen.rtgen_family = address->sa.sa_family;

  write(netlink_socket, &rtmsg, sizeof rtmsg);

  // Data should be immediately available to read, and if we don't read
  // it we lose it.
  netlink_read();

  // netlink_read() should have populated the neighbor cache with any
  // IP address from which we have received packets.
  i = find_nte(address);
  if (i < 0)
    return 0;
 have:
  if (ntes[i].host < 0)
    return 0;

  // Check for changes to configuration file.
  host_refresh(ntes[i].host);

  return &ntes[i];
}

void
host_refresh(int hostnum)
{
  char fnbuf[256];
  char *base, *lladdrp;
  char cfline[256];
  FILE *cfile;
  int i, lim;
  host_t *host;
  struct stat stb;
  int found = 0;
  static int once = 1;
  static char *dirs[] = {"/var/state",
			 "/var/state/ndp", "/var/state/ndp/neighbors", 0};

  if (hostnum < 0 || hostnum >= num_hosts)
    {
      syslog(LOG_ERR, "host_refresh: bogus host %d max %d",
	     hostnum, num_hosts);
      return;
    }
  host = &hosts[hostnum];
  
  if (once)
    {
      for (i = 0; dirs[i]; i++)
	{
	  if (stat(dirs[i], &stb) < 0)
	    {
	      if (mkdir(dirs[i], 0755) < 0)
		{
		  syslog(LOG_ERR, "Can't create %s: %m", dirs[i]);
		  return;
		}
	    }
	}
      once = 0;
    }

  strcpy(fnbuf, "/etc/config/ndp/neighbors/");
  lladdrp = fnbuf + strlen(fnbuf);
  sprintf(lladdrp, "%02x", host->lladdr.data[0]);
  base = lladdrp + strlen(lladdrp);
  for (i = 1; i < host->lladdr.len; i++)
    {
      // There needs to be space for this octet plus '/conf\0'.
      if ((base + 11) - &fnbuf[0] > sizeof fnbuf)
	{
	  syslog(LOG_ERR, "host_refresh: fnbuf is too small!");
	  return;
	}
      sprintf(base, ":%02x", host->lladdr.data[i]);
      base += 3;
    }

  // Check to see if we've already determined this isn't a directory.
  if (host->fetched == 1)
    {
      // If we haven't checked in the past five seconds to see if it's fixed,
      // check now.
      if (cycle - host->cycle > 5)
	host->fetched = 0;
      else
	return;
    }

  // See if the directory is there; if not, create it.
  if (!host->fetched)
    {
      if (stat(fnbuf, &stb) < 0)
	{
	  // If we can't create it, we can't look for a conf file in it.
	  if (mkdir(fnbuf, 0700) < 0)
	    goto nofile;
	}

      // If it's not a directory, we can't do much.
      else if (!S_ISDIR(stb.st_mode))
	{
	  syslog(LOG_ERR, "host_refresh: %s is not a directory!", fnbuf);
	  goto nofile;
	}
    }

  // Check for the config file.
  strcpy(base, "/conf");

  // If we've already fetched the configuration, check to see if it's changed.
  if (host->fetched > 1)
    {

      // Stat the file to get its change time; if stat fails, it's not there.
      if (stat(fnbuf, &stb) < 0)
	{
	  if (errno != ENOENT)
	    syslog(LOG_ERR, "host_refresh: stat(%s): %m", fnbuf);
	  goto nofile;
	}

      // If the file hasn't been modified, no need to refresh.
      if (stb.st_ctime <= host->fetched && stb.st_mtime <= host->fetched)
	return;
    }

  cfile = fopen(fnbuf, "r");
  if (!cfile)
    {
      if (errno != ENOENT)
	syslog(LOG_ERR, "host_refresh: can't open %s for read: %m", fnbuf);
      goto nofile;
    }
  
  while (fgets(cfline, sizeof cfline, cfile))
    {
      char *val, *end;

      // If the line was too big for the buffer, it's crap, so just read
      // over it.
      end = strrchr(cfline, '\n');
      if (!end)
	{
	  while (fgets(cfline, sizeof cfline, cfile))
	    if (strrchr(cfline, '\n'))
	      break;
	  continue;
	}
      // Ignore comment lines.
      if (cfline[0] == '#')
	continue;

      *end = 0;
      // Allow for DOS newline (shudder).
      if (end > cfline && end[-1] == '\r')
	*--end = 0;

      // Lines are in the form name=value; if this one isn't, ignore it.
      val = strchr(cfline, '=');
      if (!val)
	continue;
      *val++ = 0;
      // The only configuration value we care about is filter-class.
      printf("%s = %s\n", cfline, val);
      if (!strcmp(cfline, "filter-class"))
	{
	  host->filter_class = fetch_filter_class_id(val);
	  found = 1;
	  break;
	}
    }
  if (!found)
    {
    nofile:
      if (send_mac_as_filter_class)
	{
	  *base = 0;
	  host->filter_class = fetch_filter_class_id(lladdrp);
	}
    }
  else
    {
      host->fetched = cycle;
      fclose(cfile);
    }

  // Now write an updated version of the host state.
  strcpy(fnbuf, "/var/state/ndp/neighbors/");
  lladdrp = fnbuf + strlen(fnbuf);
  sprintf(lladdrp, "%02x", host->lladdr.data[0]);
  base = lladdrp + strlen(lladdrp);
  for (i = 1; i < host->lladdr.len; i++)
    {
      // There needs to be space for this octet plus '\0'.
      if ((base + 5) - &fnbuf[0] > sizeof fnbuf)
	{
	  syslog(LOG_ERR, "host_refresh: fnbuf is too small!");
	  return;
	}
      sprintf(base, ":%02x", host->lladdr.data[i]);
      base += 3;
    }

  cfile = fopen(fnbuf, "w");
  if (cfile == NULL)
    {
      syslog(LOG_ERR, "Can't write host status %s: %m", fnbuf);
      return;
    }

  lim = 0;
  i = host->ntes;
  while (i >= 0 && i < num_ntes && lim < 10)
    {
      char nbuf[128];
      nte_t *nte = &ntes[i];
      if (nte->address.sa.sa_family == AF_INET)
        {
          inet_ntop(AF_INET, &nte->address.in.sin_addr, nbuf, sizeof nbuf);
          fprintf(cfile, "4: %s\n", nbuf);
        }
      else if (nte->address.sa.sa_family == AF_INET6)
        {
          inet_ntop(AF_INET6, &nte->address.in6.sin6_addr, nbuf, sizeof nbuf);
          fprintf(cfile, "6: %s\n", nbuf);
        }
      lim++;
      i = nte->next;
    }
  fprintf(cfile, "l: %lu\n", time(NULL));
  fclose(cfile);
}

int
fetch_filter_class_id(const char *val)
{
  int i;

  for (i = 0; i < num_filter_classes; i++)
    {
      if (!strcmp(filter_classes[i], val))
	return i;
    }
  if (num_filter_classes == max_filter_classes)
    {
      char **nfc;
      int max = max_filter_classes * 2;
      if (max == 0)
	max = 10;
      nfc = malloc (max * sizeof *nfc);
      if (!nfc)
	{
	  syslog(LOG_ERR, "no memory to expand neighbor table.");
	  return -1;
	}
      memcpy(nfc, filter_classes, num_filter_classes * sizeof *filter_classes);
      memset(nfc + num_filter_classes,
	     0, num_filter_classes * sizeof *filter_classes);
      free(filter_classes);
      filter_classes = nfc;
      max_filter_classes = max;
      syslog(LOG_INFO, "Expanded filter class table to %d entries\n", max);
    }
  filter_classes[num_filter_classes] = malloc(strlen(val) + 1);
  if (!val)
    return -1;
  strcpy(filter_classes[num_filter_classes], val);
  num_filter_classes++;
  return num_filter_classes - 1;
}

const char *
fetch_filter_class(int id)
{
  if (id < 0 || id >= num_filter_classes)
    return 0;
  return filter_classes[id];
}

host_t *
fetch_host(int id)
{
  if (id < 0 || id >= num_hosts)
    return 0;
  return &hosts[id];
}

void
dump_ntes()
{
  int i, j, k;
  for (i = 0; i < num_hosts; i++)
    {
      const char *filter_class;
      if (hosts[i].filter_class >= 0)
	filter_class = fetch_filter_class(hosts[i].filter_class);
      else
	filter_class = "<none>";
      printf("Host %d: lladdr = <%02x", i, hosts[i].lladdr.data[0]);
      for (j = 1; j < hosts[i].lladdr.len; j++)
	printf(":%02x", hosts[i].lladdr.data[j]);
      printf(">  filter-class: %s\n", filter_class);
      printf("Addresses:");
      j = hosts[i].ntes;
      k = 0;
      while (j >= 0 && k < 10)
	{
	  char nbuf[128];
	  if (j >= num_ntes)
	    {
	      printf(" [broken: %d]", j);
	      break;
	    }
	  print_address(nbuf, sizeof nbuf, &ntes[j].address);
	  printf(" %s", nbuf);
	  j = ntes[j].next;
	  k++;
	}
      printf("\n");
    }
}

void
print_address(char *buf, size_t size, address_t *address)
{
  if (address->sa.sa_family == AF_INET)
    {
      inet_ntop(AF_INET, &address->in.sin_addr, buf, size);
    }
  else if (address->sa.sa_family == AF_INET6)
    {
      inet_ntop(AF_INET6, &address->in6.sin6_addr, buf, size);
    }
  else
    {
      snprintf(buf, size, "Unknown address family %d",
	       address->sa.sa_family);
    }
}

/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */

