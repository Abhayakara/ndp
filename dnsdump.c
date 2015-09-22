/* dnsdump.c
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
#include <poll.h>

#include "ndp.h"
	     
const char *opcode_names[16] = {"QUERY", "IQUERY", "STATUS",
				"(reserved)", "NOTIFY", "UPDATE",
				"(reserved)", "(reserved)", "(reserved)",
				"(reserved)", "(reserved)", "(reserved)",
				"(reserved)", "(reserved)", "(reserved)",
				"(reserved)"};
const char *rcode_names[16] = {"NOERROR", "FORMERR", "SERVFAIL", "NAMERR",
			       "NOTIMP", "REFUSED", "(reserved)", "(reserved)",
			       "(reserved)", "(reserved)", "(reserved)",
			       "(reserved)", "(reserved)", "(reserved)",
			       "(reserved)", "(reserved)"};

int
query_dump(unsigned char *buf, ssize_t len)
{
  int count, i, j;
  int offset = 12;
  char namebuf[512];
  int result;
  int type, class;

  printf("id %d  qr %d  opcode %s\n"
	 "  aa %d  tc %d  rd %d  ra %d  z %d  rcode %s\n",
	 ID(buf), QR(buf), OPCODENAME(buf), AA(buf), TC(buf),
	 RD(buf), RA(buf), Z(buf), RCODENAME(buf));
  
  count = QDCOUNT(buf);
  for (i = 0; i < count; i++)
    {
      offset = parse_name(namebuf, sizeof namebuf, buf, offset, len);
      if (offset < 0)
	return offset;
      if (offset + 4 > len)
	{
	  printf("malformed DNS packet in questions: too short: %d %ld\n",
		 offset, (long)len);
	  return -1; // Format error
	}
      type = (buf[offset] << 8) | buf[offset + 1];
      class = (buf[offset + 2] << 8) | buf[offset + 3];
      printf("%s %s ", namebuf, classname(class));
      result = dump_rrdata(class, type, 0, 0, 0, 0, 0);
      if (result < 0)
	return result;
      offset += 4;
    }
  for (j = 0; j < 3; j++)
    {
      const char *section;
      switch(j)
	{
	case 0:
	  count = ANCOUNT(buf);
	  section = "answer";
	  break;
	case 1:
	  count = NSCOUNT(buf);
	  section = "nameserver";
	  break;
	case 2:
	  count = ARCOUNT(buf);
	  section = "additional";
	  break;
	}
      for (i = 0; i < count; i++)
	{
	  int ttl, rdlength;
	  offset = parse_name(namebuf, sizeof namebuf, buf, offset, len);
	  if (offset < 0)
	    return offset;
	  if (offset + 10 > len)
	    {
	      printf(" malformed DNS packet in %s: too short: %d %ld\n",
		     section, offset, (long)len);
	      return -1; // Format error
	    }
	  type = (buf[offset] << 8) | buf[offset + 1];
	  class = (buf[offset + 2] << 8) | buf[offset + 3];
	  ttl = ((buf[offset + 4] << 24) | (buf[offset + 5] << 16) |
		 (buf[offset + 6] << 8) | buf[offset + 7]);
	  rdlength = (buf[offset + 8] << 8) | buf[offset + 9];
	  if (offset + 10 + rdlength > len)
	    {
	      printf(" bad DNS packet in %s: rdlength too short: %d %ld\n",
		     section, offset + 10 + rdlength, (long)len);
	      return -1; // Format error
	    }
	  printf("%s ", namebuf);
	  result = dump_rrdata(class, type, ttl,
			       offset + 10, rdlength, buf, len);
	  if (result < 0)
	    return result;
	  offset += 10 + rdlength;
	}      
    }
  return offset;
}

const char *
classname(int class)
{
  if (class == 1)
    return "IN";
  else if (class == 3)
    return "CH";
  else if (class == 4)
    return "HS";
  else if (class == 0xFE)
    return "NO";
  else if (class == 0xFF)
    return "AY";
  else if (class > 0xFF00 && class < 0xFFFF)
    return "PV";
  else if (class == 0 || class == 0xFFFF)
    return "RV";
  else
    return "UN";
}

int
dump_rrdata(int class, int type, int ttl, int offset, ssize_t len,
	    const unsigned char *message, ssize_t max)
{
  char buf[512];
  int i;
  struct in_addr in;
  struct in6_addr in6;
  const char *space = " ";
  const unsigned char *data = &message[offset];

  /* TTL has special meaning for OPT RRtype */
  if (message && type != 41)
    printf("%s %d ", classname(class), ttl);

  switch(type)
    {
    case 1:
      printf("A");
      if (message)
	{
	  if (len != 4)
	    {
	      printf(" malformed IPv4addr RDATA: wrong length (%ld)\n",
		     (long)len);
	      return -1; // Format error
	    }
	  memcpy(&in, data, 4);
	  inet_ntop(AF_INET, &in, buf, sizeof buf);
	  printf(" %s", buf);
	}
      break;
    case 2:
      printf("NS");
    name:
      if (message)
	{
	  i = parse_name(buf, sizeof buf, message, data - message, max);
	  if (i < 0 || i != len + (data - message))
	    {
	      printf(" malformed domain name RDATA: (%d %ld)\n", i, (long)len);
	      return -1; // Format error
	    }
	  printf(" %s", buf);
	}
      break;
    case 5:
      printf("CNAME");
      goto name;
    case 12:
      printf("PTR");
      goto name;

    case 28:
      printf("AAAA");
      if (message)
	{
	  if (len != 16)
	    {
	      printf(" malformed IPv6addr RDATA: wrong length (%ld)\n",
		     (long)len);
	      return -1; // Format error
	    }
	  memcpy(&in6, data, 16);
	  inet_ntop(AF_INET6, &in6, buf, sizeof buf);
	  printf(" %s", buf);
	}
      break;
    case 41:
      printf("OPT psiz %d  xrcode %d  version %d  DO %d  z %x\n",
	     class, ttl >> 24,
	     (ttl & 0xff0000) >> 16, (ttl & 0x8000) >> 15, ttl & 0x7fff);
      if (message)
	{
	  i = 0;
	  while (i < len)
	    {
	      int optype, oplen, j;
	      const char *space = " ";
	      if (i + 4 >= len)
		{
		  printf(" malformed EDNS0 option at %d", i);
		  return -1; // Format error
		}
	      optype = (data[i] << 8) | data[i + 1];
	      oplen = (data[i + 2] << 8) | data[i + 3];
	      if (i + 4 + oplen != len)
		{
		  printf(" bad EDNS0 option length at %d, type %d, len %d, "
			 "max %ld\n", i, optype, oplen, (long)len);
		  return -1; // Format error
		}
	      printf(" <%d", optype);
	      for (j = 0; j < oplen; j++)
		{
		  printf("%s%02x", space, data[i + 4 + j]);
		  space = ":";
		}
	      space = " ";
	      printf(">");
	      i += 4 + oplen;
	    }
	}
      break;
    default:
      printf("%d {rrtype %d ", ttl, type);
      if (message)
	{
	  for (i = 0; i < len; i++)
	    {
	      printf("%s%02x", space, data[i]);
	      space = ":";
	    }
	}
      printf("}");
    }
  if (message)
    printf("\n");
  else
    printf("?\n");
  return 0;
}

/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */
