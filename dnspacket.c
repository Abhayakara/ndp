/* dnspacket.c
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
	     
int
query_parse(query_t *query, unsigned char *buf, ssize_t len)
{
  int count, i, j;
  int offset = 12;
  int type;

  // Validate the question section.
  count = QDCOUNT(buf);
  for (i = 0; i < count; i++)
    {
      offset = parse_name(0, 0, buf, offset, len);
      if (offset < 0)
	return offset;
      if (offset + 4 > len)
	{
	  syslog(LOG_DEBUG,
		  "malformed DNS packet in questions: too short: %d %ld\n",
		  offset, (long)len);
	  return -FORMERR; // Format error
	}
#if 0 // might need later.
      type = (buf[offset] << 8) | buf[offset + 1];
      class = (buf[offset + 2] << 8) | buf[offset + 3];
#endif
      offset += 4;
    }

  // Validate the other sections, and look for an OPT RR.
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
	  int rdlength, np;
	  np = offset;
	  offset = parse_name(0, 0, buf, offset, len);
	  if (offset < 0)
	    return offset;
	  if (offset + 10 > len)
	    {
	      syslog(LOG_DEBUG,
		      "malformed DNS packet in %s: too short: %d %ld\n",
		     section, offset, (long)len);
	      return -FORMERR; // Format error
	    }
	  type = (buf[offset] << 8) | buf[offset + 1];
#if 0 // might need later
	  class = (buf[offset + 2] << 8) | buf[offset + 3];
	  ttl = ((buf[offset + 4] << 24) | (buf[offset + 5] << 16) |
		 (buf[offset + 6] << 8) | buf[offset + 7]);
#endif
	  rdlength = (buf[offset + 8] << 8) | buf[offset + 9];
	  if (offset + 10 + rdlength > len)
	    {
	      syslog(LOG_DEBUG,
		      "bad DNS packet in %s: rdlength too short: %d %ld\n",
		     section, offset + 10 + rdlength, (long)len);
	      return -FORMERR; // Format error
	    }

	  if (type == 41)
	    {
	      // We should never see an OPT RR outside the additional section.
	      if (j != 2)
		{
	          syslog(LOG_DEBUG,
			 "bad DNS packet in %s: OPT in section %d\n",
			 section, j);
		  return -FORMERR;
		}
	      // Only one OPT RR is allowed.
	      if (query)
		{
		  if (query->optptr)
		    {
	              syslog(LOG_DEBUG,
			     "bad DNS packet in %s: duplicate OPT RR\n",
			     section);
		      return -FORMERR;
		    }
		  query->optptr = np;
		  query->optdata = offset;
		  query->optlen = 10 + rdlength + (offset - np);
		}
	    }
	  else
	    // We can't handle TSIG queries.
	    if (type == 250 && query)
	      {
		// If the TSIG RR isn't at the end of the additional
		// section, return FORMERR.
		if (j != 2 || offset + 10 + rdlength != query->qlength)
		  {
	            syslog(LOG_DEBUG,
			   "bad DNS packet in %s: duplicate OPT RR\n", section);
		    return -FORMERR;
		  }
		// Otherwise, hack the TSIG on the query to generate
		// the response; we have to set the length of the MAC
		// to 0 and set the response to BADKEY, and then return
		// NOTAUTH as the RCODE.
		// However, right now we're going to be lame and just
		// return REFUSED.
		return -REFUSED;
	      }
	    else
	      // We can't handle SIG(0) queries.
	      if (type == 24 && query)
		{
		  // RFC 2931 does not require SIG(0) to be at the end
		  // of the message, but is a bit vague about what it means
		  // for a SIG(0) to appear anywhere else.   We just refuse
		  // any message containing a SIG(0) for now.
		  return -REFUSED;
		}
	  offset += 10 + rdlength;
	}      
    }
  if (query)
    query->xid = ID(buf);
  return offset;
}

int
parse_name(char *namebuf, int max,
	   const unsigned char *buf, int offset, ssize_t len)
{
  int dp, sp;
  int status;
  int pointer;

  dp = 0;
  sp = offset;

  /* Naked root label. */ 
  if (buf[sp] == 0)
    {
      if (namebuf)
	{
	  namebuf[0] = '.';
	  namebuf[1] = 0;
	}
      return sp + 1;
    }

  while (!namebuf || dp < max)
    {
      switch(buf[sp] & 0xc0)
	{
	  // normal label
	case 0:
	  if (sp + buf[sp] > len)
	    {
	      syslog(LOG_DEBUG, "parse_name: label longer than message.\n");
	      return -FORMERR; // Format error
	    }
	  if (namebuf && dp + buf[sp] + 1 > max)
	    {
	      syslog(LOG_DEBUG, "parse_name: buffer full in normal label.\n");
	      return -FORMERR; // Format error
	    }
	  if (buf[sp] && namebuf)
	    {
	      memcpy(&namebuf[dp], &buf[sp + 1], buf[sp]);
	      dp += buf[sp];
	    }
	  if (!buf[sp])
	    {
	      if (namebuf)
		namebuf[dp++] = 0;
	      return sp + 1;
	    }
	  if (namebuf)
	    namebuf[dp++] = '.';
	  sp = sp + buf[sp] + 1;
	  break;

	  // compressed label
	case 0xc0:
	  pointer = ((buf[sp] & 63) << 8) | buf[sp + 1];
	  if (pointer > len)
	    {
	      syslog(LOG_DEBUG, "parse_name: pointer outside of message.\n");
	      return -FORMERR; // Format error
	    }
	  if (namebuf)
	    status = parse_name(&namebuf[dp], max - dp, buf, pointer, len);
	  else
	    status = parse_name(0, 0, buf, pointer, len);
	  if (status < 0)
	    return status;
	  return sp + 2;

	  // extended label
	case 0x40:
	  syslog(LOG_DEBUG, "parse_name: unsupported label type 01 seen.\n");
	  return -NOTIMPL; // Not implemented

	  // unassigned
	case 0x80:
	  syslog(LOG_DEBUG, "parse_name: unsupported label type 10 seen.\n");
	  return -NOTIMPL; // Not implemented
	}
    }
  syslog(LOG_DEBUG, "parse_name: full buffer suggests malicious packet.\n");
  return -FORMERR; // Format error
}

int
add_opt_id(query_t *query, const char *id, int len)
{
  int rdlen;
  int offset;

  // If there is an OPT RR, see if it's at the end of the additional
  // section; if not, move it there.
  if (query->optptr && query->optptr + query->optlen != query->qlength)
    {
      int gap;
      // Make a copy of the OPT RR
      unsigned char *tmpopt = malloc(query->optlen);
      if (!tmpopt)
	{
	  syslog(LOG_ERR, "no memory for OPT copy\n");
	  return -SERVFAIL; // SERVFAIL
	}
      // Space consumed by options following OPT.
      gap = query->qlength - query->optptr - query->optlen;
      // Copy OPT into temporary buffer.
      memcpy(tmpopt, &query->query[query->optptr], query->optlen);
      // Move remaining options down to where OPT was.
      memmove(&query->query[query->optptr],
	      &query->query[query->optptr + query->optlen], gap);
      // Now store OPT at the end of those data.
      query->optptr += gap;
      memcpy(&query->query[query->optptr], tmpopt, query->optlen);
      free(tmpopt);
    }

  // If we already have an OPT record, add some data.
  if (query->optlen)
    {
      // Make sure we saved enough space.
      if (query->qlength + 4 + len > query->qmax)
	{
	  syslog(LOG_DEBUG, "Not enough space for ID option");
	  return -SERVFAIL; // SERVFAIL
	}

      // Add the 4 bytes of header, the length of the identifier and
      // a byte for the user ID code to the existing rdlength.
      rdlen = ((query->query[query->optdata + 8] << 8) |
	       query->query[query->optdata + 9]) + len + 4;

      // Find the end of the current data.
      offset = query->optlen + query->optptr;
    }
  else
    {
      int arcount;

      query->added_edns0 = 1;

      // Make sure we saved enough space.
      // len('.') + fixed RRDATA + option header + hint type + len
      if (query->qlength + 1 + 10 + 4 + len > query->qmax)
	{
	  syslog(LOG_DEBUG, "Not enough space for EDNS0 RRset");
	  return -SERVFAIL; // SERVFAIL
	}

      rdlen = len + 4;

      // We're adding an additional data section rrset, so increment adcount.
      arcount = ARCOUNT(query->query);
      arcount++;
      query->query[10] = (arcount & 0xff00) >> 8;
      query->query[11] = arcount & 0xff;

      // Put in the OPT RR name (.)
      offset = query->qlength;
      query->optptr = offset;
      query->query[offset++] = 0;

      // Put in the fixed RRtype data header
      query->optdata = offset;
      // type
      query->query[offset++] = 0; // (49 >> 8) & 0xff
      query->query[offset++] = 41; // 49 & 0xff
      // UDP payload size (class)
      // Payload size is 512 because the client doesn't actually support
      // EDNS0, so we can't accept a large answer.   Client is lame, needs
      // fixed.
      query->query[offset++] = 2; // (512 >> 8) & 0xff
      query->query[offset++] = 0; // 512 & 0xff
      // TTL
      query->query[offset++] = 0;
      query->query[offset++] = 0;
      query->query[offset++] = 0;
      query->query[offset++] = 0;
      // rdlength
      offset += 2;
    }

  // Update rdlength
  query->query[query->optdata + 8] = (rdlen & 0xff00) >> 8;
  query->query[query->optdata + 9] = rdlen & 0xff;

  // Nominum NOMDEVICEID OPT type
  query->query[offset++] = (OPT_NOMDEVICEID >> 8) & 0xff;
  query->query[offset++] = OPT_NOMDEVICEID & 0xff;
  
  // OPT option length
  query->query[offset++] = (len >> 8) & 0xff;
  query->query[offset++] = len & 0xff;

  // Copy in the id.
  memcpy(&query->query[offset], id, len);
  offset += len;

  // Update the lengths.
  query->optlen = offset - query->qlength;
  query->qlength = offset;
  return 0;
}

int
drop_edns0(query_t *query, int added_edns0)
{
  // If there is no EDNS0 option on the return, that's weird, but for now
  // we just ignore it.   It's allowed for a name server to ignore the
  // OPT RR, since it's an extension, but _our_ name server should never
  // ignore it.
  if (!query->optptr)
    return 0;

  // If we added the OPT RR on the way out, we can just delete it on the
  // way back, which is comparatively easy.
  if (added_edns0)
    {
      int arcount, gap;

      // Decrement ARCOUNT (should be >0)
      arcount = ARCOUNT(query->query);
      arcount--;
      if (arcount < 0)
	{
	  syslog(LOG_DEBUG, "edns0 option present, arcount <0?");
	  return -FORMERR;
	}
      query->query[10] = (arcount & 0xff00) >> 8;
      query->query[11] = arcount & 0xff;

      // If the OPT RR was at the end of the additional data, just
      // shorten the length of the query data and return.
      if (query->optptr + query->optlen == query->qlength)
	{
	  query->qlength = query->optptr;
	zero:
	  query->optptr = 0;
	  query->optdata = 0;
	  query->optlen = 0;
	  return 0;
	}

      // No such luck.   Copy down what follows.
      // Move remaining options down to where OPT was.
      gap = query->qlength - query->optptr - query->optlen;
      memmove(&query->query[query->optptr],
	      &query->query[query->optptr + query->optlen], gap);
      query->qlength -= query->optlen;
      goto zero;
    }

  // Otherwise, the client sent an EDNS0 OPT RR, but we added our own
  // option to it.  In production, we probably need to make sure we
  // don't return that option back to the client, but in principle an
  // unknown OPT option is harmless, so for now we do nothing.
  return 0;
}

/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */
