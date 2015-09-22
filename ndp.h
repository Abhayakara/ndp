/* ndp.h
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

#define LLADDR_MAXLEN	16	// Too short?   Make it longer!
typedef struct lladdr {
  char len;
  unsigned char data[LLADDR_MAXLEN];
} lladdr_t;

typedef union {
    struct sockaddr sa;
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
} address_t;

typedef struct host host_t;
typedef struct nte {
  int next;
  int host;
  address_t address;
  time_t cycle;
} nte_t ;

struct host {
  lladdr_t lladdr;	// we identify hosts by lladdr
  int filter_class;	// Each host is in a filter class.
  int ntes;		// IP addresses we are aware of for this host.
  time_t fetched;	// When we last fetched the config file for this host.
  time_t cycle;		// Last time we checked.
};

#if 0
/* xid cache entry: all the data we need on a particular transaction. */
typedef struct xid_cache_entry {
  struct xid_cache_entry *next;		/* Time-sorted list. */
  struct xid_cache_entry *next_bucket;	/* In case of duplicates. */
  time_t last_transmission;
  int socket;
  lladdr_t *lladdr;
  address_t source;
  question_t question;
} xid_cache_entry_t;
#endif

typedef struct interface {
  struct interface *next;
  char *name;
  int index;
  int numaddrs, maxaddrs;
  address_t **addresses;
  int excluded;
} interface_t;

typedef struct nameserver {
  struct nameserver *next;
  address_t address;
  int nqueries[5];
  int ncomplete[5];
  int ndropped[5];
} nameserver_t;

typedef struct query {
  struct query *next;
  nameserver_t *cur_nameserver;
  int host;		// host data structure associated with this query
  int xid;		// transaction id for this query
  time_t cycle;
  int socket;
  address_t src;
  socklen_t srclen;
  ssize_t qlength;
  ssize_t qmax;
  int optptr;
  int optdata;
  int optlen;
  int added_edns0;
  unsigned char query[1];
} query_t;

/* ndp.c */
extern int exclude_default_route;
extern interface_t *interfaces;
extern time_t cycle;
int response_read(query_t *query);
void query_read(int family, int sock);
int add_query(query_t *query);
query_t *query_allocate(const unsigned char *buf, ssize_t len);

/* dnspacket.c */
int query_parse(query_t *query, unsigned char *buf, ssize_t len);

int parse_name(char *namebuf, int max,
	       const unsigned char *buf, int offset, ssize_t len);
int add_opt_id(query_t *query, const char *id, int len);
int drop_edns0(query_t *query, int added_edns0);

/* dnsdump.c */
const char *classname(int class);
int query_dump(unsigned char *buf, ssize_t len);
int dump_rrdata(int class, int type, int ttl, int offset, ssize_t len,
		const unsigned char *message, ssize_t max);

/* netlink.c */
extern int netlink_socket;
extern int sequence;

void netlink_setup(void);
void netlink_input(void);
void netlink_read(void);

/* neighbor.c */
nte_t *fetch_nte(address_t *address);
int add_host(unsigned char *lladdr, int llal);
void add_nte(address_t *address, unsigned char *lladdr, int llal);
void host_refresh(int hostnum);
int fetch_filter_class_id(const char *val);
const char *fetch_filter_class(int id);
host_t *fetch_host(int id);
void dump_ntes();
void print_address(char *buf, size_t size, address_t *address);

#define ID(buf) (((buf)[0] << 8) | ((buf)[1]))
#define QR(buf) ((buf)[2] >> 7)
#define OPCODE(buf) (((buf)[2] & 0x78) >> 3)
#define OPCODENAME(buf) (opcode_names[OPCODE(buf)])
#define AA(buf) (((buf)[2] & 4) >> 2)
#define TC(buf) (((buf)[2] & 2) >> 1)
#define RD(buf) ((buf)[2] & 1)
#define RA(buf) ((buf)[3] >> 7)
#define Z(buf)	(((buf)[3] & 0xE0) >> 4)
#define RCODE(buf) ((buf)[3] & 15)
#define SET_RCODE(buf, rcode) ((buf)[3] = ((buf)[3] & ~15) | ((rcode) & 15))
#define SET_QR(buf, val) ((buf)[2] = ((buf)[2] & 0x7f) | ((val) ? 0x80 : 0))
#define RCODENAME(buf) (rcode_names[RCODE(buf)])
#define QDCOUNT(buf) (((buf)[4] >> 8) | (buf)[5])
#define ANCOUNT(buf) (((buf)[6] >> 8) | (buf)[7])
#define NSCOUNT(buf) (((buf)[8] >> 8) | (buf)[9])
#define ARCOUNT(buf) (((buf)[10] >> 8) | (buf)[11])

// DNS RCODE values
#define FORMERR		1
#define SERVFAIL	2
#define NOTIMPL		4
#define REFUSED		5

// OPT codes we care about (actually just the one)
#define OPT_NOMDEVICEID	65073

// Might want to override this...
#if !defined(RESOLV_CONF_NAME)
# define RESOLV_CONF_NAME "/tmp/resolv.conf.auto"
#endif

/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */
