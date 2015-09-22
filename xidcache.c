/* xidcache.c
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

#include "ndp.h"
	     
/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */
