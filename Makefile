CFLAGS=-g -O0 -Wall -Werror

ndp:	ndp.o netlink.o neighbor.o dnspacket.o dnsdump.o 

ndp.o:	ndp.c ndp.h
netlink.o:	netlink.c ndp.h
neighbor.o:	neighbor.c ndp.h
dnspacket.o:	dnspacket.c ndp.h
dnsdump.o:	dnsdump.c ndp.h
