/*  
    VTun - Virtual Tunnel over TCP/IP network.

    Copyright (C) 1998-2008  Maxim Krasnyansky <max_mk@yahoo.com>

    VTun has been derived from VPPP package by Maxim Krasnyansky. 

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 */

/*
 * $Id: netlib.c,v 1.11.2.4 2009/03/29 10:44:02 mtbishop Exp $
 */ 

#include "config.h"
#include "vtun_socks.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include <ifaddrs.h>

#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include "vtun.h"
#include "lib.h"
#include "netlib.h"

/* Connect with timeout */
int connect_t(int s, struct sockaddr *svr, time_t timeout) 
{
#if defined(VTUN_SOCKS) && VTUN_SOCKS == 2
     /* Some SOCKS implementations don't support
      * non blocking connect */
     return connect(s,svr,sizeof(struct sockaddr_storage));
#else
     int sock_flags;
     fd_set fdset;
     struct timeval tv;

     tv.tv_usec=0; tv.tv_sec=timeout;

     sock_flags=fcntl(s,F_GETFL);
     if( fcntl(s,F_SETFL,O_NONBLOCK) < 0 )
        return -1;

     if( connect(s,svr,sizeof(struct sockaddr_storage)) < 0 && errno != EINPROGRESS)
        return -1;

     FD_ZERO(&fdset);
     FD_SET(s,&fdset);
     if( select(s+1,NULL,&fdset,NULL,timeout?&tv:NULL) > 0 ){
        socklen_t l=sizeof(errno);	 
        errno=0;
        getsockopt(s,SOL_SOCKET,SO_ERROR,&errno,&l);
     } else
        errno=ETIMEDOUT;  	

     fcntl(s,F_SETFL,sock_flags); 

     if( errno )
        return -1;

     return 0;
#endif
}

/* Get port number, independently of address family. */
in_port_t get_port(struct sockaddr_storage *addr)
{
	switch (addr->ss_family) {
		case AF_INET6:
			return ntohs(((struct sockaddr_in6 *) addr)->sin6_port);
			break;
		case AF_INET:
			return ntohs(((struct sockaddr_in *) addr)->sin_port);
			break;
		default:
			return 0;
	}
} /* get_port(struct sockaddr_storage *) */

/* Set port number, independently of address family. */
void set_port(struct sockaddr_storage *addr, in_port_t port)
{
	switch (addr->ss_family) {
		case AF_INET6:
			((struct sockaddr_in6 *) addr)->sin6_port = htons(port);
			break;
		case AF_INET:
			((struct sockaddr_in *) addr)->sin_port = htons(port);
		default:
			break;
	}
} /* set_port(struct sockaddr_storage *, in_port_t) */

/* Get interface address */
int getifaddr(struct sockaddr_storage *addr, char * ifname, sa_family_t af) 
{
     struct ifaddrs *ifas, *ifa;

     if( getifaddrs(&ifas) < 0 )
        return -1;

     for (ifa = ifas; ifa; ifa = ifa->ifa_next) {
        if( ifa->ifa_addr->sa_family != af ||
               strcmp(ifname, ifa->ifa_name) )
           continue;

        /* Correct address family and interface name!
         * Locate a useful candidate. */

        /* For IPv4, the first address works. */
        if( (ifa->ifa_addr->sa_family == AF_INET) &&
               (ifa->ifa_flags & IFF_UP) )
           break; /* Good address. */

        /* IPv6 needs some obvious exceptions. */
        if( ifa->ifa_addr->sa_family == AF_INET6 ) {
           if( IN6_IS_ADDR_LINKLOCAL(&((struct sockaddr_in6 *) addr)->sin6_addr.s6_addr)
              || IN6_IS_ADDR_SITELOCAL(&((struct sockaddr_in6 *) addr)->sin6_addr.s6_addr) )
              continue;
           else
              /* Successful search at this point, which
               * only standard IPv6 can reach. */
              break;
        }
     }

     if( ifa == NULL ) {
        freeifaddrs(ifas);
        return -1;
     }

     /* Copy the found address. */
     memcpy(addr, ifa->ifa_addr, sizeof(*addr));
     freeifaddrs(ifas);

     return 0;
}

/* 
 * Establish UDP session with host connected to fd(socket).
 * Returns connected UDP socket or -1 on error.
 */
int udp_session(struct vtun_host *host) 
{
     struct sockaddr_storage saddr; 
     short port;
     int s;
     socklen_t opt;
     extern int is_rmt_fd_connected;

     /* Set local address and port */
     local_addr(&saddr, host, 1);

     if( (s=socket(saddr.ss_family,SOCK_DGRAM,0))== -1 ){
        vtun_syslog(LOG_ERR,"Can't create socket");
        return -1;
     }

     opt=1;
     setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)); 
    
     if( bind(s,(struct sockaddr *)&saddr,sizeof(saddr)) ){
        vtun_syslog(LOG_ERR,"Can't bind to the socket");
        return -1;
     }

     opt = sizeof(saddr);
     if( getsockname(s,(struct sockaddr *)&saddr,&opt) ){
        vtun_syslog(LOG_ERR,"Can't get socket name");
        return -1;
     }

     /* Write port of the new UDP socket */
     port = get_port(&saddr);
     if( write_n(host->rmt_fd,(char *)&port,sizeof(short)) < 0 ){
        vtun_syslog(LOG_ERR,"Can't write port number");
        return -1;
     }
     host->sopt.lport = htons(port);

     /* Read port of the other's end UDP socket */
     if( readn_t(host->rmt_fd,&port,sizeof(short),host->timeout) < 0 ){
        vtun_syslog(LOG_ERR,"Can't read port number %s", strerror(errno));
        return -1;
     }

     opt = sizeof(saddr);
     if( getpeername(host->rmt_fd,(struct sockaddr *)&saddr,&opt) ){
        vtun_syslog(LOG_ERR,"Can't get peer name");
        return -1;
     }

     set_port(&saddr, port);

     /* if the config says to delay the UDP connection, we wait for an
	incoming packet and then force a connection back.  We need to
	put this here because we need to keep that incoming triggering
	packet and pass it back up the chain. */

     if (VTUN_USE_NAT_HACK(host))
     	is_rmt_fd_connected=0;
	else {
     if( connect(s,(struct sockaddr *)&saddr,sizeof(saddr)) ){
        vtun_syslog(LOG_ERR,"Can't connect socket");
        return -1;
     }
     is_rmt_fd_connected=1;
	}
     
     host->sopt.rport = htons(port);

     /* Close TCP socket and replace with UDP socket */	
     close(host->rmt_fd); 
     host->rmt_fd = s;	

     vtun_syslog(LOG_INFO,"UDP connection initialized");
     return s;
}

/* Set local address */
int local_addr(struct sockaddr_storage *addr, struct vtun_host *host, int con)
{
     socklen_t opt;
     char *ip = (char *) calloc(INET6_ADDRSTRLEN, sizeof(char));

     memset(addr, '\0', sizeof(*addr));

     if( con ){
        /* Use address of the already connected socket. */
        opt = sizeof(*addr);
        if( getsockname(host->rmt_fd, (struct sockaddr *)addr, &opt) < 0 ){
           vtun_syslog(LOG_ERR,"Can't get local socket address");
           return -1; 
        }
     } else {
        addr->ss_family = vtun.transport_af;
        if (generic_addr(addr, &host->src_addr) < 0)
                 return -1;
              }

     getnameinfo((struct sockaddr *) addr, sizeof(*addr),
		 ip, INET6_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST);
     host->sopt.laddr = ip;

     return 0;
}

int server_addr(struct sockaddr_storage *addr, struct vtun_host *host)
{
     struct addrinfo hints, *aiptr;
     char *ip, portstr[12];

     ip = (char *) calloc(INET6_ADDRSTRLEN, sizeof(char));

     memset(addr, '\0', sizeof(*addr));

     memset(&hints, '\0', sizeof(hints));
     hints.ai_family = vtun.transport_af;
     hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;

     snprintf(portstr, sizeof(portstr), "%u", vtun.bind_addr.port);

     /* Lookup server's IP address.
      * We do it on every reconnect because server's IP 
      * address can be dynamic.
      */
     if (getaddrinfo(vtun.svr_name, portstr, &hints, &aiptr)) {
         vtun_syslog(LOG_ERR, "Can't resolv server address: %s", vtun.svr_name);
         return -1;
     }

     memcpy(addr, aiptr->ai_addr, aiptr->ai_addrlen);
     freeaddrinfo(aiptr);
     getnameinfo((struct sockaddr *) addr, sizeof(*addr),
		 ip, INET6_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST);
     host->sopt.raddr = ip;
     host->sopt.rport = vtun.bind_addr.port;

     return 0; 
}

/* Set address by interface name, ip address or hostname */
int generic_addr(struct sockaddr_storage *addr, struct vtun_addr *vaddr)
{
     sa_family_t use_af = addr->ss_family;
     struct addrinfo hints, *aiptr;

     memset(addr, '\0', sizeof(*addr)); /* Implicitly setting INADDR_ANY. */
     memset(&hints, '\0', sizeof(hints));
  
     switch (vaddr->type) {
        case VTUN_ADDR_IFACE:
            if (getifaddr(addr, vaddr->name, use_af)) {
		vtun_syslog(LOG_ERR, "Can't get address of interface %s", vaddr->name);
		return -1;
            }
	    break;
        case VTUN_ADDR_NAME:
	    memset(&hints, '\0', sizeof(hints));
	    hints.ai_family = use_af;
	    hints.ai_flags = AI_ADDRCONFIG;

	    if (getaddrinfo(vaddr->name, NULL, &hints, &aiptr)) {
		vtun_syslog(LOG_ERR, "Can't resolv local address %s", vaddr->name);
		return -1;
	    }
	    memcpy(addr, aiptr->ai_addr, aiptr->ai_addrlen);
	    freeaddrinfo(aiptr);
	    break;
	default:
	    /* INADDR_ANY has already been implicitly set, when erasing. */
	    addr->ss_family = use_af;
            break;
     }
  
     if (vaddr->port)
        set_port(addr, vaddr->port);

     return 0; 
}
