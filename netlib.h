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
 * $Id: netlib.h,v 1.5.2.2 2008/01/07 22:35:58 mtbishop Exp $
 */ 

#ifndef _VTUN_NETDEV_H
#define _VTUN_NETDEV_H

#include "config.h"
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

int getifaddr(struct sockaddr_storage *addr, char * ifname, sa_family_t af);
int connect_t(int s, struct sockaddr *svr, time_t timeout); 
int udp_session(struct vtun_host *host); 

int local_addr(struct sockaddr_storage *addr, struct vtun_host *host, int con);
int server_addr(struct sockaddr_storage *addr, struct vtun_host *host);
int generic_addr(struct sockaddr_storage *addr, struct vtun_addr *vaddr);
in_port_t get_port(struct sockaddr_storage *addr);
void set_port(struct sockaddr_storage *addr, in_port_t port);

#endif /* _VTUN_NETDEV_H */
