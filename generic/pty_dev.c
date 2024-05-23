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
 * $Id: pty_dev.c,v 1.4.2.2 2008/01/07 22:36:13 mtbishop Exp $
 */ 
/* Althought differing from documentation, this is necessary to have
 * posix_openpt in GNU libc */
#define _XOPEN_SOURCE 600
#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include <pty.h>

#include "vtun.h"
#include "lib.h"

/* 
 * Allocate pseudo tty, returns master side fd. 
 * Stores slave name in the first arg(must be large enough).
 */  
int pty_open(char *sl_name)
{
    int  mr_fd;
#if defined (HAVE_POSIX_OPENPT) && defined (HAVE_GRANTPT) && defined (HAVE_UNLOCKPT) && defined (HAVE_PTSNAME)
    char *ptyname;

    if((mr_fd=posix_openpt(O_RDWR|O_NOCTTY)) < 0)
 	return -1;
    if(grantpt(mr_fd) != 0)
	return -1;
    if(unlockpt(mr_fd) != 0)
	return -1;
    if ((ptyname = (char*)ptsname(mr_fd)) == NULL)
	return -1;
    strcpy(sl_name, ptyname);
    return mr_fd;

#else

    char ptyname[1024];
    int  l, m;
    int master, slave;

    /* This algorithm works for UNIX98 PTS */	

    /* Open the master */
    mr_fd = openpty(&master, &slave, ptyname, NULL, NULL);
    if (mr_fd == -1)
    {
      printf("error open pty");
      return -1;
    }
    else
    {
		/* Check the slave */
		if( (access(ptyname, R_OK | W_OK)) < 0 ){
		   /* close(mr_fd); */
		   return -1;
		}
		strcpy(sl_name,ptyname);
		return master;
   }
#endif
}

/* Write frames to PTY device */
int pty_write(int fd, char *buf, int len)
{
    return write_n(fd, buf, len);
}

/* Read frames from PTY device */
int pty_read(int fd, char *buf, int len)
{
    return read(fd, buf, len);
}
