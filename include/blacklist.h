/*
 *  charybdis: A slightly useful ircd.
 *  blacklist.h: Manages DNS blacklist entries and lookups
 *
 *  Copyright (C) 2006 charybdis development team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 *  $Id: blacklist.h 1463 2006-05-26 21:25:28Z jilles $
 */

#ifndef _BLACKLIST_H_
#define _BLACKLIST_H_

struct Blacklist {
	unsigned int status;	/* If CONF_ILLEGAL, delete when no clients */
	int refcount;
	char host[HOSTLEN];
	char reject_reason[IRCD_BUFSIZE];
	unsigned int hits;
};

struct BlacklistClient {
	struct Blacklist *blacklist;
	struct Client *client_p;
	struct DNSQuery *dns_query;
};

/* public interfaces */
struct Blacklist *new_blacklist(char *host, char *reject_entry);
void lookup_blacklists(struct Client *client_p);
void unref_blacklist(struct Blacklist *blptr);
void destroy_blacklists(void);

extern dlink_list blacklist_list;

#endif
