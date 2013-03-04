/*
 * charybdis: an advanced ircd
 * m_markupfun.c: testing and demonstration of the markup API.
 *
 * Copyright (c) 2006 William Pitcock <nenolod@nenolod.net>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id: m_markupfun.c 3171 2007-01-31 23:37:30Z jilles $
 */

#include "stdinc.h"
#include "modules.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "substitution.h"

static int m_substitution_parse(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static int m_substitution_add(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);

struct Message substitution_parse_msgtab = {
  "SUBSTITUTION_PARSE", 0, 0, 0, MFLG_SLOW,
  { mg_ignore, {m_substitution_parse, 2}, mg_ignore, mg_ignore, mg_ignore, {m_substitution_parse, 2} }
};

struct Message substitution_add_msgtab = {
  "SUBSTITUTION_ADD", 0, 0, 0, MFLG_SLOW,
  { mg_ignore, {m_substitution_add, 3}, mg_ignore, mg_ignore, mg_ignore, {m_substitution_add, 3} }
};

mapi_clist_av1 markupfun_clist[] = { &substitution_parse_msgtab, &substitution_add_msgtab, NULL };


DECLARE_MODULE_AV1(markupfun, NULL, NULL, markupfun_clist, NULL, NULL, "$Revision: 3171 $");

dlink_list markupvars = { NULL, NULL, 0 };

static int
m_substitution_parse(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	sendto_one_notice(source_p, ":%s", substitution_parse(parv[1], &markupvars));	

	return 0;
}

static int
m_substitution_add(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	substitution_append_var(&markupvars, parv[1], parv[2]);

	sendto_one_notice(source_p, ":Added mapping '%s' -> '%s'", parv[1], parv[2]);	

	return 0;
}
