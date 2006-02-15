/* $Id: m_sshortcut.c 466 2006-01-14 18:45:57Z jilles $ */

#include "stdinc.h"
#include "client.h"
#include "common.h"
#include "ircd.h"
#include "irc_string.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_log.h"
#include "s_serv.h"
#include "send.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"

#define SVS_operserv_NICK "OperServ"
#define SVS_chanserv_NICK "ChanServ"
#define SVS_nickserv_NICK "NickServ"

char *reconstruct_parv(int parc, const char *parv[]);

static int m_operserv(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static int m_chanserv(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static int m_nickserv(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);

struct Message operserv_msgtab = {
  "OPERSERV", 0, 0, 0, MFLG_SLOW,
  {mg_unreg, {m_operserv, 1}, mg_ignore, mg_ignore, mg_ignore, {m_operserv, 1}}
};

struct Message chanserv_msgtab = {
  "CHANSERV", 0, 0, 0, MFLG_SLOW,
  {mg_unreg, {m_chanserv, 1}, mg_ignore, mg_ignore, mg_ignore, {m_chanserv, 1}}
};

struct Message nickserv_msgtab = {
  "NICKSERV", 0, 0, 0, MFLG_SLOW,
  {mg_unreg, {m_nickserv, 1}, mg_ignore, mg_ignore, mg_ignore, {m_nickserv, 1}}
};

struct Message os_msgtab = {
  "OS", 0, 0, 0, MFLG_SLOW,
  {mg_unreg, {m_operserv, 1}, mg_ignore, mg_ignore, mg_ignore, {m_operserv, 1}}
};

struct Message cs_msgtab = {
  "CS", 0, 0, 0, MFLG_SLOW,
  {mg_unreg, {m_chanserv, 1}, mg_ignore, mg_ignore, mg_ignore, {m_chanserv, 1}}
};

struct Message ns_msgtab = {
  "NS", 0, 0, 0, MFLG_SLOW,
  {mg_unreg, {m_nickserv, 1}, mg_ignore, mg_ignore, mg_ignore, {m_nickserv, 1}}
};

mapi_clist_av1 sshortcut_clist[] = {
  &operserv_msgtab,
  &chanserv_msgtab,
  &nickserv_msgtab,
  &os_msgtab,
  &cs_msgtab,
  &ns_msgtab,
  NULL
};

DECLARE_MODULE_AV1(sshortcut, NULL, NULL, sshortcut_clist, NULL, NULL, "$Revision: 466 $");

char *reconstruct_parv(int parc, const char *parv[])
{
  static char tmpbuf[BUFSIZE]; int i;

  strlcpy(tmpbuf, parv[0], BUFSIZE);
  for (i = 1; i < parc; i++)
  {
    strlcat(tmpbuf, " ", BUFSIZE);
    strlcat(tmpbuf, parv[i], BUFSIZE);
  }
  return tmpbuf;
}

static int m_operserv(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
  struct Client *target_p;

  if (parc < 2 || EmptyString(parv[1]))
  {
    sendto_one(source_p, form_str(ERR_NOTEXTTOSEND), me.name, source_p->name);
    return 0;
  }

  if ((target_p = find_named_person(SVS_operserv_NICK)) && IsService(target_p))
  {
    sendto_one(target_p, ":%s PRIVMSG %s :%s", get_id(source_p, target_p), get_id(target_p, target_p), reconstruct_parv(parc - 1, &parv[1]));
  }
  else
  {
    sendto_one_numeric(source_p, ERR_SERVICESDOWN, form_str(ERR_SERVICESDOWN), SVS_operserv_NICK);
  }
  return 0;
}

static int m_chanserv(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
  struct Client *target_p;

  if (parc < 2 || EmptyString(parv[1]))
  {
    sendto_one(source_p, form_str(ERR_NOTEXTTOSEND), me.name, source_p->name);
    return 0;
  }

  if ((target_p = find_named_person(SVS_chanserv_NICK)) && IsService(target_p))
  {
    sendto_one(target_p, ":%s PRIVMSG %s :%s", get_id(source_p, target_p), get_id(target_p, target_p), reconstruct_parv(parc - 1, &parv[1]));
  }
  else
  {
    sendto_one_numeric(source_p, ERR_SERVICESDOWN, form_str(ERR_SERVICESDOWN), SVS_chanserv_NICK);
  }
  return 0;
}

static int m_nickserv(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
  struct Client *target_p;

  if (parc < 2 || EmptyString(parv[1]))
  {
    sendto_one(source_p, form_str(ERR_NOTEXTTOSEND), me.name, source_p->name);
    return 0;
  }

  if ((target_p = find_named_person(SVS_nickserv_NICK)) && IsService(target_p))
  {
    sendto_one(target_p, ":%s PRIVMSG %s :%s", get_id(source_p, target_p), get_id(target_p, target_p), reconstruct_parv(parc - 1, &parv[1]));
  }
  else
  {
    sendto_one_numeric(source_p, ERR_SERVICESDOWN, form_str(ERR_SERVICESDOWN), SVS_nickserv_NICK);
  }
  return 0;
}

