#include "stdinc.h"
#include "modules.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "numeric.h"

#define RPL_WHOISSPECIAL 320 /* Unreal3.2 */

#define fmt_RPL_WHOISSPECIAL "%s :is known by TS6 UID as %s"

static int m_uidwhois(struct Client *, struct Client *, int, const char **);
static void h_uidwhois(hook_data_client *);

struct Message uidwhois_msgtab = {
	"UIDWHOIS", 0, 0, 0, MFLG_SLOW,
	{mg_ignore, {m_uidwhois, 0}, mg_ignore, mg_ignore, mg_ignore, {m_uidwhois, 0}}
};

mapi_clist_av1 uidwhois_clist[] = {&uidwhois_msgtab, NULL};

mapi_hfn_list_av1 uidwhois_hfnlist[] = {
	{"doing_whois",		(hookfn) h_uidwhois},
	{"doing_whois_global",	(hookfn) h_uidwhois},
	{NULL, NULL}
};

DECLARE_MODULE_AV1(uidwhois, NULL, NULL, uidwhois_clist,
		   NULL, uidwhois_hfnlist, "Revision 0.43");

static int
m_uidwhois(struct Client *client_p, struct Client *source_p,
	   int parc, const char *parv[])
{
	struct Client *target_p;
	char *nick;
	int i = 0;

	if (parc < 2)
		return 0;

	if (!IsOper(source_p)) {
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES,
				   form_str(ERR_NOPRIVILEGES));
		return 0;
	}

	while (parv[++i]) {
		nick = LOCAL_COPY(parv[i]);
		target_p = find_person(nick);
		if (target_p != NULL) {
			sendto_one_numeric(source_p, RPL_WHOISUSER,
					   form_str(RPL_WHOISUSER),
					   target_p->name, target_p->username,
					   target_p->host, target_p->info);
			sendto_one_numeric(source_p, RPL_WHOISSERVER,
					   form_str(RPL_WHOISSERVER),
					   target_p->name, target_p->servptr->name,
					   target_p->servptr->info);
			sendto_one_numeric(source_p, RPL_WHOISSPECIAL,
					   fmt_RPL_WHOISSPECIAL,
					   target_p->name, target_p->id);
		} else
			sendto_one_numeric(source_p, ERR_NOSUCHNICK,
					   form_str(ERR_NOSUCHNICK), nick);
	}

	return 0;
}

static void
h_uidwhois(hook_data_client *data)
{
	if (IsOper(data->client)) {
		sendto_one_numeric(data->client, RPL_WHOISSPECIAL,
				   fmt_RPL_WHOISSPECIAL,
				   data->target->name, data->target->id);
	}
}
