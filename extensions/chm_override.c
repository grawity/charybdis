/*
 * Channel mode granting free oper-override in it.
 */

#include "stdinc.h"
#include "modules.h"
#include "hook.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "hash.h"
#include "s_conf.h"
#include "s_user.h"
#include "s_serv.h"
#include "numeric.h"
#include "privilege.h"
#include "s_newconf.h"
#include "chmode.h"

const char mode_letter_override = '!';

static unsigned int mode_override;
static unsigned int mode_permanent;

static void hack_channel_access(void *data);
static void hack_can_join(void *data);

mapi_hfn_list_av1 override_hfnlist[] = {
	{ "get_channel_access", (hookfn) hack_channel_access },
	{ "can_join", (hookfn) hack_can_join },
	{ NULL, NULL }
};

static void
hack_channel_access(void *vdata)
{
	hook_data_channel_approval *data = (hook_data_channel_approval *) vdata;

	if (data->approved == CHFL_CHANOP)
		return;

	if (data->chptr->mode.mode & (mode_override | mode_permanent))
		data->approved = CHFL_CHANOP;
}

static void
hack_can_join(void *vdata)
{
	hook_data_channel *data = (hook_data_channel *) vdata;

	if (data->approved == 0)
		return;

	if (data->chptr->mode.mode & (mode_override | mode_permanent))
	{
		data->approved = 0;
		sendto_channel_flags(NULL, ALL_MEMBERS, &me, data->chptr,
				"NOTICE %s :Allowed %s to bypass join restriction.",
				data->chptr->chname, get_oper_name(data->client));
		/*
		sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
				"%s is using channel-override on %s (banwalking)",
				get_oper_name(data->client), data->chptr->chname);
		*/
	}
}

unsigned int
x_cflag_find(char c_)
{
	int c = (unsigned char)c_;

	if (chmode_table[c].set_func == chm_nosuch ||
	    chmode_table[c].set_func == chm_orphaned)
		return 0;
	else
		return chmode_table[c].mode_type;
}

static int
_modinit(void)
{
	mode_override = cflag_add(mode_letter_override, chm_simple);
	if (mode_override == 0)
		return -1;

	mode_permanent = x_cflag_find('P');

	return 0;
}

static void
_moddeinit(void)
{
	cflag_orphan(mode_letter_override);
}

DECLARE_MODULE_AV1(override, _modinit, _moddeinit, NULL, NULL,
			override_hfnlist, "$Revision: 1 $");
