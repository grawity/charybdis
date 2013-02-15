#include "stdinc.h"
#include "modules.h"
#include "s_conf.h"
#include "chmode.h"

static unsigned int mymode;

static int _modinit(void) {
	mymode = cflag_add('S', chm_simple);
	if (!mymode)
		return -1;
	return 0;
}


static void _moddeinit(void) {
	cflag_orphan('S');
}

DECLARE_MODULE_AV1(chm_foo, _modinit, _moddeinit, NULL, NULL, NULL, "1.0");
