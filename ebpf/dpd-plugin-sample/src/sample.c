/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * dpd-plugin-sample - reference implementation of the dpdfwd plugin ABI.
 *
 * It blocks TCP/25 for every new flow (which dpdfwd turns into a dpd_class
 * entry) and counts events. It is deliberately small: a real plugin would
 * keep state, consult a database, or drive an external service.
 */
#include <stdio.h>
#include <string.h>

#include "dpd_plugin.h"

static unsigned long flow_count;
static unsigned long event_count;

static int sample_init(void)
{
	fprintf(stderr, "dpd-sample: init (ABI %d)\n", DPD_PLUGIN_ABI);
	return 0;
}

static int sample_classify(struct dpd_flow_desc *d)
{
	/* Example policy: never allow outbound SMTP from this plugin. */
	if (d->proto == 6 && d->dport == 25) {
		d->action = DPD_PLUGIN_BLOCK;
		d->skb_priority = 0;
	}
	return 0;
}

static int sample_create(const struct dpd_flow_desc *d)
{
	(void)d;
	flow_count++;
	return 0;
}

static void sample_expire(const struct dpd_flow_desc *d)
{
	(void)d;
}

static void sample_topology(int event, const char *ifname)
{
	(void)event;
	(void)ifname;
	event_count++;
}

static int sample_dump(char *buf, size_t len)
{
	return snprintf(buf, len, "sample: flows=%lu events=%lu",
			flow_count, event_count);
}

struct dpd_plugin_ops dpd_plugin_ops = {
	.name		= "sample",
	.version	= DPD_PLUGIN_ABI,
	.init		= sample_init,
	.flow_classify	= sample_classify,
	.flow_create	= sample_create,
	.flow_expire	= sample_expire,
	.topology_event	= sample_topology,
	.dump		= sample_dump,
};
