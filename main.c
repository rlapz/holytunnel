#include "config.h"
#include "holytunnel.h"
#include "resolver.h"


int
main(void)
{
	/* TODO: argument parser */
	const Config config = {
		.listen_host = "127.0.0.1",
		.listen_port = 8007,
		.resolver_type = RESOLVER_TYPE_DOH,
		.resolver_doh_url = CFG_DOH_ADGUARD,
	};

	return -holytunnel_run(&config);
}
