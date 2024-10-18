#include "config.h"
#include "holytunnel.h"


int
main(void)
{
	/* TODO: argument parser */
	const Config config = {
		.listen_host = "127.0.0.1",
		.listen_port = 8007,
	};

	return -holytunnel_run(&config);
}
