#ifndef __RESOLVER_H__
#define __RESOLVER_H__


#include <time.h>
#include <threads.h>

#include <arpa/inet.h>

#include "util.h"
#include "config.h"


enum {
	RESOLVER_TYPE_DEFAULT,
	RESOLVER_TYPE_DOH,
};


typedef void (*ResolverContextFn)(const char addr[], void *udata0, void *udata1);

typedef struct resolver_context {
	const char        *host;
	const char        *port;
	void              *udata0;
	void              *udata1;
	ResolverContextFn  callback_fn;
	size_t             addr_len;
	char               addr[INET6_ADDRSTRLEN];

	/* private */
	size_t    _host_len;
	DListNode _node;
} ResolverContext;

typedef struct resolver_host {
	time_t    timer;
	char      name[CFG_HOST_NAME_SIZE];
	size_t    addr_len;
	char      addr[INET6_ADDRSTRLEN];
	DListNode node;
} ResolverHost;

typedef struct resolver {
	volatile int  is_alive;
	int           type;
	const char   *uri;
	Str           str_buffer;
	DList         req_queue;
	CstrMap       host_map;
	DList         host_list;
	unsigned      host_count;
	ResolverHost  host_array[CFG_HOST_ARRAY_SIZE];
	mtx_t         mutex;
	cnd_t         condv;
} Resolver;

int  resolver_init(Resolver *r, int type, const char uri[]);
void resolver_deinit(Resolver *r);
void resolver_run(Resolver *r);
void resolver_stop(Resolver *r);
int  resolver_resolve(Resolver *r, ResolverContext *ctx);
int  resolver_remove(Resolver *r, const char host[]);


#endif

