#include <assert.h>
#include <netdb.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <poll.h>

#include <sys/socket.h>
#include <sys/types.h>

#include "resolver.h"
#include "json.h"
#include "config.h"


/*
 * private
 */
static int  _get_address(Resolver *r, ResolverContext *ctx);
static int  _get_host(Resolver *r, ResolverContext *ctx, ResolverHost **ret_host);
static int  _resolve(Resolver *r, ResolverHost *host, ResolverContext *ctx);
static int  _resolve_default(Resolver *r, ResolverHost *host, ResolverContext *ctx);
static int  _resolve_doh(Resolver *r, ResolverHost *host, ResolverContext *ctx);
static int  _resolve_doh_status(const char status[], const char name[]);
static int  _resolve_doh_verify(const char name[]);
static void _set_host(Resolver *r, ResolverHost *host, ResolverContext *ctx);
static int  _add_host(Resolver *r, ResolverContext *ctx);
static int  _add_host_replace(Resolver *r, ResolverContext *ctx);
static int  _update_host(Resolver *r, ResolverHost *host, ResolverContext *ctx);
static int  _remove_host(Resolver *r, const char host[]);


/*
 * public
 */
int
resolver_init(Resolver  *r, int type, const char uri[])
{
#ifdef DEBUG
	memset(r, 0xaa, sizeof(*r));
#endif

	if (mtx_init(&r->mutex, mtx_plain) != thrd_success) {
		log_err(0, "resolver: resolver_init: mtx_init: failed");
		return -1;
	}

	if (cnd_init(&r->condv) != thrd_success) {
		log_err(0, "resolver: resolver_init: cnd_init: failed");
		goto err0;
	}

	int ret = str_init_alloc(&r->str_buffer, 1024);
	if (ret < 0) {
		log_err(ret, "resolver: resolver_init: str_init_alloc");
		goto err1;
	}

	/* big array size: avoid hash collisions */
	const size_t map_size = CFG_HOST_ARRAY_SIZE * 2;
	ret = cstrmap_init(&r->host_map, map_size);
	if (ret < 0) {
		log_err(ret, "resolver: resolver_init: cstrmap_init");
		goto err2;
	}

	dlist_init(&r->req_queue);
	dlist_init(&r->host_list);

	r->is_alive = 0;
	r->type = type;
	r->uri = uri;
	r->host_count = 0;
	return 0;

err2:
	str_deinit(&r->str_buffer);
err1:
	cnd_destroy(&r->condv);
err0:
	mtx_destroy(&r->mutex);
	return -1;
}


void
resolver_deinit(Resolver *r)
{
	str_deinit(&r->str_buffer);
	cstrmap_deinit(&r->host_map);
	mtx_destroy(&r->mutex);
	cnd_destroy(&r->condv);
}


void
resolver_run(Resolver *r)
{
	mtx_lock(&r->mutex); // LOCK

	r->is_alive = 1;
	while (r->is_alive != 0) {
		DListNode *const node = dlist_pop(&r->req_queue);
		if (node != NULL) {
			mtx_lock(&r->mutex); // UNLOCK

			ResolverContext *const ctx = FIELD_PARENT_PTR(ResolverContext, _node, node);
			if (ctx->callback_fn != NULL) {
				if (_get_address(r, ctx) < 0)
					ctx->callback_fn(NULL, ctx->udata0, ctx->udata1);
				else
					ctx->callback_fn(ctx->_addr, ctx->udata0, ctx->udata1);
			}

			mtx_unlock(&r->mutex); // LOCK
			continue;
		}

		if (r->is_alive == 0)
			break;

		cnd_wait(&r->condv, &r->mutex);
	}

	mtx_unlock(&r->mutex); // UNLOCK
}


void
resolver_stop(Resolver *r)
{
	mtx_lock(&r->mutex); // LOCK

	r->is_alive = 0;
	cnd_broadcast(&r->condv);

	mtx_unlock(&r->mutex); // UNLOCK
}


int
resolver_resolve(Resolver *r, ResolverContext *ctx)
{
	int ret = -1;
	mtx_unlock(&r->mutex); // LOCK

	if (r->is_alive == 0) {
		log_err(0, "resolver: resolver_resolve: stopped!");
		goto out0;
	}

	const size_t len = strlen(ctx->host);
	if ((len == 0) || (len >= CFG_HOST_NAME_SIZE)) {
		log_err(ret, "resolver: resolver_resolve: invalid host name");
		goto out0;
	}

	ctx->_host_len = len;
	dlist_prepend(&r->req_queue, &ctx->_node);
	cnd_signal(&r->condv);
	ret = 0;

out0:
	mtx_unlock(&r->mutex); // UNLOCK
	return ret;
}


int
resolver_remove(Resolver *r, const char host[])
{
	int ret;
	mtx_lock(&r->mutex); // LOCK

	ret = _remove_host(r, host);

	mtx_unlock(&r->mutex); // UNLOCK
	return ret;
}


/*
 * private
 */
static int
_get_address(Resolver *r, ResolverContext *ctx)
{
	ResolverHost *host;
	for (int i = 0; i <= 3; i++) {
		if (_get_host(r, ctx, &host) < 0) {
			if (_add_host(r, ctx) < 0)
				return -1;

			continue;
		}

		const time_t diff = (time(NULL) - host->timer);
		if (diff >= CFG_HOST_EXP_TIME) {
			log_debug("resolver: _get_address: expired: \"%s\" -> (%s)", host->name, host->addr);
			if (_update_host(r, host, ctx) < 0)
				return -1;

			continue;
		}

		/* success */
		memcpy(ctx->_addr, host->addr, host->addr_len + 1);
		log_info("resolver: _get_address: load: \"%s\" -> (%s)", host->name, host->addr);
		return 0;
	}

	log_err(0, "resolver: _get_address: \"%s\": operation aborted", ctx->host);
	return -1;
}


static int
_get_host(Resolver *r, ResolverContext *ctx, ResolverHost **ret_host)
{
	ResolverHost *const host = cstrmap_get(&r->host_map, ctx->host);
	if (host == NULL)
		return -1;

	dlist_remove(&r->host_list, &host->node);
	dlist_prepend(&r->host_list, &host->node);
	*ret_host = host;
	return 0;
}


static int
_resolve(Resolver *r, ResolverHost *host, ResolverContext *ctx)
{
	switch (r->type) {
	case RESOLVER_TYPE_DEFAULT:
		return _resolve_default(r, host, ctx);
	case RESOLVER_TYPE_DOH:
		return _resolve_doh(r, host, ctx);
	}

	log_err(0, "resolver: _resolve: invalid resolver type");
	abort();
}


static int
_resolve_default(Resolver *r, ResolverHost *host, ResolverContext *ctx)
{
	struct addrinfo *ai, *p = NULL;
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
	};

	int ret = getaddrinfo(ctx->host, ctx->port, &hints, &ai);
	if (ret != 0) {
		log_err(0, "resolver: _resolve_default: getaddrinfo: \"%s:%s\": %s", ctx->host, ctx->port,
			gai_strerror(ret));
		return -1;
	}

	for (p = ai; p != NULL; p = p->ai_next) {
		void *addr;
		if (p->ai_family == AF_INET)
			addr = &((struct sockaddr_in *)p->ai_addr)->sin_addr;
		else if (p->ai_family == AF_INET6)
			addr = &((struct sockaddr_in6 *)p->ai_addr)->sin6_addr;
		else
			continue;

		const char *const saddr = inet_ntop(p->ai_family, addr, host->addr, p->ai_addrlen);
		/* unlikely, but yeah */
		if (saddr == NULL)
			continue;

		host->addr_len = strlen(saddr);
		break;
	}

	freeaddrinfo(ai);
	if (p == NULL) {
		log_err(0, "resolver: _resolve_default: \"%s:%s\": failed to resolve", ctx->host, ctx->port);
		return -1;
	}

	(void)r;
	return 0;
}


static int
_resolve_doh(Resolver *r, ResolverHost *host, ResolverContext *ctx)
{
	int ret = -1;
	const char *const uri = str_set_fmt(&r->str_buffer, "%s?name=%s", r->uri, ctx->host);
	if (uri == NULL) {
		log_err(0, "resolver: _resolve_doh: str_set_fmt: failed to compose uri: \"%s\"", ctx->host);
		return -1;
	}

	const char *const res = http_request(&r->str_buffer, uri);
	if (res == NULL)
		return -1;

	json_value_t *const json = json_parse(res, r->str_buffer.len);
	if (json == NULL) {
		log_err(0, "resolver: json_parse: \"%s\": failed to parse json", ctx->host);
		return -1;
	}

	const json_object_t *const json_obj = json_value_as_object(json);
	if (json_obj == NULL) {
		log_err(0, "resolver: \"%s\": invalid json", ctx->host);
		goto out0;
	}

	const json_number_t *status = NULL;
	const json_array_t *answer = NULL;
	for (const json_object_element_t *e = json_obj->start; e != NULL; e = e->next) {
		const char *const name = e->name->string;
		if (strcasecmp(name, "Status") == 0)
			status = json_value_as_number(e->value);
		else if (strcasecmp(name, "Answer") == 0)
			answer = json_value_as_array(e->value);
	}

	if (_resolve_doh_status(status->number, ctx->host) < 0)
		goto out0;

	if (answer == NULL) {
		log_err(0, "resolver: \"%s\": invalid json: no data", ctx->host);
		goto out0;
	}

	for (const json_array_element_t *e = answer->start; e != NULL; e = e->next) {
		const json_object_t *const ee = json_value_as_object(e->value);
		if (ee == NULL)
			continue;

		for (const json_object_element_t *o = ee->start; o != NULL; o = o->next) {
			if (strcasecmp(o->name->string, "data") != 0)
				continue;

			const json_string_t *const ip = json_value_as_string(o->value);
			if (ip == NULL)
				continue;

			const size_t ip_size = ip->string_size;
			if ((ip_size == 0) || (ip_size >= INET6_ADDRSTRLEN))
				continue;

			const char *const ip_string = ip->string;
			if (_resolve_doh_verify(ip_string) < 0)
				continue;

			/* success */
			memcpy(host->addr, ip_string, ip_size + 1);
			host->addr_len = ip_size;
			ret = 0;
			goto out0;
		}
	}

out0:
	free(json);
	return ret;
}


/* https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6 */
static int
_resolve_doh_status(const char status[], const char name[])
{
	const char *err_str = "empty status";
	if (status != NULL) {
		switch (strtoull(status, NULL, 10)) {
		case 0: /* success */ return 0;
		case 1: err_str = "invalid format"; break;
		case 2: err_str = "server failure"; break;
		case 3: err_str = "non existent domain"; break;
		case 4: err_str = "not implemented"; break;
		case 5: err_str = "connection refused"; break;
		case 9: err_str = "unauthorized"; break;
		default: err_str = "unknown"; break;
		}
	}

	log_err(0, "resolver: _resolve_doh_status: \"%s\": %s", name, err_str);
	return -1;
}


static int
_resolve_doh_verify(const char name[])
{
	int family = AF_INET;
	char buffer[sizeof(struct in6_addr)];
	for (int i = 0; i < 2; i++) {
		const int ret = inet_pton(family, name, buffer);
		if (ret < 0) {
			family = AF_INET6;
			continue;
		}

		if (ret == 0)
			break;

		log_debug("resolver: _resolve_doh_verify: \"%s\": version: %s", name,
			  ((family == AF_INET6)? "IPv6":"IPv4"));
		return 0;
	}

	(void)buffer;
	log_err(0, "resolver: _resolve_doh_verify: \"%s\": invalid", name);
	return -1;
}


static inline void
_set_host(Resolver *r, ResolverHost *host, ResolverContext *ctx)
{
	host->timer = time(NULL);
	memcpy(host->name, ctx->host, ctx->_host_len + 1);

	const int ret = cstrmap_set(&r->host_map, host->name, host);
	assert(ret == 0);
	(void)ret;

	dlist_append(&r->host_list, &host->node);
	log_debug("resolver: _set_host: \"%s\" -> (%s)", host->name, host->addr);
}


static int
_add_host(Resolver *r, ResolverContext *ctx)
{
	log_debug("resolver: _add_host: \"%s\"...", ctx->host);
	if (r->host_count < CFG_HOST_ARRAY_SIZE) {
		ResolverHost *const host = &r->host_array[r->host_count];
		if (_resolve(r, host, ctx) < 0)
			return -1;

		_set_host(r, host, ctx);
		r->host_count++;
		return 0;
	}

	return _add_host_replace(r, ctx);
}


static int
_add_host_replace(Resolver *r, ResolverContext *ctx)
{
	DListNode *const node = dlist_pop(&r->host_list);
	assert(node != NULL);

	ResolverHost *const host = FIELD_PARENT_PTR(ResolverHost, node, node);
	if (_resolve(r, host, ctx) < 0) {
		dlist_append(&r->host_list, node);
		return -1;
	}

	ResolverHost *const _host = cstrmap_del(&r->host_map, host->name);
	assert(_host != NULL);

	_set_host(r, host, ctx);
	log_debug("resolver: _add_host_replace: remove: \"%s\" -> (%s)", _host->name, _host->addr);

#ifdef DEBUG
	memset(_host, 0xaa, sizeof(_host));
#endif
	return 0;
}


static int
_update_host(Resolver *r, ResolverHost *host, ResolverContext *ctx)
{
	if (_resolve(r, host, ctx) < 0)
		return -1;

	dlist_remove(&r->host_list, &host->node);
	host->timer = time(NULL);
	dlist_append(&r->host_list, &host->node);

	log_debug("resolver: _add_host_update: add: \"%s\" -> (%s)", host->name, host->addr);
	return 0;
}


static int
_remove_host(Resolver *r, const char host[])
{
	ResolverHost *const _host = cstrmap_del(&r->host_map, host);
	if (_host == NULL) {
		log_err(EINVAL, "resolver: _del_host: cstrmap_get: \"%s\": no such host name", host);
		return -1;
	}

	dlist_remove(&r->host_list, &_host->node);
	assert(r->host_count != 0);

	r->host_count--;
	log_debug("resolver: _del_host: \"%s\" -> (%s)", _host->name, _host->addr);

#ifdef DEBUG
	memset(_host, 0xaa, sizeof(*_host));
#endif
	return 0;
}

