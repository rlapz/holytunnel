#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>

#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/sysinfo.h>
#include <sys/signalfd.h>

#include "holytunnel.h"
#include "util.h"
#include "resolver.h"
#include "config.h"


typedef struct epoll_event Event;


/*
 * Client
 */
enum {
	_CLIENT_STATE_HEADER,
	_CLIENT_STATE_CONNECT,
	_CLIENT_STATE_RESPONSE,         /* HTTPS */
	_CLIENT_STATE_FORWARD_HEADER,   /* HTTP  */
	_CLIENT_STATE_FORWARD_ALL,
	_CLIENT_STATE_STOP,
};

enum {
	_CLIENT_TYPE_HTTP,
	_CLIENT_TYPE_HTTPS,
};

typedef struct client Client;
struct client {
	int              type;
	int              state;
	int              src_fd;
	int              trg_fd;
	Event            event;
	Client          *peer;
	HttpRequest      request;
	Url              url;
	ResolverContext  resolver_ctx;
	size_t           sent;
	size_t           recvd;
	char             buffer[CFG_BUFFER_SIZE];
};

static int         _client_try_connect(const Client *client);
static const char *_client_state_str(int state);
static const char *_client_type_str(int type);


/*
 * Worker
 */
typedef struct worker {
	unsigned    index;
	atomic_int  is_alive;
	int         event_fd;
	Mempool     clients;
	Resolver   *resolver;
	thrd_t      thread;
} Worker;

static int  _worker_create(Worker *w, Resolver *resolver, unsigned index);
static void _worker_destroy(Worker *w);
static int  _worker_event_loop_thrd(void *worker);
static void _worker_handle_client_state(Worker *w, Client *client);
static int  _worker_client_add(Worker *w, int src_fd, int trg_fd, int state, Client *peer);
static void _worker_client_del(Worker *w, Client *client);
static int  _worker_client_state_header(Worker *w, Client *client);
static int  _worker_client_state_header_get_host(Worker *w, Client *client);
static int  _worker_client_state_connect(Worker *w, Client *client);
static int  _worker_client_state_peer(Worker *w, Client *client);
static int  _worker_client_state_response(Worker *w, Client *client);
static int  _worker_client_state_forward_header(Worker *w, Client *client);
static int  _worker_client_state_forward_all(Worker *w, Client *client);

static void _worker_on_destroy_active_client(void *client, void *udata);
static void _worker_on_resolved(const char addr[], void *worker, void *client);


/*
 * Server
 */
typedef struct server {
	volatile int  is_alive;
	int           listen_fd;
	int           signal_fd;
	unsigned      workers_curr;
	unsigned      workers_len;
	Worker       *workers;
	Resolver      resolver;
	Config        config;
} Server;

static int  _server_open_signal_fd(Server *s);
static int  _server_open_listen_fd(Server *s, const char lhost[], int lport);
static int  _server_create_workers(Server *s);
static void _server_destroy_workers(Server *s);
static int  _server_event_loop(Server *s);
static void _server_event_handle_listener(Server *s);
static void _server_event_handle_signal(Server *s);
static int  _server_resolver_thrd(void *udata);


/*********************************************************************************************
 * IMPL                                                                                      *
 *********************************************************************************************/
/*
 * public
 */
int
holytunnel_run(const Config *config)
{
	int ret = -1;
	Server server;
	thrd_t resolver_thrd;

	memset(&server, 0, sizeof(server));
	if (log_init() < 0) {
		fprintf(stdout, "holytunnel: run: log_init: failed");
		return -1;
	}

	server.config = *config;
	const Config *const cfg = &server.config;
	if (_server_open_listen_fd(&server, cfg->listen_host, cfg->listen_port) < 0)
		goto out0;

	if (_server_open_signal_fd(&server) < 0)
		goto out1;

	if (resolver_init(&server.resolver, cfg->resolver_type, cfg->resolver_doh_url) < 0)
		goto out2;

	if (thrd_create(&resolver_thrd, _server_resolver_thrd, &server.resolver) != thrd_success) {
		log_err(0, "holytunnel: run: thrd_create: _server_resolver_thrd: failed");
		goto out3;
	}

	if (_server_create_workers(&server) < 0)
		goto out4;

	log_info("holytunnel: run: listening on: \"%s:%d\"", cfg->listen_host, cfg->listen_port);
	ret = _server_event_loop(&server);

	_server_destroy_workers(&server);

out4:
	resolver_stop(&server.resolver);
	thrd_join(resolver_thrd, NULL);
out3:
	resolver_deinit(&server.resolver);
out2:
	close(server.signal_fd);
out1:
	close(server.listen_fd);
out0:
	log_deinit();
	return ret;
}


/*
 * private
 */
/*
 * Client
 */
static int
_client_try_connect(const Client *client)
{
	int ret;
	const int fd = client->trg_fd;
	socklen_t ret_len = sizeof(ret);


	const int port = atoi(client->resolver_ctx.port);
	const char *const addr = client->resolver_ctx.addr;
	if (port == 0) {
		log_err(errno, "holytunnel: _client_try_connect: \"%s:%d\": invalid port", addr, port);
		return -1;
	}

	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &ret, &ret_len) < 0) {
		log_err(errno, "holytunnel: _client_try_connect: getsockopt: \"%s:%d\"", addr, port);
		return -1;
	}

	if (ret != 0) {
		log_err(ret, "holytunnel: _client_try_connect: getsockopt: ret: \"%s:%d\"", addr, port);
		return -1;
	}

	if (net_connect_tcp(fd, addr, port) < 0) {
		if ((errno == EINPROGRESS) || (errno == EAGAIN))
			return 0;

		log_err(errno, "holytunnel: _client_try_connect: net_connect_tcp: \"%s:%d\""), addr, port;
		return -1;
	}

	return 1;
}


static const char *
_client_state_str(int state)
{
	switch (state) {
	case _CLIENT_STATE_HEADER: return "header";
	case _CLIENT_STATE_CONNECT: return "connect";
	case _CLIENT_STATE_RESPONSE: return "response";
	case _CLIENT_STATE_FORWARD_HEADER: return "forward header";
	case _CLIENT_STATE_FORWARD_ALL: return "forward all";
	case _CLIENT_STATE_STOP: return "stop";
	}

	return "unknown";
}


static const char *
_client_type_str(int type)
{
	switch (type) {
	case _CLIENT_TYPE_HTTP: return "http";
	case _CLIENT_TYPE_HTTPS: return "https";
	}

	return "unknown";
}


/*
 * Worker
 */
static int
_worker_create(Worker *w, Resolver *resolver, unsigned index)
{
	atomic_store(&w->is_alive, 0);

	const int efd = epoll_create1(0);
	if (efd < 0) {
		log_err(errno, "holytunnel: _worker_create[%u]: epoll_create1", index);
		return -1;
	}

	if (mempool_init(&w->clients, sizeof(Client), CFG_CLIENT_SIZE) < 0) {
		log_err(ENOMEM, "holytunnel: _worker_create[%u]: mempool_init", index);
		goto err0;
	}

	w->index = index;
	w->event_fd = efd;
	if (thrd_create(&w->thread, _worker_event_loop_thrd, w) != thrd_success) {
		log_err(0, "holytunnel: _worker_create[%u]: thrd_create: failed", index);
		goto err1;
	}

	w->resolver = resolver;
	return 0;

err1:
	mempool_deinit(&w->clients, NULL, NULL);
err0:
	close(efd);
	return -1;
}


static void
_worker_destroy(Worker *w)
{
	log_debug("holytunnel: _worker_destroy: [%u:%p]", w->index, (void *)w);
	atomic_store(&w->is_alive, 0);
	thrd_join(w->thread, NULL);

	close(w->event_fd);
	mempool_deinit(&w->clients, _worker_on_destroy_active_client, w);
}


static int
_worker_event_loop_thrd(void *worker)
{
	int ret = -1;
	Worker *const w = (Worker *)worker;
	Event events[CFG_EVENT_SIZE];
	const int efd = w->event_fd;


	atomic_store(&w->is_alive, 1);
	while (atomic_load_explicit(&w->is_alive, memory_order_relaxed)) {
		const int count = epoll_wait(efd, events, CFG_EVENT_SIZE, CFG_EVENT_TIMEOUT);
		if (count < 0) {
			if (errno == EINTR)
				break;

			log_err(errno, "holytunnel: _worker_event_loop_thrd[%u]: epoll_wait", w->index);
			goto out0;
		}

		for (int i = 0; i < count; i++)
			_worker_handle_client_state(w, (Client *)events[i].data.ptr);
	}

	ret = 0;

out0:
	atomic_store(&w->is_alive, 0);
	return ret;
}


static void
_worker_handle_client_state(Worker *w, Client *client)
{
	log_debug("holytunnel: _worker_handle_client_state[%u]: %p: state: %s", w->index, (void *)client,
		  _client_state_str(client->state));

	int state = client->state;
	switch (state) {
	case _CLIENT_STATE_HEADER:
		state = _worker_client_state_header(w, client);
		break;
	case _CLIENT_STATE_CONNECT:
		state = _worker_client_state_connect(w, client);
		break;
	case _CLIENT_STATE_RESPONSE:
		state = _worker_client_state_response(w, client);
		break;
	case _CLIENT_STATE_FORWARD_HEADER:
		state = _worker_client_state_forward_header(w, client);
		break;
	case _CLIENT_STATE_FORWARD_ALL:
		state = _worker_client_state_forward_all(w, client);
		break;
	}

	if (state == _CLIENT_STATE_STOP)
		_worker_client_del(w, client);

	client->state = state;
}


static int
_worker_client_add(Worker *w, int src_fd, int trg_fd, int state, Client *peer)
{
	log_debug("holytunnel: _worker_client_add[%u]: new client: fd: %d", w->index, src_fd);

	Client *const client = mempool_alloc(&w->clients);
	if (client == NULL) {
		log_err(ENOMEM, "holytunnel: _worker_client_add[%u]: mempool_alloc", w->index);
		return -1;
	}

#ifdef DEBUG
	memset(client, 0xaa, sizeof(*client));
	log_debug("holytunnel: _worker_client_add[%u]: new client: %p", w->index, (void *)client);
#endif

	client->event.events = EPOLLIN;
	client->event.data.ptr = client;
	if (epoll_ctl(w->event_fd, EPOLL_CTL_ADD, src_fd, &client->event) < 0) {
		log_err(ENOMEM, "holytunnel: _worker_client_add[%u]: epoll_ctl: add", w->index);
		mempool_free(&w->clients, client);
		return -1;
	}

	client->type = _CLIENT_TYPE_HTTP;
	client->state = state;
	client->src_fd = src_fd;
	client->trg_fd = trg_fd;
	client->url.host = NULL;
	client->url.port = NULL;
	client->sent = 0;
	client->recvd = 0;
	client->request.headers_len = CFG_HTTP_HEADER_SIZE;
	client->peer = peer;
	return 0;
}


static void
_worker_client_del(Worker *w, Client *client)
{
	log_debug("holytunnel: _worker_client_del[%u]: client: %p", w->index, (void *)client);

	if (epoll_ctl(w->event_fd, EPOLL_CTL_DEL, client->src_fd, &client->event) < 0) {
		log_err(errno, "holytunnel: _worker_client_del[%u]: epoll_ctl: del", w->index);
		abort();
	}

	Client *const peer = client->peer;
	if (peer != NULL) {
		peer->event.events = EPOLLIN | EPOLLOUT;
		if (epoll_ctl(w->event_fd, EPOLL_CTL_MOD, peer->src_fd, &peer->event) < 0) {
			log_err(errno, "holytunnel: _worker_client_del[%u]: epoll_ctl: mod: peer", w->index);
			abort();
		}

		peer->state = _CLIENT_STATE_STOP;
		peer->peer = NULL;
	} else if (client->trg_fd > 0) {
		close(client->trg_fd);
		client->trg_fd = -1;
	}

	close(client->src_fd);
	url_free(&client->url);

#ifdef DEBUG
	memset(client, 0xaa, sizeof(*client));
#endif

	mempool_free(&w->clients, client);
}


static int
_worker_client_state_header(Worker *w, Client *client)
{
	const size_t recvd = client->recvd;
	char *const buffer = client->buffer;
	const size_t buffer_size = CFG_BUFFER_SIZE;
	if (recvd >= buffer_size) {
		/* TODO: flexible buffer size */
		log_err(0, "holytunnel: _worker_client_state_header[%u]: buffer full", w->index);
		return _CLIENT_STATE_STOP;
	}

	const ssize_t rv = recv(client->src_fd, buffer + recvd, buffer_size - recvd, 0);
	if (rv < 0) {
		if (errno == EAGAIN)
			return _CLIENT_STATE_HEADER;

		log_err(errno, "holytunnel: _worker_client_state_header[%u]: recv", w->index);
		return _CLIENT_STATE_STOP;
	}

	if (rv == 0) {
		log_err(0, "holytunnel: _worker_client_state_header[%u]: recv: EOF", w->index);
		return _CLIENT_STATE_STOP;
	}

	client->recvd = recvd + (size_t)rv;

#ifdef DEBUG
	buffer[client->recvd] = '\0';
	log_debug("holytunnel: _worker_client_state_header[%u]: recv: \n|%s|", w->index, buffer);
#endif

	switch (http_request_parse(&client->request, buffer, client->recvd, recvd)) {
	case -1:
		log_err(0, "holytunnel: _worker_client_state_header[%u]: http_request_parse: invalid request",
			w->index);

		/* TODO: send error response */
		return _CLIENT_STATE_STOP;
	case -2:
		/* header incomplete */
		return _CLIENT_STATE_HEADER;
	}

	const char *const method = client->request.method;
	const size_t method_len = client->request.method_len;
	if ((method_len == 7) && (strncasecmp(method, "CONNECT", method_len) == 0))
		client->type = _CLIENT_TYPE_HTTPS;

	return _worker_client_state_header_get_host(w, client);
}


static int
_worker_client_state_header_get_host(Worker *w, Client *client)
{
	const size_t headers_len = client->request.headers_len;
	const HttpHeader *const headers = client->request.headers;

	const char *host = NULL;
	size_t host_len = 0;
	for (size_t i = 0; i < headers_len; i++) {
		const HttpHeader *const header = &headers[i];
		if ((header->name_len == 4) && (strncasecmp(header->name, "Host", header->name_len) == 0)) {
			host = header->value;
			host_len = header->value_len;
			break;
		}
	}

	/* no host found, use 'path' instead */
	if (host == NULL) {
		host = client->request.path;
		host_len = client->request.path_len;
	}

	const char *const def_port = (client->type == _CLIENT_TYPE_HTTPS)? "443" : "80";
	if (url_parse(&client->url, host, (int)host_len, def_port) < 0) {
		log_err(0, "holytunnel: _worker_client_state_header_get_host[%u]: url_parse: invalid request",
			w->index);

		return _CLIENT_STATE_STOP;
	}

	log_debug("holytunnel: _worker_client_state_header_get_host[%u]: host: |%s:%s|", w->index,
		 client->url.host, client->url.port);

	/* sleeping... */
	client->event.events = 0;
	if (epoll_ctl(w->event_fd, EPOLL_CTL_MOD, client->src_fd, &client->event) < 0) {
		log_err(errno, "holytunnel: _worker_client_state_header_get_host[%u]: epoll_ctl: mod", w->index);
		abort();
	}

	const char *const _host = client->url.host;
	const char *const _port = client->url.port;
	if (net_host_is_resolved(_host)) {
		log_debug("holytunnel: _worker_client_state_header_get_host[%u]: host: |%s:%s|: already resolved",
			  w->index, _host, _port);

		ResolverContext *const ctx = &client->resolver_ctx;
		const size_t _host_len = strlen(_host);

		memcpy(ctx->addr, _host, _host_len + 1);
		ctx->addr_len = _host_len;
		ctx->host = _host;
		ctx->port = _port;

		_worker_on_resolved(ctx->addr, w, client);
	} else {
		client->resolver_ctx.callback_fn = _worker_on_resolved;
		client->resolver_ctx.udata0 = w;
		client->resolver_ctx.udata1 = client;
		client->resolver_ctx.host = _host;
		client->resolver_ctx.port = _port;
		if (resolver_resolve(w->resolver, &client->resolver_ctx) < 0)
			abort();
	}

	return _CLIENT_STATE_CONNECT;
}


static int
_worker_client_state_connect(Worker *w, Client *client)
{
	log_debug("%.*s", (int)client->resolver_ctx.addr_len, client->resolver_ctx.addr);
	switch (_client_try_connect(client)) {
	case -1: return _CLIENT_STATE_STOP;
	case 0: return _CLIENT_STATE_CONNECT;
	}

	return _worker_client_state_peer(w, client);
}


static int
_worker_client_state_peer(Worker *w, Client *client)
{
	return _CLIENT_STATE_STOP;
}


static int
_worker_client_state_response(Worker *w, Client *client)
{
	return _CLIENT_STATE_STOP;
}


static int
_worker_client_state_forward_header(Worker *w, Client *client)
{
	return _CLIENT_STATE_STOP;
}


static int
_worker_client_state_forward_all(Worker *w, Client *client)
{
	return _CLIENT_STATE_STOP;
}


static void
_worker_on_destroy_active_client(void *client, void *udata)
{
	Worker *const w = (Worker *)udata;
	Client *const c = (Client *)client;
	log_debug("holytunnel: _worker_on_destroy_active_client[%u]: [%p: %d]", w->index, client,
		  c->src_fd);

	close(c->src_fd);
	url_free(&c->url);
}


static void
_worker_on_resolved(const char addr[], void *worker, void *client)
{
	/* WARN: callback function with no locks */
	Worker *const w = (Worker *)worker;
	Client *const c = (Client *)client;
	log_debug("holytunnel: _worker_on_resolved[%u]: %p: %s", w->index, client, addr);


	if (addr == NULL) {
		c->state = _CLIENT_STATE_STOP;
		goto out0;
	}

	const int trg_fd = net_open_tcp(addr, SOCK_NONBLOCK);
	if (trg_fd < 0) {
		log_err(errno, "holytunnel: _worker_on_resolved: net_open_tcp");
		goto out0;
	}

	c->trg_fd = trg_fd;
	log_debug("holytunnel: _worker_on_resolved[%u]: %p: new trg_fd: %d", w->index, client, trg_fd);


	switch (_client_try_connect(c)) {
	case -1:
		c->state = _CLIENT_STATE_STOP;
		goto out0;
	case 0:
		/* try again later */
		break;
	case 1:
		/* next step */
		goto out0;
	}

	/* prepare to connect to target fd */
	c->state = _CLIENT_STATE_CONNECT;
	c->event.events = EPOLLOUT;
	if (epoll_ctl(w->event_fd, EPOLL_CTL_ADD, c->trg_fd, &c->event) < 0) {
		log_err(errno, "holytunnel: _worker_on_resolved: epoll_ctl: add: trg_fd");
		goto out0;
	}

	return;

out0:
	/* TODO */
	c->state = _CLIENT_STATE_STOP;
	c->event.events = EPOLLIN | EPOLLOUT;
	if (epoll_ctl(w->event_fd, EPOLL_CTL_MOD, c->src_fd, &c->event) < 0) {
		log_err(errno, "holytunnel: _worker_on_resolved: epoll_ctl: mod");
		abort();
	}
}


/*
 * Server
 */
static int
_server_open_signal_fd(Server *s)
{
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);
	sigaddset(&mask, SIGHUP);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		log_err(errno, "holytunnel: _server_open_signal_fd: sigprocmask");
		return -1;
	}

	const int fd = signalfd(-1, &mask, 0);
	if (fd < 0) {
		log_err(errno, "holytunnel: _server_open_signal_fd: signalfd");
		return -1;
	}

	s->signal_fd = fd;
	return 0;
}


static int
_server_open_listen_fd(Server *s, const char lhost[], int lport)
{
	const struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons((in_port_t)lport),
		.sin_addr.s_addr = inet_addr(lhost),
	};

	const int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (fd < 0) {
		log_err(errno, "holytunnel: _server_open_listen_fd: socket");
		return -1;
	}

	const int y = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &y, sizeof(y)) < 0) {
		log_err(errno, "holytunnel: _server_open_listen_fd: setsockopt: SO_REUSEADDR");
		goto err0;
	}

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		log_err(errno, "holytunnel: _server_open_listen_fd: bind");
		goto err0;
	}

	if (listen(fd, 32) < 0) {
		log_err(errno, "holytunnel: _server_open_listen_fd: listen");
		goto err0;
	}

	s->listen_fd = fd;
	return 0;

err0:
	close(fd);
	return -1;
}


static int
_server_create_workers(Server *s)
{
	const int nprocs = get_nprocs();
	assert(nprocs > 0);

	const unsigned _nprocs = (unsigned)nprocs;
	Worker *const workers = malloc(sizeof(Worker) * _nprocs);
	if (workers == NULL) {
		log_err(errno, "holytunnel: _server_create_workers: malloc: workers");
		return -1;
	}

	unsigned i = 0;
	for (; i < _nprocs; i++) {
		if (_worker_create(&workers[i], &s->resolver, i) < 0)
			goto err0;
	}

	s->workers_curr = 0;
	s->workers_len = _nprocs;
	s->workers = workers;

	/* TODO:
	 * - Carefully wait worker threads.
	 * - Ignore dead (error) worker thread, at least there is 1 worker thread alive.
	 */
	log_debug("holytunnel: _server_create_workers: nprocs: %u", _nprocs);
	for (unsigned j = 0; j < i;) {
		if (atomic_load(&s->workers[j].is_alive)) {
			log_debug("holytunnel: _server_create_workers: wait: [%u:%p]: OK", j, &s->workers[j]);
			j++;
		}

		usleep(10000);
	}

	log_debug("holytunnel: _server_create_workers: OK");
	return 0;

err0:
	while (i--)
		_worker_destroy(&workers[i]);

	free(workers);
	return -1;
}



static void
_server_destroy_workers(Server *s)
{
	for (unsigned i = 0; i < s->workers_len; i++)
		_worker_destroy(&s->workers[i]);

	free(s->workers);
	s->workers = NULL;
}


static int
_server_event_loop(Server *s)
{
	int ret = -1;
	const int lfd = s->listen_fd;
	const int sfd = s->signal_fd;
	struct pollfd pfds[2] = {
		{ .events = POLLIN, .fd = lfd },
		{ .events = POLLIN, .fd = sfd },
	};

	s->is_alive = 1;
	while (s->is_alive) {
		const int count = poll(pfds, 2, -1);
		if (count < 0) {
			if (errno == EINTR)
				break;

			log_err(errno, "holytunnel: _server_event_loop: poll");
			goto out0;
		}

		short int rv = pfds[0].revents;
		if (rv & (POLLERR | POLLHUP)) {
			log_err(0, "holytunnel: _server_event_loop: POLLERR/POLLHUP: listen fd");
			goto out0;
		}

		if (rv & POLLIN)
			_server_event_handle_listener(s);

		rv = pfds[1].revents;
		if (rv & (POLLERR | POLLHUP)) {
			log_err(0, "holytunnel: _server_event_loop: POLLERR/POLLHUP: signal fd");
			goto out0;
		}

		if (rv & POLLIN)
			_server_event_handle_signal(s);
	}

	ret = 0;

out0:
	s->is_alive = 0;
	return ret;
}


static void
_server_event_handle_listener(Server *s)
{
	const int fd = accept(s->listen_fd, NULL, NULL);
	if (fd < 0) {
		log_err(errno, "holytunnel: _server_event_handle_signal: accept");
		return;
	}

	const unsigned curr = s->workers_curr;
	Worker *const worker = &s->workers[curr];
	if (_worker_client_add(worker, fd, -1, _CLIENT_STATE_HEADER, NULL) < 0) {
		/* TODO: use another worker thread */
		close(fd);
		return;
	}

	s->workers_curr = (curr + 1) % s->workers_len;
}


static void
_server_event_handle_signal(Server *s)
{
	struct signalfd_siginfo siginfo;
	if (read(s->signal_fd, &siginfo, sizeof(siginfo)) <= 0) {
		log_err(errno, "holytunnel: _server_event_handle_signal: read");
		return;
	}

	switch (siginfo.ssi_signo) {
	case SIGHUP:
		break;
	case SIGINT:
	case SIGQUIT:
		s->is_alive = 0;
		putchar('\n');
		log_info("holytunnel: _server_event_handle_signal[%u]: interrupted", siginfo.ssi_signo);
		break;
	default:
		log_err(errno, "holytunnel: _server_event_handle_signal: invalid signal");
		abort();
	}
}


static int
_server_resolver_thrd(void *udata)
{
	resolver_run((Resolver *)udata);
	return 0;
}
