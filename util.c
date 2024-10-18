#include <errno.h>
#include <ctype.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
#include <time.h>
#include <threads.h>

#include <sys/poll.h>

#include <curl/curl.h>

#include "util.h"


/*
 * DList
 */
static void
_dlist_init_node(DList *d, DListNode *node)
{
	node->next = NULL;
	node->prev = NULL;
	d->first = node;
	d->last = node;
}


void
dlist_init(DList *d)
{
	d->first = NULL;
	d->last = NULL;
}


void
dlist_append(DList *d, DListNode *node)
{
	if (d->last != NULL) {
		node->prev = d->last;
		node->next = NULL;
		d->last->next = node;
		d->last = node;
		return;
	}

	_dlist_init_node(d, node);
}


void
dlist_prepend(DList *d, DListNode *node)
{
	if (d->first != NULL) {
		node->next = d->first;
		node->prev = NULL;
		d->first->prev = node;
		d->first = node;
		return;
	}

	_dlist_init_node(d, node);
}


void
dlist_remove(DList *d, DListNode *node)
{
	if (node->next != NULL)
		node->next->prev = node->prev;
	else
		d->last = node->prev;

	if (node->prev != NULL)
		node->prev->next = node->next;
	else
		d->first = node->next;
}


DListNode *
dlist_pop(DList *d)
{
	DListNode *const node = d->last;
	if (node == NULL)
		return NULL;

	dlist_remove(d, node);
	return node;
}


/*
 * CstrMap
 *
 * 32bit FNV-1a case-insensitive hash function & hash map
 * ref: https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
 */
static CstrMapItem *
_cstrmap_map(CstrMap *c, const char key[])
{
	uint32_t hash = 0x811c9dc5; /* FNV-1 offset */
	for (const char *p = key; *p != '\0'; p++) {
		hash ^= (uint32_t)((unsigned char)tolower(*p));
		hash *= 0x01000193; /* FNV-1 prime */
	}

	const size_t size = c->size;
	size_t index = (size_t)(hash & (size - 1));
	CstrMapItem *item = &c->items[index];
	for (size_t i = 0; (i < size) && (item->key != NULL); i++) {
		if (strcasecmp(item->key, key) == 0) {
			/* found matched key */
			return item;
		}

		log_debug("cstrmap: _cstrmap_map: linear probing: [%s:%s]:[%zu:%zu]", key, item->key, i, index);
		index = (index + 1) % size;
		item = &c->items[index];
	}

	/* slot full, no free key */
	if (item->key != NULL)
		return NULL;

	return item;
}


int
cstrmap_init(CstrMap *c, size_t size)
{
	assert(size != 0);
	while ((size % 2) != 0)
		size++;

	void *const items = calloc(size, sizeof(CstrMapItem));
	if (items == NULL)
		return -ENOMEM;

	c->size = size;
	c->items = items;
	return 0;
}


void
cstrmap_deinit(CstrMap *c)
{
	free(c->items);
}


int
cstrmap_set(CstrMap *c, const char key[], void *val)
{
	CstrMapItem *const item = _cstrmap_map(c, key);
	if (item == NULL)
		return -1;

	item->key = key;
	item->val = val;
	return 0;
}


void *
cstrmap_get(CstrMap *c, const char key[])
{
	CstrMapItem *const item = _cstrmap_map(c, key);
	if ((item == NULL) || (item->key == NULL))
		return NULL;

	return item->val;
}


void *
cstrmap_del(CstrMap *c, const char key[])
{
	CstrMapItem *const item = _cstrmap_map(c, key);
	if ((item == NULL) || (item->key == NULL))
		return NULL;

	void *const val = item->val;
	item->key = NULL;
	item->val = NULL;
	return val;
}


/*
 * Str
 */
static int
_str_resize(Str *s, size_t slen)
{
	size_t remn_size = 0;
	const size_t size = s->size;
	if (size > slen)
		remn_size = size - s->len;

	if (slen < remn_size)
		return 0;

	if (s->is_alloc == 0)
		return -ENOMEM;

	const size_t _rsize = (slen - remn_size) + size + 1;
	char *const _new_cstr = realloc(s->cstr, _rsize);
	if (_new_cstr == NULL)
		return -errno;

	s->size = _rsize;
	s->cstr = _new_cstr;
	return 0;
}


int
str_init(Str *s, char buffer[], size_t size)
{
	if (size == 0)
		return -EINVAL;

	buffer[0] = '\0';
	s->is_alloc = 0;
	s->size = size;
	s->len = 0;
	s->cstr = buffer;
	return 0;
}


int
str_init_alloc(Str *s, size_t size)
{
	if (size == 0)
		size = 1;

	void *const cstr = malloc(size);
	if (cstr == NULL)
		return -ENOMEM;

	const int ret = str_init(s, cstr, size);
	if (ret < 0) {
		free(cstr);
		return ret;
	}

	s->is_alloc = 1;
	return 0;
}


void
str_deinit(Str *s)
{
	if (s->is_alloc)
		free(s->cstr);
}


char *
str_append_n(Str *s, const char cstr[], size_t len)
{
	if (len == 0)
		return s->cstr;

	if (_str_resize(s, len) < 0)
		return NULL;

	size_t slen = s->len;
	memcpy(s->cstr + slen, cstr, len);

	slen += len;
	s->len = slen;
	s->cstr[slen] = '\0';
	return s->cstr;
}


char *
str_set_n(Str *s, const char cstr[], size_t len)
{
	if (len == 0) {
		s->len = 0;
		s->cstr[0] = '\0';
		return s->cstr;
	}

	if (_str_resize(s, len) < 0)
		return NULL;

	memcpy(s->cstr, cstr, len);
	s->len = len;
	s->cstr[len] = '\0';
	return s->cstr;
}


char *
str_set_fmt(Str *s, const char fmt[], ...)
{
	int ret;
	va_list va;


	/* determine required size */
	va_start(va, fmt);
	ret = vsnprintf(NULL, 0, fmt, va);
	va_end(va);

	if (ret < 0)
		return NULL;

	const size_t cstr_len = (size_t)ret;
	if (cstr_len == 0) {
		s->len = 0;
		s->cstr[0] = '\0';
		return s->cstr;
	}

	if (_str_resize(s, cstr_len) < 0)
		return NULL;

	va_start(va, fmt);
	ret = vsnprintf(s->cstr, cstr_len + 1, fmt, va);
	va_end(va);

	if (ret < 0)
		return NULL;

	s->len = (size_t)ret;
	s->cstr[ret] = '\0';
	return s->cstr;
}


char *
str_append_fmt(Str *s, const char fmt[], ...)
{
	int ret;
	va_list va;


	/* determine required size */
	va_start(va, fmt);
	ret = vsnprintf(NULL, 0, fmt, va);
	va_end(va);

	if (ret < 0)
		return NULL;

	const size_t cstr_len = (size_t)ret;
	if (cstr_len == 0)
		return s->cstr;

	if (_str_resize(s, cstr_len) < 0)
		return NULL;

	size_t len = s->len;
	va_start(va, fmt);
	ret = vsnprintf(s->cstr + len, cstr_len + 1, fmt, va);
	va_end(va);

	if (ret < 0)
		return NULL;

	len += (size_t)ret;
	s->len = len;
	s->cstr[len] = '\0';
	return s->cstr;
}


/*
 * Mempool
 */
int
mempool_init(Mempool *m, size_t chunk, size_t size)
{
	if (mtx_init(&m->mutex, mtx_plain) != thrd_success)
		return -1;

	m->chunk = chunk;
	dlist_init(&m->active);
	dlist_init(&m->inactive);

	for (size_t i = 0; i < size; i++) {
		MempoolItem *const item = malloc(sizeof(MempoolItem) + chunk);
		if (item == NULL) {
			mempool_deinit(m, NULL, NULL);
			return -1;
		}

		dlist_append(&m->inactive, &item->node);
	}

	return 0;
}


void
mempool_deinit(Mempool *m, MempoolCallbackFn on_destroy_active_item, void *udata)
{
	mtx_lock(&m->mutex); /* LOCK */

	DListNode *node;
	while ((node = dlist_pop(&m->inactive)) != NULL)
		free(FIELD_PARENT_PTR(MempoolItem, node, node));

	while ((node = dlist_pop(&m->active)) != NULL) {
		MempoolItem *const item = FIELD_PARENT_PTR(MempoolItem, node, node);
		if (on_destroy_active_item != NULL)
			on_destroy_active_item(item->udata, udata);

		free(item);
	}

	mtx_unlock(&m->mutex); /* UNLOCK */
}


void *
mempool_alloc(Mempool *m)
{
	void *ret = NULL;
	mtx_lock(&m->mutex); /* LOCK */

	DListNode *node = dlist_pop(&m->inactive);
	if (node == NULL) {
		MempoolItem *const item = malloc(sizeof(MempoolItem) + m->chunk);
		if (item == NULL)
			goto out0;

		node = &item->node;
	}

	dlist_append(&m->active, node);
	ret = &FIELD_PARENT_PTR(MempoolItem, node, node)->udata;

out0:
	mtx_unlock(&m->mutex); /* UNLOCK */
	return ret;
}


void
mempool_free(Mempool *m, void *mem)
{
	MempoolItem *const item = FIELD_PARENT_PTR(MempoolItem, udata, mem);
	mtx_lock(&m->mutex); /* LOCK */

	dlist_remove(&m->active, &item->node);
	dlist_append(&m->inactive, &item->node);

	mtx_unlock(&m->mutex); /* UNLOCK */
}


/*
 * Http
 */
static size_t
_http_writer_fn(void *data, size_t size, size_t nmemb, void *udata)
{
	const size_t rsize = (size * nmemb);
	if (str_append_n((Str *)udata, (const char *)data, rsize) == NULL)
		return 0;

	return rsize;
}


int
http_init(void)
{
	if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
		log_err(0, "http: http_init: curl_global_init: failed to init");
		return -1;
	}

	return 0;
}


void
http_deinit(void)
{
	curl_global_cleanup();
}


const char *
http_request(Str *buffer, const char url[])
{
	const char *ret = NULL;
	struct curl_slist *slist = NULL;
	CURL *const handle = curl_easy_init();
	if (handle == NULL) {
		log_err(0, "http: http_request: curl_global_init: failed to init");
		return NULL;
	}

	slist = curl_slist_append(NULL, "accept: application/dns-json");
	if (slist == NULL) {
		log_err(0, "http: http_request: curl_slist_append: failed to add list option");
		goto out0;
	}

	if (curl_easy_setopt(handle, CURLOPT_URL, url) != CURLE_OK) {
		log_err(0, "http: http_request: curl_easy_setopt: CURLOPT_URL: failed to set option");
		goto out1;
	}

	if (curl_easy_setopt(handle, CURLOPT_HTTPHEADER, slist) != CURLE_OK) {
		log_err(0, "http: http_request: curl_easy_setopt: CURLOPT_HTTPHEADER: failed to set option");
		goto out1;
	}

	if (curl_easy_setopt(handle, CURLOPT_TIMEOUT, CFG_RESOLVER_HTTP_TIMEOUT) != CURLE_OK) {
		log_err(0, "http: http_request: curl_easy_setopt: CURLOPT_TIMEOUT: failed to set option");
		goto out1;
	}

	/* reset str buffer */
	str_set_n(buffer, NULL, 0);
	if (curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, _http_writer_fn) != CURLE_OK) {
		log_err(0, "http: http_request: curl_easy_setopt: CURLOPT_WRITEFUNCTION: failed to set option");
		goto out1;
	}

	if (curl_easy_setopt(handle, CURLOPT_WRITEDATA, buffer) != CURLE_OK) {
		log_err(0, "http: http_request: curl_easy_setopt: CURLOPT_WRITEDATA: failed to set option");
		goto out1;
	}

	if (curl_easy_perform(handle) != CURLE_OK) {
		log_err(0, "http: http_request: curl_easy_perform: failed to perform request");
		goto out1;
	}

	long re;
	if (curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &re) != CURLE_OK) {
		log_err(0, "http: http_request: curl_easy_getinfo: failed to get response info");
		goto out1;
	}

	if (re != 200) {
		log_err(0, "http: http_request: invalid response status: %ld", re);
		goto out1;
	}

	/* success */
	ret = buffer->cstr;

out1:
	curl_slist_free_all(slist);
out0:
	curl_easy_cleanup(handle);
	return ret;
}


/*
 * Url
 * TODO: parse url without heap allocation (without curl)
 */
int
url_parse(Url *a, const char url[], size_t len, const char default_port[])
{
	int ret = -1;
	CURLU *curl;
	char *host = NULL;
	char *port = NULL;

	char *new_url;
	if (strstr(url, "://") == NULL)
		new_url = curl_maprintf("http://%.*s", (int)len, url);
	else
		new_url = curl_maprintf("%.*s", (int)len, url);

	if (new_url == NULL)
		return -1;

	curl = curl_url();
	if (curl == NULL)
		goto out0;

	if (curl_url_set(curl, CURLUPART_URL, new_url, 0) != CURLUE_OK)
		goto out1;

	if (curl_url_get(curl, CURLUPART_HOST, &host, 0) != CURLUE_OK)
		goto out1;

	curl_url_get(curl, CURLUPART_PORT, &port, 0);
	if (port == NULL) {
		port = curl_maprintf("%s", default_port);
		if (port == NULL)
			goto out2;
	}

	ret = 0;

out2:
	if (ret < 0)
		curl_free(host);
out1:
	curl_url_cleanup(curl);
out0:
	curl_free(new_url);

	if (ret < 0) {
		a->host = NULL;
		a->port = NULL;
	} else {
		a->host = host;
		a->port = port;
	}

	return ret;
}


void
url_free(Url *a)
{
	curl_free(a->host);
	curl_free(a->port);
}


/*
 * net
 */
int
net_blocking_send(int fd, const char buffer[], size_t *len, int timeout)
{
	struct pollfd pfd = {
		.fd = fd,
		.events = POLLOUT,
	};

	size_t sent = 0;
	const size_t _len = *len;
	while (sent < _len) {
		const int ret = poll(&pfd, 1, timeout);
		if (ret < 0)
			return -1;

		if (ret == 0)
			return 0;

		if (pfd.revents & (POLLERR | POLLHUP))
			return -1;

		assert((pfd.revents & POLLOUT) != 0);

		const ssize_t sn = send(fd, buffer + sent, _len - sent, 0);
		if (sn < 0)
			return -1;

		if (sn == 0)
			break;

		sent += (size_t)sn;
	}

	*len = sent;
	return 1;
}


/*
 * Log
 */
static mtx_t _log_mutex;
static const char *const _log_datetime_default = "???";


static const char *
_log_datetime_now(char dest[], size_t size)
{
	const time_t tm_r = time(NULL);
	struct tm *const tm = localtime(&tm_r);
	if (tm == NULL)
		return _log_datetime_default;

	const char *const res = asctime(tm);
	if (res == NULL)
		return _log_datetime_default;

	const size_t res_len = strlen(res);
	if ((res == 0) || (res_len >= size))
		return _log_datetime_default;

	memcpy(dest, res, res_len - 1);
	dest[res_len - 1] = '\0';
	return dest;
}


int
log_init(void)
{
	if (mtx_init(&_log_mutex, mtx_plain) != thrd_success)
		return -1;

	return 0;
}


void
log_deinit(void)
{
	mtx_destroy(&_log_mutex);
}


void
log_info(const char fmt[], ...)
{
	int ret;
	va_list va;
	char dt[32];
	char buf[1024];
	const size_t len = LEN(buf);


	va_start(va, fmt);
	ret = vsnprintf(buf, len, fmt, va);
	va_end(va);

	if (ret <= 0)
		buf[0] = '\0';

	if ((size_t)ret >= len)
		buf[len - 1] = '\0';

	mtx_lock(&_log_mutex); /* LOCK */
	fprintf(stdout, "I: [%s]: %s\n", _log_datetime_now(dt, LEN(dt)), buf);
	fflush(stdout);
	mtx_unlock(&_log_mutex); /* UNLOCK */
}


void
log_err(int errnum, const char fmt[], ...)
{
	int ret;
	va_list va;
	char dt[32];
	char buf[1024];
	const size_t len = LEN(buf);


	va_start(va, fmt);
	ret = vsnprintf(buf, len, fmt, va);
	va_end(va);

	if (ret <= 0)
		buf[0] = '\0';

	if ((size_t)ret >= len)
		buf[len - 1] = '\0';

	mtx_lock(&_log_mutex); /* LOCK */

	const char *const now = _log_datetime_now(dt, LEN(dt));
	if (errnum != 0)
		fprintf(stderr, "E: [%s]: %s: %s\n", now, buf, strerror(abs(errnum)));
	else
		fprintf(stderr, "E: [%s]: %s\n", now, buf);

	mtx_unlock(&_log_mutex); /* UNLOCK */
}


void
log_debug(const char fmt[], ...)
{
#ifdef DEBUG
	int ret;
	va_list va;
	char dt[32];
	char buf[1024];
	const size_t len = LEN(buf);


	va_start(va, fmt);
	ret = vsnprintf(buf, len, fmt, va);
	va_end(va);

	if (ret <= 0)
		buf[0] = '\0';

	if ((size_t)ret >= len)
		buf[len - 1] = '\0';

	mtx_lock(&_log_mutex); /* LOCK */
	fprintf(stderr, "D: [%s]: %s\n", _log_datetime_now(dt, LEN(dt)), buf);
	mtx_unlock(&_log_mutex); /* UNLOCK */
#else
	(void)fmt;
#endif
}

