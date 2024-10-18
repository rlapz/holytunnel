#ifndef __UTIL_H__
#define __UTIL_H__


#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <threads.h>

#include <sys/socket.h>

#include "config.h"
#include "picohttpparser.h"


#define LEN(X)                          ((sizeof(X) / sizeof(*X)))
#define FIELD_PARENT_PTR(T, FIELD, PTR) ((T *)(((char *)(PTR)) - offsetof(T, FIELD)))


/*
 * DList
 */
typedef struct dlist_node {
	struct dlist_node *next;
	struct dlist_node *prev;
} DListNode;

typedef struct dlist {
	DListNode *first;
	DListNode *last;
} DList;

void       dlist_init(DList *d);
void       dlist_append(DList *d, DListNode *node);
void       dlist_prepend(DList *d, DListNode *node);
void       dlist_remove(DList *d, DListNode *node);
DListNode *dlist_pop(DList *d);


/*
 * Mempool
 */
typedef void (*MempoolCallbackFn)(void *mem, void *udata);

typedef struct mempool_item MempoolItem;
struct mempool_item {
	DListNode node;
	char      udata[];
};

typedef struct mempool {
	size_t chunk;
	DList  active;
	DList  inactive;
	mtx_t  mutex;
} Mempool;

int   mempool_init(Mempool *m, size_t chunk, size_t size);
void  mempool_deinit(Mempool *m, MempoolCallbackFn on_destroy_active_item, void *udata);
void *mempool_alloc(Mempool *m);
void  mempool_free(Mempool *m, void *mem);


/*
 * CstrMap
 */
typedef struct cstrmap_item {
	const char *key;
	void       *val;
} CstrMapItem;

typedef struct cstrmap {
	size_t       size;
	CstrMapItem *items;
} CstrMap;

int   cstrmap_init(CstrMap *c, size_t size);
void  cstrmap_deinit(CstrMap *c);
int   cstrmap_set(CstrMap *c, const char key[], void *val);
void *cstrmap_get(CstrMap *c, const char key[]);
void *cstrmap_del(CstrMap *c, const char key[]);


/*
 * Str
 */
typedef struct str {
	int     is_alloc;
	size_t  size;
	size_t  len;
	char   *cstr;
} Str;

int   str_init(Str *s, char buffer[], size_t size);
int   str_init_alloc(Str *s, size_t size);
void  str_deinit(Str *s);
char *str_append_n(Str *s, const char cstr[], size_t len);
char *str_set_n(Str *s, const char cstr[], size_t len);
char *str_set_fmt(Str *s, const char fmt[], ...);
char *str_append_fmt(Str *s, const char fmt[], ...);


/*
 * Http
 */
typedef struct phr_header HttpHeader;

typedef struct http_request {
	size_t      method_len;
	const char *method;
	size_t      path_len;
	const char *path;
	int32_t     version;
	size_t      headers_len;
	HttpHeader  headers[CFG_HTTP_HEADER_SIZE];
} HttpRequest;

static inline int
http_request_parse(HttpRequest *h, const char buffer[], size_t len, size_t last_len)
{
	return phr_parse_request(buffer, len, &h->method, &h->method_len, &h->path, &h->path_len,
				 &h->version, h->headers, &h->headers_len, last_len);
}

int         http_init(void);
void        http_deinit(void);
const char *http_request(Str *buffer, const char url[]);


/*
 * Url
 */
typedef struct uri {
        char *host;
        char *port;
} Url;

/* @host_port: [host:port]
 *
 * examples:
 *
 * https://abcdef.com:80/path/a/b/c
 * result:
 *   host:     abcdef.com
 *   host_len: 10
 *   port:     80
 *
 * http://abcdef.com/path/a/b/c
 * result:
 *   host:     abcdef.com
 *   host_len: 10
 *   port:     80
 *
 * https://abcdef.com/path/a/b/c
 * result:
 *   host:     abcdef.com
 *   host_len: 10
 *   port:     443
 */
int  url_parse(Url *a, const char url[], int len, const char default_port[]);
void url_free(Url *a);


/*
 * net
 */
/* ret:
 *  -1: error
 *   0: timeout
 *   1: ok
 */
int net_blocking_send(int fd, const char buffer[], size_t *len, int timeout);


/*
 * Log
 */
int  log_init(void);
void log_deinit(void);
void log_err(int errnum, const char fmt[], ...);
void log_debug(const char fmt[], ...);
void log_info(const char fmt[], ...);


#endif

