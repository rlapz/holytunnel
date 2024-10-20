#ifndef __CONFIG_H__
#define __CONFIG_H__


#define CFG_BUFFER_SIZE           (8192)
#define CFG_CLIENT_MIN_SIZE       (32)
#define CFG_SERVER_ADDR           "127.0.0.1"
#define CFG_SERVER_PORT           "5395"
#define CFG_EVENT_SIZE            (32)
#define CFG_EVENT_TIMEOUT         (500)      /* ms */
#define CFG_BLOCKING_SEND_TIMEOUT (3)        /* s */

#define CFG_HTTP_HEADER_SIZE  (128)
#define CFG_HTTP_CHUNK_SIZE   (3)
#define CFG_HTTPS_RESPONSE_OK "HTTP/1.1 200 OK\r\n\r\n"
#define CFG_HTTPS_CHUNK_SIZE  (13)

#define CFG_RESOLVER_HTTP_TIMEOUT (5) /* seconds */

#define CFG_DOH_ADGUARD    "https://dns.adguard-dns.com/resolve"
#define CFG_DOH_CLOUDFLARE "https://cloudflare-dns.com/dns-query"
#define CFG_DOH_GOOGLE     "https://dns.google/resolve"

#define CFG_HOST_NAME_SIZE  (256)
#define CFG_HOST_ARRAY_SIZE (128)
#define CFG_HOST_EXP_TIME   (1200)   /* seconds */


typedef struct config {
	const char *listen_host;
	int         listen_port;
	int         resolver_type;
	const char *resolver_doh_url;
} Config;


#endif

