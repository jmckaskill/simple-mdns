#pragma once
#include <stdint.h>
#include <stddef.h>

#define EMDNS_FINISHED 0
#define EMDNS_PENDING -1
#define EMDNS_TOO_MANY -2
#define EMDNS_MALFORMED -3
#define EMDNS_DUPLICATE -4
#define EMDNS_RESPOND 1

struct emdns_service {
	const uint8_t *name;
	size_t namesz;
	const uint8_t *txt;
	size_t txtsz;
	uint16_t port;
	unsigned respond; // internal
};

#define EMDNS_SERVICE(name, txt, port) {(uint8_t*)name, sizeof(name)-1, (uint8_t*)txt, sizeof(txt)-1, port, 0}

typedef uint32_t emdns_ip4_t;
typedef struct {uint8_t u[16];} emdns_ip6_t;

struct emdns_responder {
    emdns_ip4_t *ip4v;
	size_t ip4n;
	emdns_ip6_t *ip6v;
	size_t ip6n;
	struct emdns_service *svcv;
	size_t svcn;
	const char *label;
	size_t labelsz;
	const uint8_t *host;
	size_t hostsz;
};

int emdns_should_respond(struct emdns_responder *r, const void *msg, int sz);
int emdns_build_response(struct emdns_responder *r, void *buf, int sz);
