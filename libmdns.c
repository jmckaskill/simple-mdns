#include "libmdns.h"
#include "../hw/copy.h"
#include "../hw/endian.h"
#include <stdbool.h>

#define MIN_MESSAGE_SIZE 512

#define RCLASS_IN 1
#define RCLASS_IN_FLUSH 0x8001
#define RCLASS_MASK 0x7FFF

#define RTYPE_A 1
#define RTYPE_AAAA 28
#define RTYPE_SRV 33
#define RTYPE_TXT 16
#define RTYPE_PTR 12
#define RTYPE_NSEC 47

#define LABEL_MASK 0xC0
#define LABEL_NORMAL 0x00
#define LABEL_PTR 0xC0
#define LABEL_PTR16 0xC000

#define FLAG_RESPONSE 0x8000
#define FLAG_AUTHORITY 0x0400

#define TTL_DEFAULT 120
#define MAX_TTL (10*24*3600)
#define PRIORITY_DEFAULT 0
#define WEIGHT_DEFAULT 0

#define MAX_ADDRS 5
#define MAX_SCANS 5
#define MAX_IPS 5
#define MAX_SERVICES 5

#define ID_ADDR 1
#define ID_SCAN (ID_ADDR + MAX_ADDRS)
#define ID_IP (ID_SCAN + MAX_SCANS)
#define ID_SERVICE (ID_IP + MAX_IPS)
#define ID_LAST (ID_SERVICE + MAX_SERVICES)

#define MAX_LABEL_SIZE 63
#define MAX_HOST_SIZE 255

#define assert(x) do{}while(0)

static uint8_t lower(uint8_t ch) {
    if ('A' <= ch && ch <= 'Z') {
        return ch - 'A' + 'a';
    } else {
        return ch;
    }
}

static bool equals_dns_label(const uint8_t *a, const uint8_t *b, int len) {
    while (len) {
        if (lower(*a) != lower(*b)) {
            return false;
        }
        a++;
        b++;
        len--;
    }
    return true;
}

static bool equals_dns_name(const uint8_t *a, const uint8_t *b) {
    for (;;) {
		uint8_t alen = *(a++);
		uint8_t blen = *(b++);
		if (alen != blen) {
			return false;
		}
		if (!alen) {
			return true;
        }
		if (!equals_dns_label(a, b, alen)) {
			return false;
		}
		a += alen;
		b += blen;
	}
}

#define MAX_LABEL_REDIRECTS 5

// decodes a dns name from an incoming message, decompressing as we go
// poff points to the current offset into the message
// it is updated to the offset of the next field after the name
// returns -ve on error
// returns length on success
static int decode_dns_name(uint8_t *buf, const void *msg, int sz, int *poff) {
	int redirects = 0;
	int off = *poff;
    uint8_t *u = (uint8_t*) msg;
    
	int w = 0;

	for (;;) {
		if (off >= sz) {
			return -1;
		}

		uint8_t labelsz = u[off++];

		switch (labelsz & LABEL_MASK) {
		case LABEL_PTR:
			if (off == sz || ++redirects >= MAX_LABEL_REDIRECTS) {
				return -1;
			}
			if (poff) {
				*poff = off+1;
				poff = NULL;
			}
			off = (uint16_t) ((labelsz &~LABEL_MASK) << 8) | (uint16_t) u[off];
			break;
		case LABEL_NORMAL:
			if (labelsz == 0) {
                goto end;
			}

			off--;
			if (off + 1 + labelsz > sz || w + 1 + labelsz + 1 > MAX_HOST_SIZE) {
				return -1;
			}

			copy_unaligned(buf + w, u + off, 1 + labelsz);
			off += 1+ labelsz;
			w += 1 + labelsz;

			if (poff) {
				*poff = off;
			}
			break;
		default:
			return -1;
		}
    }

end:
    if (poff) {
        *poff = off;
    }
    buf[w++] = 0;
    assert(w <= MAX_HOST_SIZE);

    return w;
}

int emdns_should_respond(struct emdns_responder *r, const void *msg, int sz) {
	if (sz < 12) {
		return EMDNS_MALFORMED;
	}

	uint8_t *u = (uint8_t*) msg;
	uint16_t flags = big_16(u + 2);
	uint16_t question_num = big_16(u + 4);
	uint16_t answer_num = big_16(u + 6);
	uint16_t auth_num = big_16(u + 8);
	uint16_t additional_num = big_16(u + 10);
	int off = 12;
	int possible_answers = 0;

	if (flags & FLAG_RESPONSE) {
		return 0;
	}

	if (auth_num || additional_num) {
		return EMDNS_MALFORMED;
	}

	for (size_t i = 0; i < r->svcn; i++) {
		r->svcv[i].respond = 0;
	}

	while (question_num--) {
		uint8_t name[MAX_HOST_SIZE];
		int namesz = decode_dns_name(name, u, sz, &off);
		if (namesz < 0 || off + 4 > sz) {
			return EMDNS_MALFORMED;
		}

		uint8_t labelsz = name[0];
		uint16_t rtype = big_16(u + off);
		uint16_t rclass = big_16(u + off + 2) & RCLASS_MASK;
		off += 4;

		if (rclass != RCLASS_IN) {
			continue;
		}

		switch (rtype) {
		case RTYPE_A:
		case RTYPE_AAAA:
			if (r->hostsz == (size_t) namesz && equals_dns_name(r->host, name)) {
				return EMDNS_RESPOND;
			}
			break;
		case RTYPE_SRV:
		case RTYPE_TXT:
			if (r->labelsz == (size_t) labelsz && equals_dns_label(name + 1, (uint8_t*) r->label, labelsz)) {
				for (size_t i = 0; i < r->svcn; i++) {
					struct emdns_service *s = &r->svcv[i];
					if (s->namesz == (size_t) (namesz - labelsz - 1) && equals_dns_name(s->name, name + labelsz + 1)) {
						return EMDNS_RESPOND;
					}
				}
			}
			break;
		case RTYPE_PTR:
			for (size_t i = 0; i < r->svcn; i++) {
				struct emdns_service *s = &r->svcv[i];
				if (!s->respond && s->namesz == (size_t) namesz && equals_dns_name(s->name, name)) {
					s->respond = 1;
					possible_answers++;
				}
			}
		}

	}

	if (!possible_answers) {
		return 0;
	}

	while (answer_num--) {
		uint8_t svc[MAX_HOST_SIZE];
		int svcsz = decode_dns_name(svc, u, sz, &off);
		if (svcsz < 0 || off + 10 > sz) {
			return EMDNS_MALFORMED;
		}

		uint16_t rtype = big_16(u + off);
		uint16_t rclass = big_16(u + off + 2);
		uint32_t ttl = big_32(u + off + 4);
		uint16_t datasz = big_16(u + off + 8);
		int dataoff = off + 10;
		off += 10 + datasz;

		(void) ttl; // TODO check ttl

		if (off > sz) {
			return EMDNS_MALFORMED;
		}

		if (rclass != RCLASS_IN || rtype != RTYPE_PTR) {
			continue;
		}

		uint8_t name[MAX_HOST_SIZE];
		int namesz = decode_dns_name(name, u, sz, &dataoff);
		if (namesz < 0 || dataoff != off) {
			return EMDNS_MALFORMED;
		}

		uint8_t labelsz = name[0];
		if (namesz != svcsz + labelsz + 1 || !equals_dns_name(svc, name + 1 + labelsz)) {
			continue;
		}

		if (labelsz != r->labelsz || equals_dns_label(name + 1, (uint8_t*) r->label, labelsz)) {
			continue;
		}

		for (size_t i = 0; i < r->svcn; i++) {
			struct emdns_service *s = &r->svcv[i];
			if (s->respond && s->namesz == (size_t) svcsz && equals_dns_name(svc, s->name)) {
				if (--possible_answers == 0) {
					return 0;
				}
			}
		}
	}

	if (possible_answers) {
		return EMDNS_RESPOND;
	}

	return 0;
}

static int encode_address(const uint8_t *host, int hostsz, bool is_ip6, const void *addr, uint8_t *buf, int sz, int *off, int *hostoff) {
    int datasz = is_ip6 ? 16 : 4;
    int reqsz = (*hostoff ? 2 : hostsz) + 2 /*type*/ + 2 /*class*/ + 4 /*ttl*/ + 2 /*datasz*/ + datasz;

	if (*off + reqsz > sz) {
		return -1;
	}

	uint8_t *p = buf + *off;
	if (*hostoff) {
		write_big_16(p, LABEL_PTR16 | (uint16_t) *hostoff);
		p += 2;
	} else {
		*hostoff = *off;
		copy_unaligned(p, host, hostsz);
		p += hostsz;
	}
	write_big_16(p, is_ip6 ? RTYPE_AAAA : RTYPE_A);
	write_big_16(p + 2, RCLASS_IN_FLUSH);
	write_big_32(p + 4, TTL_DEFAULT);
	write_big_16(p + 8, (uint16_t) datasz);
	p += 10;
	copy_unaligned(p, addr, datasz);
	p += datasz;

	*off += reqsz;
	assert(p - buf == *off);
	return 0;
}

static int encode_nsec(int ip4, int ip6, uint8_t *buf, int sz, int *off, int hostoff) {
    uint32_t bitmap = 0;
    if (ip4) {
        bitmap |= 1 << (RTYPE_A - 1);
    }
    if (ip6) {
        bitmap |= 1 << (RTYPE_AAAA - 1);
    }
	uint16_t bitmapsz = sizeof(bitmap);
	uint16_t datasz = 2 /*next name*/ + 2 /*bitmap size*/ + bitmapsz;
	int reqsz = 2 /*name*/ + 2 /*type*/ + 2 /*class*/ + 4 /*ttl*/ + 2 /*datasz*/ + datasz;

	if (*off + reqsz > sz) {
		return -1;
	}

	uint8_t *p = buf + *off;
	write_big_16(p, LABEL_PTR16 | (uint16_t) hostoff);
	write_big_16(p + 2, RTYPE_NSEC);
	write_big_16(p + 4, RCLASS_IN_FLUSH);
	write_big_32(p + 6, TTL_DEFAULT);
	write_big_16(p + 10, datasz);
	write_big_16(p + 12, LABEL_PTR16 | (uint16_t) hostoff);
	write_big_16(p + 14, bitmapsz);
    p += 16;
    write_little_32(p, bitmap);
    p += 4;

	*off += reqsz;
	assert(p - buf == *off);
	return 0;
}

static int encode_service(const char *label, size_t labelsz, const uint8_t *svc, size_t svcsz, const uint8_t *host, size_t hostsz, const uint8_t *txt, size_t txtsz, uint16_t port, uint8_t *u, int sz, int *poff, int *hostoff) {
    // SRV
    int srvdatasz = 2 /*pri*/ + 2 /*weight*/ + 2 /*port*/ + (*hostoff ? 2 : hostsz);
	int reqsz = 1 + labelsz + svcsz + 2 /*type*/ + 2 /*class*/ + 4 /*ttl*/ + 2 /*datasz*/ + srvdatasz;
	// TXT
	reqsz += 2 /*name*/ + 2 /*type*/ + 2 /*class*/ + 4 /*ttl*/ + 2 /*datasz*/ + txtsz;
	// PTR
	reqsz += 2 /*name*/ + 2 /*type*/ + 2 /*class*/ + 4 /*ttl*/ + 2 /*datasz*/ + 2 /*srv name*/;

	if (*poff + reqsz > sz) {
		return -1;
	}

	// SRV
	uint8_t *p = u + *poff;
	uint16_t nameoff = (uint16_t) *poff;
	uint16_t svcoff = nameoff + (uint16_t) labelsz + 1;
	*(p++) = (uint8_t) labelsz;
	copy_unaligned(p, label, labelsz);
	p += labelsz;
	copy_unaligned(p, svc, svcsz);
	p += svcsz;
	write_big_16(p, RTYPE_SRV);
	write_big_16(p + 2, RCLASS_IN_FLUSH);
	write_big_32(p + 4, TTL_DEFAULT);
	write_big_16(p + 8, (uint16_t) srvdatasz);
	write_big_16(p + 10, PRIORITY_DEFAULT);
	write_big_16(p + 12, WEIGHT_DEFAULT);
	write_big_16(p + 14, port);
	p += 16;
	if (*hostoff) {
        write_big_16(p, LABEL_PTR16 | (uint16_t) *hostoff);
        p += 2;
	} else {
		*hostoff = (int) (p - u);
		copy_unaligned(p, host, hostsz);
		p += hostsz;
	}

	// TXT
	write_big_16(p, LABEL_PTR16 | (uint16_t) nameoff);
	write_big_16(p + 2, RTYPE_TXT);
	write_big_16(p + 4, RCLASS_IN_FLUSH);
	write_big_32(p + 6, TTL_DEFAULT);
	write_big_16(p + 10, (uint16_t) txtsz);
    p += 12;
	copy_unaligned(p, txt, txtsz);
	p += txtsz;

	// PTR
	write_big_16(p, LABEL_PTR16 | svcoff);
	write_big_16(p + 2, RTYPE_PTR);
	write_big_16(p + 4, RCLASS_IN);
	write_big_32(p + 6, TTL_DEFAULT);
	write_big_16(p + 10, 2); /*datasz*/
	write_big_16(p + 12, LABEL_PTR16 | (uint16_t) nameoff);
	p += 14;

	*poff += reqsz;
	assert(u + *poff == p);
	return 0;
}



int emdns_build_response(struct emdns_responder *r, void *buf, int sz) {
	if (sz < 12) {
		return EMDNS_MALFORMED;
	}

    int hostoff = 0;
    uint16_t answers = 0;
    uint8_t *u = (uint8_t*) buf;
	int off = 12;

	for (size_t i = 0; i < r->ip4n; i++) {
		if (encode_address(r->host, r->hostsz, false, &r->ip4v[i], u, sz, &off, &hostoff)) {
			return EMDNS_TOO_MANY;
        }
        answers++;
	}
	for (size_t i = 0; i < r->ip6n; i++) {
		if (encode_address(r->host, r->hostsz, true, &r->ip6v[i], u, sz, &off, &hostoff)) {
			return EMDNS_TOO_MANY;
        }
        answers++;
    }
    if (r->ip4n || r->ip6n) {
        if (encode_nsec(r->ip4n, r->ip6n, u, sz, &off, hostoff)) {
            return EMDNS_TOO_MANY;
        }
        answers++;
    }
	for (size_t i = 0; i < r->svcn; i++) {
		struct emdns_service *s = &r->svcv[i];
		if (encode_service(r->label, r->labelsz, s->name, s->namesz, r->host, r->hostsz, s->txt, s->txtsz, s->port, u, sz, &off, &hostoff)) {
			return EMDNS_TOO_MANY;
        }
        answers += 3;
    }
    
    write_big_16(u, 0); // transaction id
    write_big_16(u+2, FLAG_RESPONSE | FLAG_AUTHORITY);
    write_big_16(u+4, 0); // questions
    write_big_16(u+6, answers);
    write_big_16(u+8, 0); // authority
    write_big_16(u+10, 0); // additional 

	return off;
}

