#include "mdns.h"
#include "hw/tick.h"
#include "hw/debug.h"
#include "hw/endian.h"
#include "mdns/libmdns.h"

#define MDNS_PORT 5353

static const ip6_addr_t g_mdns      = {{0xFF,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0xFB}};
static const mac_addr_t g_mdns_mac      = {{0x33,0x33,0,0,0,0xFB}};



static unsigned g_last_mdns;
static struct emdns_service g_mdns_services[1] = {
	EMDNS_SERVICE("\x05_http\x04_tcp\x05local\0", "\0", 80),
};
#define PFX "ethboot_"
static char g_mdns_label[] = PFX "001122334455";
static char g_mdns_host[] = "\0" PFX "001122334455\x05local\0";
static struct emdns_responder g_mdns_responder = {
	NULL, 0,
	(emdns_ip6_t*) &g_my_ip, 1,
	g_mdns_services, 1,
	g_mdns_label, sizeof(g_mdns_label)-1,
	(uint8_t*) g_mdns_host, sizeof(g_mdns_host)-1,
};

void send_mdns_broadcast() {
	struct ip6_header *ip = new_ip6_frame(&g_mdns_mac, &g_mdns, IP6_UDP);
	if (ip) {
		struct udp_header *udp = (struct udp_header*) (ip+1);
		write_big_16(udp->src_port, MDNS_PORT);
		write_big_16(udp->dst_port, MDNS_PORT);
		int mdnssz = emdns_build_response(&g_mdns_responder, udp+1, MAX_UDP_SIZE);
		int udpsz = mdnssz + sizeof(*udp);
		write_big_16(udp->length, (uint16_t) udpsz);
		write_big_16(udp->checksum, 0);
		write_big_16(udp->checksum, ones_checksum(ip, udpsz));

		send_ip6_frame(ip, udpsz);
		g_last_mdns = tick_count();
	}
}

void process_mdns(struct ip6_header *ip, struct udp_header *udp, const void *msg, int sz) {
	if (big_16(udp->src_port) == MDNS_PORT
	&& big_16(udp->dst_port) == MDNS_PORT
	&& ip6_equals(&ip->ip6_dst, &g_mdns)
	&& (tick_count() - g_last_mdns >= MS_TO_TICKS(1000))
	&& emdns_should_respond(&g_mdns_responder, msg, sz) == EMDNS_RESPOND) {
		send_mdns_broadcast();
	}
}

void init_mdns() {
	char *label = g_mdns_label + sizeof(PFX) - 1;
	char *host = g_mdns_host + 1 + sizeof(PFX) - 1;
	for (int i = 0; i < 6; i++) {
		host[2*i] = label[2*i] = hex[g_my_mac.u[i] >> 4];
		host[2*i+1] = label[2*i+1] = hex[g_my_mac.u[i] & 15];
	}
	g_mdns_host[0] = sizeof(PFX)-1 + 12;

	send_mdns_broadcast();
}
