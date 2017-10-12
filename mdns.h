#pragma once
#include "ip6.h"

void send_mdns_broadcast();
void init_mdns();
void process_mdns(struct ip6_header *ip, struct udp_header *udp, const void *msg, int sz);
