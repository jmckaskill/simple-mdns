#pragma once

#ifdef _WIN32
#include <WS2tcpip.h>
#include <winsock2.h>
#else
#include <unistd.h>
#endif

struct emdns_interface {
	int id;
	const struct in_addr *ip4;
	const struct in6_addr *ip6;
	int ip6_num;
#ifdef _WIN32
	const wchar_t *name;
	const wchar_t *description;
#else
	const char *name;
#endif
};

typedef int(*emdns_ifcb)(void* udata, const struct emdns_interface *iface);
int emdns_lookup_interfaces(void *udata, emdns_ifcb cb);


// emdns_bind6 creates and binds an IPv6 socket bound to the correct port
// with the request multicast address setup.
// sa returns the address packets should be sent to/from
// the socket is bound to the interface specified
// this is only implemented for mainstream operating systems
int emdns_bind6(int interface_id, struct sockaddr_in6 *send_addr);
int emdns_bind4(struct in_addr interface_addr, struct sockaddr_in *send_addr);
