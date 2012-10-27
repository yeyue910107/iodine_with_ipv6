/*
 * Copyright (c) 2011-2012 Zhe Zhang <bleastrind@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "ipal.h"

#include <stdio.h>
#include <memory.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netdb.h>
#include <assert.h>

const struct sockaddr_in sockaddr_any = {AF_INET, 0, {0}, {0}};
const struct sockaddr_in6 sock6addr_any = {AF_INET6, 0, 0, {{{0}}}, 0};

static char err_msg[256];

sa_family_t
get_type(const char* cp){
	static char addr[MAX(sizeof(struct in_addr),sizeof(struct in6_addr))];
	if (inet_pton(AF_INET, cp, addr) == 1){
		return AF_INET;
	}else if(inet_pton(AF_INET6, cp, addr) == 1){
		return AF_INET6;
	}else
		return AF_UNSPEC;
}

int
get_mtu(const char* cp, int mtu)
{
	sa_family_t family = get_type(cp);
	if (mtu == 0) {
		if (family == AF_INET)
			mtu = 1130;/* Very many relays give fragsize 1150 or slightly
				   higher for NULL; tun/zlib adds ~17 bytes. */
		else if (family == AF_INET6)
			mtu = 1280;/* change to 1280 to meet the minimal requirement of ipv6*/
	}
	return mtu;
}

int
if_setip4(const char* if_name, const char *ip, const char *remoteip, int netbits)
{
	char cmdline[512];
	int netmask;
	struct in_addr net;
	int i;
#ifndef LINUX
	int r;
#endif
#ifdef WINDOWS32
	DWORD status;
	DWORD ipdata[3];
	struct in_addr addr;
	DWORD len;
#endif

	netmask = 0;
	for (i = 0; i < netbits; i++) {
		netmask = (netmask << 1) | 1;
	}
	netmask <<= (32 - netbits);
	net.s_addr = htonl(netmask);

	if (inet_addr(ip) == INADDR_NONE) {
		fprintf(stderr, "Invalid IP: %s!\n", ip);
		return 1;
	}
#ifndef WINDOWS32
	snprintf(cmdline, sizeof(cmdline),
			"/sbin/ifconfig %s %s %s netmask %s",
			if_name,
			ip,
#ifdef FREEBSD
			remoteip, /* FreeBSD wants other IP as second IP */
#else
			ip,
#endif
			inet_ntoa(net));

	fprintf(stderr, "Setting IP of %s to %s\n", if_name, ip);
#ifndef LINUX
	r = system(cmdline);
	if(r != 0) {
		return r;
	} else {
		snprintf(cmdline, sizeof(cmdline),
				"/sbin/route add %s/%d %s",
				ip, netbits, ip);
	}
	fprintf(stderr, "Adding route %s/%d to %s\n", ip, netbits, ip);
#endif
	return system(cmdline);
#else /* WINDOWS32 */

	/* Set device as connected */
	fprintf(stderr, "Enabling interface '%s'\n", if_name);
	status = 1;
	r = DeviceIoControl(dev_handle, TAP_IOCTL_SET_MEDIA_STATUS, &status,
		sizeof(status), &status, sizeof(status), &len, NULL);
	if (!r) {
		fprintf(stderr, "Failed to enable interface\n");
		return -1;
	}

	if (inet_aton(ip, &addr)) {
		ipdata[0] = (DWORD) addr.s_addr;   /* local ip addr */
		ipdata[1] = net.s_addr & ipdata[0]; /* network addr */
		ipdata[2] = (DWORD) net.s_addr;    /* netmask */
	} else {
		return -1;
	}

	/* Tell ip/networkaddr/netmask to device for arp use */
	r = DeviceIoControl(dev_handle, TAP_IOCTL_CONFIG_TUN, &ipdata,
		sizeof(ipdata), &ipdata, sizeof(ipdata), &len, NULL);
	if (!r) {
		fprintf(stderr, "Failed to set interface in TUN mode\n");
		return -1;
	}

	/* use netsh to set ip address */
	fprintf(stderr, "Setting IP of interface '%s' to %s (can take a few seconds)...\n", if_name, ip);
	snprintf(cmdline, sizeof(cmdline), "netsh interface ip set address \"%s\" static %s %s",
		if_name, ip, inet_ntoa(net));
	return system(cmdline);
#endif
}

int
if_setip6(const char* if_name, const char *ip, const char *remoteip, int netbits)
{
	char cmdline[512];
	struct in6_addr addr;
#ifndef LINUX
	int r;
#endif
#ifdef WINDOWS32
	fprintf(stderr,"Don't support windows on IPv6\n!");
	return -1;
#endif
	if (inet_pton( AF_INET6, ip, &addr) == 0) {
		fprintf(stderr, "Invalid IP: %s!\n", ip);
		return 1;
	}
#ifndef WINDOWS32
	snprintf(cmdline, sizeof(cmdline),
			"/sbin/ifconfig %s inet6 add %s/%d",
			if_name,
			ip,
			netbits);

	fprintf(stderr, "Setting IP of %s to %s\n", if_name, ip);
#ifndef LINUX
	r = system(cmdline);
	if(r != 0) {
		return r;
	} else {
		snprintf(cmdline, sizeof(cmdline),
				"/sbin/route add %s/%d %s",
				ip, netbits, ip);
	}
	fprintf(stderr, "Adding route %s/%d to %s\n", ip, netbits, ip);
#endif
	return system(cmdline);
#else /* WINDOWS32 */
	return -1;
#endif
}

int
setip(const char* if_name, const char* ip, const char* ip2, int netbits){
	sa_family_t type;

	type = get_type(ip);
	if( type == AF_INET ){
		return if_setip4( if_name, ip, ip2, netbits);
	}else if( type == AF_INET6 ){
		return if_setip6( if_name, ip, ip2, netbits);
	}else{
		fprintf(stderr, "Invalid IP: %s!\n", ip);
		return 1;
	}

}

sa_family_t
resolve_addr( const char* cp, void* addr ){

	if (inet_pton(AF_INET, cp, addr) == 1){
		return AF_INET;
	}else if(inet_pton(AF_INET6, cp, addr) == 1){
		return AF_INET6;
	}else{	/* try resolving if a domain is given */
		struct addrinfo hints, *res;
		int status;
		const char *err;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		if((status = getaddrinfo(cp, NULL, &hints, &res)) == 0){
			char ipstr[INET6_ADDRSTRLEN];

			assert(res != NULL);

			if(res->ai_family == AF_INET){
				memcpy(addr ,
						&((struct sockaddr_in*)res->ai_addr)->sin_addr,
						sizeof(struct in_addr));
			}else{
				memcpy(addr ,
						&((struct sockaddr_in6*)res->ai_addr)->sin6_addr,
						sizeof(struct in6_addr));
			}

			inet_ntop(res->ai_family, addr, ipstr, sizeof(ipstr));
			fprintf(stderr, "Resolved %s to %s\n", cp, ipstr);

			return res->ai_family;
		}else{
			err = gai_strerror(status);
		}

#ifndef WINDOWS32
		err = hstrerror(h_errno);
#else
		{
			DWORD wserr = WSAGetLastError();
			switch (wserr) {
			case WSAHOST_NOT_FOUND:
				err = "Host not found";
				break;
			case WSANO_DATA:
				err = "No data record found";
				break;
			default:
				err = "Unknown error";
				break;
			}
		}
#endif /* !WINDOWS32 */
		strncpy(err_msg, err, sizeof(err_msg) - 1);
	}
	return 0;
}

int
get_addr(struct sockaddr_storage* sock, char* buf, size_t bufsize){
	void * addr;
	if(sock->ss_family == AF_INET)
		addr = &((struct sockaddr_in*)sock)->sin_addr;
	else if(sock->ss_family == AF_INET6)
		addr = &((struct sockaddr_in6*)sock)->sin6_addr;
	else
		return 0;
	inet_ntop(sock->ss_family, addr, buf, bufsize);

	return strlen(buf);
}

void
set_port(struct sockaddr_storage* sock, in_port_t port){
	if(sock->ss_family == AF_INET)
		((struct sockaddr_in*)sock)->sin_port = port;
	else if(sock->ss_family == AF_INET6)
		((struct sockaddr_in6*)sock)->sin6_port = port;
}

void
set_addr(struct sockaddr_storage* sock, void * addr){
	if(sock->ss_family == AF_INET)
		memcpy(&((struct sockaddr_in*)sock)->sin_addr, addr, sizeof(struct in_addr));
	else if(sock->ss_family == AF_INET6)
		memcpy(&((struct sockaddr_in6*)sock)->sin6_addr, addr, sizeof(struct in6_addr));
}

void
set_socket(struct sockaddr_storage* sock, const char* cp, int port){
	static char buf[129];

	sock->ss_family = resolve_addr(cp, buf);
	set_addr(sock, buf);
	set_port(sock, htons(port));
}

char* getlasterror(){
	return err_msg;
}

//yeyue
/*
operations of IPv6 addr
*/
void
in6_addr_add(struct in6_addr* dst, struct in6_addr* src1, struct in6_addr* src2)
{
	int i;
	int temp1;
	u_int8_t temp2 = 0;
	for (i = 15; i >= 0; i--)
	{
		temp1 = (u_int16_t)src1->s6_addr[i] + src2->s6_addr[i] + temp2;
		if (temp1 >= 256)
		{
			dst->s6_addr[i] = temp1 - 256;
			temp2 = 1;
		}
		dst->s6_addr[i] = temp1;
		temp2 = 0;
	}
}

void
in6_addr_netmask(struct in6_addr* addr_any, int netbits)
{
	int i, j;
	for (i = 0; i < 16; i++) {
		for (j = 0; netbits > 0 && j < 8; netbits--, j++)
			addr_any->s6_addr[i] = (addr_any->s6_addr[i]) << 1 | 1;
	}
}

void
in6_addr_and(struct in6_addr* dst, struct in6_addr* src1, struct in6_addr* src2)
{
	int i;
	int temp1;
	u_int8_t temp2 = 0;
	for (i = 15; i >= 0; i--)
	{
		temp1 = ((u_int16_t)src1->s6_addr[i] & src2->s6_addr[i]) + temp2;
		if (temp1 >= 256)
		{
			dst->s6_addr[i] = temp1 - 256;
			temp2 = 1;
		}
		dst->s6_addr[i] = temp1;
		temp2 = 0;
	}
}

