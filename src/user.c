/*
 * Copyright (c) 2006-2009 Bjorn Andersson <flex@kryo.se>, Erik Ekman <yarrick@kryo.se>
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

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/ip.h>

#ifdef WINDOWS32
#include <winsock2.h>
#else
#include <netdb.h>
#endif

#include "common.h"
#include "encoding.h"
#include "user.h"
#include "ipal.h"

struct user users[USERS];

struct ipv6hdr_temp {
	char t1;
	char t2[3];
	short payload_len;
	char next_header;
	char hop_limit;
	struct in6_addr saddr;
	struct in6_addr daddr;
};
//yeyue

int
init_users_g(char* my_ip, int netbits)
{
	sa_family_t type;
	type = get_type(my_ip);
	if (type == AF_INET)
		return init_users(my_ip, netbits);
	else if (type == AF_INET6)
		return init_users_v6(my_ip, netbits);
	else
		return -1;
}

int
init_users_v6(char* my_ip, int netbits)
{
	int i;
	int skip = 0;
	char newip[128];
	char buf[INET6_ADDRSTRLEN];
	int created_users = 0;

	int maxusers;

	//in_addr_t netmask = 0;
	//struct in_addr net;
	//struct in_addr ipstart;
	//u_int8_t netmask[16] = {0};
	struct in6_addr netmask;
	struct in6_addr net;
	struct in6_addr ipstart;
	
	//memset(&net, 0, sizeof(struct in6_addr));
	//inet_pton(AF_INET6, &net, my_ip, sizeof(my_ip));
	/*for (i = 0; i < netbits; i++) {
		netmask = (netmask << 1) | 1;
	}
	netmask <<= (128 - netbits);*/
	in6_addr_netmask(&netmask, netbits);
	inet_pton(AF_INET6, my_ip, &net);
	
	//ipstart.s6_addr = net.s6_addr & netmask;
	in6_addr_and(&ipstart, &net, &netmask);

	maxusers = (1 << (128 - netbits)) - 3;
	
	memset(users, 0, USERS * sizeof(struct user));
	
	
	for (i = 0; i < USERS; i++) {
		struct in6_addr ip;
		//u_int8_t ip[16];
		struct in6_addr newip_n;
		users[i].id = 1;
		snprintf(newip, sizeof(newip), "::%d", i + skip + 1);
		inet_pton(AF_INET6, newip, &newip_n);
		//ip.s6_addr = ipstart.s6_addr + newip_n.s6_addr;
		in6_addr_add(&ip, &ipstart, &newip_n);
		if (memcmp(&ip, &net, sizeof(struct in6_addr)) == 0 && skip == 0) {
			skip++;
			snprintf(newip, sizeof(newip), "::%d", i + skip + 1);
			//ip.s6_addr = ipstart.s6_addr + newip_n.s6_addr;
			inet_pton(AF_INET6, newip, &newip_n);
			in6_addr_add(&ip, &ipstart, &newip_n);
		}
		inet_ntop(AF_INET6, &ip, buf, INET6_ADDRSTRLEN);
		//users[i].tun_ip = (char *)malloc(sizeof(buf) + 1);
		strncpy(users[i].tun_ip, buf, sizeof(users[i].tun_ip));
		users[i].tun_ip[INET6_ADDRSTRLEN] = '\0';
		if (maxusers--  < 1) {
			users[i].disabled = 1;
		} else {
			users[i].disabled = 0;
			created_users++;
		}
		users[i].active = 0;
	}

	return created_users;
}

int
init_users(char* my_ip, int netbits)
{
	int i;
	int skip = 0;
	char newip[16];
	int created_users = 0;

	int maxusers;

	in_addr_t netmask = 0;
	in_addr_t my_ip_addr = inet_addr(my_ip);
	struct in_addr net;
	struct in_addr ipstart;

	for (i = 0; i < netbits; i++) {
		netmask = (netmask << 1) | 1;
	}
	netmask <<= (32 - netbits);
	net.s_addr = htonl(netmask);
	ipstart.s_addr = my_ip_addr & net.s_addr;

	maxusers = (1 << (32-netbits)) - 3; /* 3: Net addr, broadcast addr, iodined addr */
	
	memset(users, 0, USERS * sizeof(struct user));
	for (i = 0; i < USERS; i++) {
		//yeyue
		//in_addr_t ip;
		struct in_addr ip;
		users[i].id = i;
		snprintf(newip, sizeof(newip), "0.0.0.%d", i + skip + 1);
		ip.s_addr = ipstart.s_addr + inet_addr(newip);
		if (ip.s_addr == my_ip_addr && skip == 0) {
			/* This IP was taken by iodined */
			skip++;
			snprintf(newip, sizeof(newip), "0.0.0.%d", i + skip + 1);
			ip.s_addr = ipstart.s_addr + inet_addr(newip);
		}
		strncpy(users[i].tun_ip, inet_ntoa(ip), sizeof(users[i].tun_ip));
		net.s_addr = ip.s_addr;
		if (maxusers--  < 1) {
			users[i].disabled = 1;
		} else {
			users[i].disabled = 0;
			created_users++;
		}
		users[i].active = 0;
 		/* Rest is reset on login ('V' packet) */
	}

	return created_users;
}

const char*
users_get_first_ip()
{
	/*struct in_addr ip;
	ip.s_addr = users[0].tun_ip;
	return inet_ntoa(ip);*/
	return users[0].tun_ip;
}

int
users_waiting_on_reply()
{
	int ret;
	int i;

	ret = 0;
	for (i = 0; i < USERS; i++) {
		if (users[i].active && !users[i].disabled && 
			users[i].last_pkt + 60 > time(NULL) &&
			users[i].q.id != 0 && users[i].conn == CONN_DNS_NULL) {
			ret++;
		}
	}
	
	return ret;
}

//yeyue
int
find_user_by_ip_g(unsigned char* header)
{
	int ret;
	int i;
	char version;
	char flag;
	void* ip4_dst = &((struct ip*)header)->ip_dst.s_addr;
	void* ip6_dst = &((struct ipv6hdr_temp*)header)->daddr;
	
	version = *header >> 4;
	if (version == 4) {
		flag = (memcmp(ip4_dst, users[i].tun_ip, sizeof(struct in_addr)) == 0);
	}
	else if (version == 6) {
		flag = (memcmp(ip6_dst, users[i].tun_ip, sizeof(struct in6_addr)) == 0);
	}
	else
		flag = 0;

	ret = -1;
	for (i = 0; i < USERS; i++) {
		if (users[i].active && !users[i].disabled &&
			users[i].last_pkt + 60 > time(NULL) &&
			flag) {
			ret = i;
			break;
		}
	}
	return ret;
}
//

int
find_user_by_ip(uint32_t ip)
{
	int ret;
	int i;

	ret = -1;
	for (i = 0; i < USERS; i++) {
		if (users[i].active && !users[i].disabled &&
			users[i].last_pkt + 60 > time(NULL) &&
			ip == inet_addr(users[i].tun_ip)) {
			ret = i;
			break;
		}
	}
	return ret;
}

int
all_users_waiting_to_send()
/* If this returns true, then reading from tun device is blocked.
   So only return true when all clients have at least one packet in
   the outpacket-queue, so that sending back-to-back is possible
   without going through another select loop.
*/
{
	time_t now;
	int ret;
	int i;

	ret = 1;
	now = time(NULL);
	for (i = 0; i < USERS; i++) {
		if (users[i].active && !users[i].disabled &&
			users[i].last_pkt + 60 > now &&
			((users[i].conn == CONN_RAW_UDP) || 
			((users[i].conn == CONN_DNS_NULL) 
#ifdef OUTPACKETQ_LEN
				&& users[i].outpacketq_filled < 1
#else
				&& users[i].outpacket.len == 0
#endif
			))) {

			ret = 0;
			break;
		}
	}
	return ret;
}

int
find_available_user()
{
	int ret = -1;
	int i;
	for (i = 0; i < USERS; i++) {
		/* Not used at all or not used in one minute */
		if ((!users[i].active || users[i].last_pkt + 60 < time(NULL)) && !users[i].disabled) {
			users[i].active = 1;
			users[i].last_pkt = time(NULL);
			users[i].fragsize = 4096;
			users[i].conn = CONN_DNS_NULL;
			ret = i;
			break;
		}
	}
	return ret;
}

void
user_switch_codec(int userid, struct encoder *enc)
{
	if (userid < 0 || userid >= USERS)
		return;
	
	users[userid].encoder = enc;
}

void
user_set_conn_type(int userid, enum connection c)
{
	if (userid < 0 || userid >= USERS)
		return;

	if (c < 0 || c >= CONN_MAX)
		return;
	
	users[userid].conn = c;
}
	
