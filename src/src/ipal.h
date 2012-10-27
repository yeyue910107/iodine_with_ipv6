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

#ifndef __IPAL_H__
#define __IPAL_H__
/*
 * IP Abstract Level
 *
 * This module abstract the operation on ipv4 and ipv6
 *
 * Linux support only
 * */

#include <netinet/in.h>

extern const struct sockaddr_in sockaddr_any;
extern const struct sockaddr_in6 sock6addr_any;

#define SOCKET_LEN(x) (*((sa_family_t *)&(x)) == AF_INET ? sizeof(struct sockaddr_in) : ( *((sa_family_t *)&(x)) == AF_INET6 ? sizeof(struct sockaddr_in6) : 0))

sa_family_t get_type(const char* cp);
/*
 * assign ip to a given interface
 * for freebsd system, a second IP is needed
 */
int setip(const char* ifname, const char* ip, const char* ip2, int netbits);

/*
 * Convert a string of ipv4,ipv6 or domain name to the struct sockaddr
 * return 0 if failed, otherwise the type of the address family.
 *  */
sa_family_t resolve_addr(const char* cp, void* addr);

/*
 * return the size of the string
 */
int get_addr(struct sockaddr_storage* sock, char* buf, size_t bufsize);


void set_socket(struct sockaddr_storage* sock, const char* cp, int port);


char* getlasterror();
#endif /* _IPAL_H_ */
