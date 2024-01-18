/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 1998-2013 Sourcefire, Inc.
** Adam Keeton
** Kevin Liu <kliu@sourcefire.com>
*
** $ID: $
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

/*
 * Adam Keeton
 * sf_ip.h
 * 11/17/06
*/

#ifndef SF_IP_H
#define SF_IP_H

#ifndef WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

/* define SFIP_ROBUST to check pointers passed into the sfip libs.
 * Robustification should not be enabled if the client code is trustworthy.
 * Namely, if pointers are checked once in the client, or are pointers to
 * data allocated on the stack, there's no need to check them again here.
 * The intention is to prevent the same stack-allocated variable from being
 * checked a dozen different times. */
#define SFIP_ROBUST

#ifdef SFIP_ROBUST

#define ARG_CHECK1(a, z) if(!a) return z;
#define ARG_CHECK2(a, b, z) if(!a || !b) return z;
#define ARG_CHECK3(a, b, c, z) if(!a || !b || !c) return z;

#elif defined(DEBUG)

#define ARG_CHECK1(a, z) assert(a);
#define ARG_CHECK2(a, b, z) assert(a); assert(b);
#define ARG_CHECK3(a, b, c, z) assert(a); assert(b); assert(c);

#else

#define ARG_CHECK1(a, z)
#define ARG_CHECK2(a, b, z)
#define ARG_CHECK3(a, b, c, z)

#endif

typedef struct _ip {
    int16_t family;
    int16_t bits;

    /* see sfip_size(): these address bytes
     * must be the last field in this struct */
    union
    {
        u_int8_t  u6_addr8[16];
        u_int16_t u6_addr16[8];
        u_int32_t u6_addr32[4];
/*        u_int64_t    u6_addr64[2]; */
    } ip;
    #define ip8  ip.u6_addr8
    #define ip16 ip.u6_addr16
    #define ip32 ip.u6_addr32
/*    #define ip64 ip.u6_addr64 */
} sfip_t;

typedef enum _return_values {
    SFIP_SUCCESS=0,
    SFIP_FAILURE,
    SFIP_LESSER,
    SFIP_GREATER,
    SFIP_EQUAL,
    SFIP_ARG_ERR,
    SFIP_CIDR_ERR,
    SFIP_INET_PARSE_ERR,
    SFIP_INVALID_MASK,
    SFIP_ALLOC_ERR,
    SFIP_CONTAINS,
    SFIP_NOT_CONTAINS,
    SFIP_DUPLICATE,         /* Tried to add a duplicate variable name to table */
    SFIP_LOOKUP_FAILURE,    /* Failed to lookup a variable from the table */
    SFIP_UNMATCHED_BRACKET, /* IP lists that are missing a closing bracket */
    SFIP_NOT_ANY,           /* For !any */
    SFIP_CONFLICT           /* For IP conflicts in IP lists */
} SFIP_RET;


/* IP allocations and setting ******************************************/

/* Parses "src" and stores results in "dst" */
/* If the conversion is invalid, returns SFIP_FAILURE */
SFIP_RET sfip_pton(const char *src, sfip_t *dst);

/* Allocate IP address from a character array describing the IP */
sfip_t *sfip_alloc(const char *ip, SFIP_RET *status);

/* Frees an sfip_t */
void sfip_free(sfip_t *ip);

/* Allocate IP address from an array of integers.  The array better be
 * long enough for the given family! */
sfip_t *sfip_alloc_raw(void *ip, int family, SFIP_RET *status);

/* Sets existing IP, "dst", to a raw source IP (4 or 16 bytes,
 * according to family) */
SFIP_RET sfip_set_raw(sfip_t *dst, void *src, int src_family);

/* Sets existing IP, "dst", to be source IP, "src" */
SFIP_RET sfip_set_ip(sfip_t *dst, const sfip_t *src);

/* Obfuscates an IP */
void sfip_obfuscate(sfip_t *ob, sfip_t *ip);

/* return required size (eg for hashing)
 * requires that address bytes be the last field in sfip_t */
static inline unsigned int sfip_size(sfip_t* ipt)
{
    if ( ipt->family == AF_INET6 ) return sizeof(*ipt);
    return (unsigned int)((ipt->ip.u6_addr8+4) - (u_int8_t*)ipt);
}

/* Member-access *******************************************************/

/* Returns the family of "ip", either AF_INET or AF_INET6 */
/* XXX This is a performance critical function,
*  need to determine if it's safe to not check these pointers */
/* ARG_CHECK1(ip, 0); */
#define sfip_family(ip) ip->family

/* Returns the number of bits used for masking "ip" */
static inline unsigned char sfip_bits(const sfip_t *ip) {
    ARG_CHECK1(ip, 0);
    return (unsigned char)ip->bits;
}

static inline void sfip_set_bits(sfip_t *p, int bits) {

    if(!p)
        return;

    if(bits < 0 || bits > 128) return;

    p->bits = bits;
}

/* Returns the raw IP address as an in6_addr */
/*inline struct in6_addr sfip_to_raw(sfip_t *); */



/* IP Comparisons ******************************************************/

/* Check if ip is contained within the network specified by net */
/* Returns SFIP_EQUAL if so */
SFIP_RET sfip_contains(const sfip_t *net, const sfip_t *ip);

/* Returns 1 if the IP is non-zero. 0 otherwise */
/* XXX This is a performance critical function, \
 *  need to determine if it's safe to not check these pointers */\
static inline int sfip_is_set(const sfip_t *ip) {
/*    ARG_CHECK1(ip, -1); */
    return ip->ip32[0] ||
            ( (ip->family == AF_INET6) &&
              (ip->ip32[1] ||
              ip->ip32[2] ||
              ip->ip32[3] || ip->bits != 128)) || ((ip->family == AF_INET) && ip->bits != 32)  ;
}

/* Return 1 if the IP is a loopback IP */
int sfip_is_loopback(const sfip_t *ip);

/* Returns 1 if the IPv6 address appears mapped. 0 otherwise. */
int sfip_ismapped(const sfip_t *ip);

/* Support function for sfip_compare */
static inline SFIP_RET _ip4_cmp(u_int32_t ip1, u_int32_t ip2) {
    u_int32_t hip1 = htonl(ip1);
    u_int32_t hip2 = htonl(ip2);
    if(hip1 < hip2) return SFIP_LESSER;
    if(hip1 > hip2) return SFIP_GREATER;
    return SFIP_EQUAL;
}

/* Support function for sfip_compare */
static inline SFIP_RET _ip6_cmp(const sfip_t *ip1, const sfip_t *ip2) {
    SFIP_RET ret;
    const u_int32_t *p1, *p2;

    /* XXX
     * Argument are assumed trusted!
     * This function is presently only called by sfip_compare
     * on validated pointers.
     * XXX */

    p1 = ip1->ip32;
    p2 = ip2->ip32;

    if( (ret = _ip4_cmp(p1[0], p2[0])) != SFIP_EQUAL) return ret;
    if( (ret = _ip4_cmp(p1[1], p2[1])) != SFIP_EQUAL) return ret;
    if( (ret = _ip4_cmp(p1[2], p2[2])) != SFIP_EQUAL) return ret;
    if( (ret = _ip4_cmp(p1[3], p2[3])) != SFIP_EQUAL) return ret;

    return ret;
}

/* Compares two IPs
 * Returns SFIP_LESSER, SFIP_EQUAL, SFIP_GREATER, if ip1 is less than, equal to,
 * or greater than ip2 In the case of mismatched families, the IPv4 address
 * is converted to an IPv6 representation. */
/* XXX-IPv6 Should add version of sfip_compare that just tests equality */
static inline SFIP_RET sfip_compare(const sfip_t *ip1, const sfip_t *ip2) {
    int f1,f2;

    ARG_CHECK2(ip1, ip2, SFIP_ARG_ERR);

    /* This is being done because at some points in the existing Snort code,
     * an unset IP is considered to match anything.  Thus, if either IP is not
     * set here, it's considered equal. */
    if(!sfip_is_set(ip1) || !sfip_is_set(ip2)) return SFIP_EQUAL;

    f1 = sfip_family(ip1);
    f2 = sfip_family(ip2);

    if(f1 == AF_INET && f2 == AF_INET) {
        return _ip4_cmp(*ip1->ip32, *ip2->ip32);
    }
/* Mixed families not presently supported */
#if 0
    else if(f1 == AF_INET && f2 == AF_INET6) {
        conv = sfip_4to6(ip1);
        return _ip6_cmp(&conv, ip2);
    } else if(f1 == AF_INET6 && f2 == AF_INET) {
        conv = sfip_4to6(ip2);
        return _ip6_cmp(ip1, &conv);
    }
    else {
        return _ip6_cmp(ip1, ip2);
    }
#endif
    else if(f1 == AF_INET6 && f2 == AF_INET6) {
        return _ip6_cmp(ip1, ip2);
    }

    return SFIP_FAILURE;
}

/* Compares two IPs
 * Returns SFIP_LESSER, SFIP_EQUAL, SFIP_GREATER, if ip1 is less than, equal to,
 * or greater than ip2 In the case of mismatched families, the IPv4 address
 * is converted to an IPv6 representation. */
/* XXX-IPv6 Should add version of sfip_compare that just tests equality */
static inline SFIP_RET sfip_compare_unset(const sfip_t *ip1, const sfip_t *ip2) {
    int f1,f2;

    ARG_CHECK2(ip1, ip2, SFIP_ARG_ERR);

    /* This is to handle the special case when one of the values being
     * unset is considered to match nothing.  This is the opposite of
     * sfip_compare(), defined above.  Thus, if either IP is not
     * set here, it's considered not equal. */
    if(!sfip_is_set(ip1) || !sfip_is_set(ip2)) return SFIP_FAILURE;

    f1 = sfip_family(ip1);
    f2 = sfip_family(ip2);

    if(f1 == AF_INET && f2 == AF_INET) {
        return _ip4_cmp(*ip1->ip32, *ip2->ip32);
    }
/* Mixed families not presently supported */
#if 0
    else if(f1 == AF_INET && f2 == AF_INET6) {
        conv = sfip_4to6(ip1);
        return _ip6_cmp(&conv, ip2);
    } else if(f1 == AF_INET6 && f2 == AF_INET) {
        conv = sfip_4to6(ip2);
        return _ip6_cmp(ip1, &conv);
    }
    else {
        return _ip6_cmp(ip1, ip2);
    }
#endif
    else if(f1 == AF_INET6 && f2 == AF_INET6) {
        return _ip6_cmp(ip1, ip2);
    }

    return SFIP_FAILURE;
}

static inline int sfip_fast_lt4(const sfip_t *ip1, const sfip_t *ip2) {
    return *ip1->ip32 < *ip2->ip32;
}
static inline int sfip_fast_gt4(const sfip_t *ip1, const sfip_t *ip2) {
    return *ip1->ip32 > *ip2->ip32;
}
static inline int sfip_fast_eq4(const sfip_t *ip1, const sfip_t *ip2) {
    return *ip1->ip32 == *ip2->ip32;
}

static inline int sfip_fast_lt6(const sfip_t *ip1, const sfip_t *ip2) {
    const u_int32_t *p1, *p2;

    p1 = ip1->ip32;
    p2 = ip2->ip32;

    if(*p1 < *p2) return 1;
    else if(*p1 > *p2) return 0;

    if(p1[1] < p2[1]) return 1;
    else if(p1[1] > p2[1]) return 0;

    if(p1[2] < p2[2]) return 1;
    else if(p1[2] > p2[2]) return 0;

    if(p1[3] < p2[3]) return 1;
    else if(p1[3] > p2[3]) return 0;

    return 0;
}

static inline int sfip_fast_gt6(const sfip_t *ip1, const sfip_t *ip2) {
    const u_int32_t *p1, *p2;

    p1 = ip1->ip32;
    p2 = ip2->ip32;

    if(*p1 > *p2) return 1;
    else if(*p1 < *p2) return 0;

    if(p1[1] > p2[1]) return 1;
    else if(p1[1] < p2[1]) return 0;

    if(p1[2] > p2[2]) return 1;
    else if(p1[2] < p2[2]) return 0;

    if(p1[3] > p2[3]) return 1;
    else if(p1[3] < p2[3]) return 0;

    return 0;
}

static inline int sfip_fast_eq6(const sfip_t *ip1, const sfip_t *ip2) {
    const u_int32_t *p1, *p2;

    p1 = ip1->ip32;
    p2 = ip2->ip32;

    if(*p1 != *p2) return 0;
    if(p1[1] != p2[1]) return 0;
    if(p1[2] != p2[2]) return 0;
    if(p1[3] != p2[3]) return 0;

    return 1;
}

/* Checks if ip2 is equal to ip1 or contained within the CIDR ip1 */
static inline int sfip_fast_cont4(const sfip_t *ip1, const sfip_t *ip2) {
    u_int32_t shift = 32 - sfip_bits(ip1);
    u_int32_t ip = ntohl(*ip2->ip32);

    ip >>= shift;
    ip <<= shift;

    return ntohl(*ip1->ip32) == ip;
}

/* Checks if ip2 is equal to ip1 or contained within the CIDR ip1 */
static inline int sfip_fast_cont6(const sfip_t *ip1, const sfip_t *ip2) {
    u_int32_t ip;
    int i, bits = sfip_bits(ip1);
    int words = bits / 32;
    bits = 32 - (bits % 32);

    for ( i = 0; i < words; i++ ) {
        if ( ip1->ip32[i] != ip2->ip32[i] )
            return 0;
    }

    if ( bits == 32 ) return 1;

    ip = ntohl(ip2->ip32[i]);

    ip >>= bits;
    ip <<= bits;

    return ntohl(ip1->ip32[i]) == ip;
}

/* Compares two IPs
 * Returns 1 for equal and 0 for not equal
 */
static inline int sfip_fast_equals_raw(const sfip_t *ip1, const sfip_t *ip2)
{
    int f1,f2;

    ARG_CHECK2(ip1, ip2, 0);

    f1 = sfip_family(ip1);
    f2 = sfip_family(ip2);

    if(f1 == AF_INET)
    {
        if(f2 != AF_INET)
            return 0;
        if (sfip_fast_eq4(ip1, ip2))
            return 1;
    }
    else if(f1 == AF_INET6)
    {
        if(f2 != AF_INET6)
            return 0;
        if (sfip_fast_eq6(ip1, ip2))
            return 1;
    }
    return 0;
}

/********************************************************************
 * Function: sfip_is_private()
 *
 * Checks if the address is local
 *
 * Arguments:
 *  sfip_t * - IP address to check
 *
 * Returns:
 *  1  if the IP is in local network
 *  0  otherwise
 *
 ********************************************************************/
static inline int sfip_is_private(const sfip_t *ip)
{
    const unsigned int *p;

    ARG_CHECK1(ip, 0);

    if(sfip_family(ip) == AF_INET) {
        /*
         * 10.0.0.0        -   10.255.255.255  (10/8 prefix)
         * 172.16.0.0      -   172.31.255.255  (172.16/12 prefix)
         * 192.168.0.0     -   192.168.255.255 (192.168/16 prefix)
         * */
        return( (ip->ip8[0] == 10)
              ||((ip->ip8[0] == 172) && ((ip->ip8[1] & 0xf0 ) == 16))
              ||((ip->ip8[0] == 192) && (ip->ip8[1] == 168)) );

    }

    p = ip->ip32;

    /* Check the first 64 bits in an IPv6 address, and */
    /* verify they're zero.  If not, it's not a loopback */
    if(p[0] || p[1]) return 0;

    /* Check if the 3rd 32-bit int is zero */
    if ( p[2] == 0 ) {
        /* ::ipv4 compatible ipv6 */
        /* ::1 is the IPv6 loopback */
        return ( (ip->ip8[12] == 10)
                ||((ip->ip8[12] == 172) && ((ip->ip8[13] & 0xf0 ) == 16))
                ||((ip->ip8[12] == 192) && (ip->ip8[13] == 168))
                || (ntohl(p[3]) == 0x1) );
    }
    /* Check the 3rd 32-bit int for a mapped IPv4 address */
    if ( ntohl(p[2]) == 0xffff ) {
        /* ::ffff: IPv4 loopback mapped over IPv6 */
        return ( (ip->ip8[12] == 10)
                ||((ip->ip8[12] == 172) && ((ip->ip8[13] & 0xf0 ) == 16))
                ||((ip->ip8[12] == 192) && (ip->ip8[13] == 168)) );
    }
    return 0;

}

#define sfip_equals(x,y) (sfip_compare(&x, &y) == SFIP_EQUAL)
#define sfip_not_equals !sfip_equals
#define sfip_clear(x) memset(x, 0, 16)

/* Printing ************************************************************/

/* Uses a static buffer to return a string representation of the IP */
char *sfip_to_str(const sfip_t *ip);
#define sfip_ntoa(x) sfip_to_str(x)
void sfip_raw_ntop(int family, const void *ip_raw, char *buf, int bufsize);
void sfip_ntop(const sfip_t *ip, char *buf, int bufsize);

/* Conversions *********************************************************/

SFIP_RET sfip_convert_ip_text_to_binary( const int, char *src, void *dst );

#endif /* SF_IP_H */

