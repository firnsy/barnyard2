/* $Id$ */
/*
** Copyright (C) 2002-2009 Sourcefire, Inc.
** Copyright (C) 2002 Martin Roesch <roesch@sourcefire.com>
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
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/


#ifndef __UTIL_H__
#define __UTIL_H__

#define TIMEBUF_SIZE 26

#include <sys/time.h>
#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include "sf_types.h"

/* specifies that a function does not return 
 * used for quieting Visual Studio warnings */
#ifdef _MSC_VER
# if _MSC_VER >= 1400
#  define NORETURN __declspec(noreturn)
# else
#  define NORETURN
# endif
#else
# define NORETURN
#endif

#define SNORT_SNPRINTF_SUCCESS 0
#define SNORT_SNPRINTF_TRUNCATION 1
#define SNORT_SNPRINTF_ERROR -1

#define SNORT_STRNCPY_SUCCESS 0
#define SNORT_STRNCPY_TRUNCATION 1
#define SNORT_STRNCPY_ERROR -1

#define SNORT_STRNLEN_ERROR -1

#define SECONDS_PER_DAY  86400  /* number of seconds in a day  */
#define SECONDS_PER_HOUR  3600  /* number of seconds in a hour */
#define SECONDS_PER_MIN     60     /* number of seconds in a minute */

#define STD_BUF  1024

#define COPY4(x, y) \
    x[0] = y[0]; x[1] = y[1]; x[2] = y[2]; x[3] = y[3];

#define COPY16(x,y) \
    x[0] = y[0]; x[1] = y[1]; x[2] = y[2]; x[3] = y[3]; \
    x[4] = y[4]; x[5] = y[5]; x[6] = y[6]; x[7] = y[7]; \
    x[8] = y[8]; x[9] = y[9]; x[10] = y[10]; x[11] = y[11]; \
    x[12] = y[12]; x[13] = y[13]; x[14] = y[14]; x[15] = y[15];

#define ENCODING_HEX 0
#define ENCODING_BASE64 1
#define ENCODING_ASCII 2
#define DETAIL_FAST  0
#define DETAIL_FULL  1

#ifndef MAX_QUERY_LENGTH
#define MAX_QUERY_LENGTH ((65536 * 2) + 4096) /* Lets add some space for payload decoding and query esaping..*/
#endif  /* MAX_QUERY_LENGTH */



/* Externs ********************************************************************/
extern uint32_t *netmasks;


/* Data types *****************************************************************/

/* Self preservation memory control struct */
typedef struct _SPMemControl
{
    unsigned long memcap;
    unsigned long mem_usage;
    void *control;
    int (*sp_func)(struct _SPMemControl *);

    unsigned long fault_count;

} SPMemControl;

typedef struct _PcapPktStats
{
    uint64_t recv;
    uint64_t drop;
    uint32_t wrap_recv;
    uint32_t wrap_drop;

} PcapPktStats;


typedef struct _IntervalStats
{
    uint64_t recv, recv_total;
    uint64_t drop, drop_total;
    uint64_t processed, processed_total;
    uint64_t tcp, tcp_total;
    uint64_t udp, udp_total;
    uint64_t icmp, icmp_total;
    uint64_t arp, arp_total;
    uint64_t ipx, ipx_total;
    uint64_t eapol, eapol_total;
    uint64_t ipv6, ipv6_total;
    uint64_t ethloopback, ethloopback_total;
    uint64_t other, other_total;
    uint64_t frags, frags_total;
    uint64_t discards, discards_total;
    uint64_t frag_trackers, frag_trackers_total;
    uint64_t frag_rebuilt, frag_rebuilt_total;
    uint64_t frag_element, frag_element_total;
    uint64_t frag_incomp, frag_incomp_total;
    uint64_t frag_timeout, frag_timeout_total;
    uint64_t frag_mem_faults, frag_mem_faults_total;
    uint64_t tcp_str_packets, tcp_str_packets_total;
    uint64_t tcp_str_trackers, tcp_str_trackers_total;
    uint64_t tcp_str_flushes, tcp_str_flushes_total;
    uint64_t tcp_str_segs_used, tcp_str_segs_used_total;
    uint64_t tcp_str_segs_queued, tcp_str_segs_queued_total;
    uint64_t tcp_str_mem_faults, tcp_str_mem_faults_total;

#ifdef GRE
    uint64_t ip4ip4, ip4ip4_total;
    uint64_t ip4ip6, ip4ip6_total;
    uint64_t ip6ip4, ip6ip4_total;
    uint64_t ip6ip6, ip6ip6_total;

    uint64_t gre, gre_total;
    uint64_t gre_ip, gre_ip_total;
    uint64_t gre_eth, gre_eth_total;
    uint64_t gre_arp, gre_arp_total;
    uint64_t gre_ipv6, gre_ipv6_total;
    uint64_t gre_ipx, gre_ipx_total;
    uint64_t gre_loopback, gre_loopback_total;
    uint64_t gre_vlan, gre_vlan_total;
    uint64_t gre_ppp, gre_ppp_total;
#endif

#ifdef DLT_IEEE802_11
    uint64_t wifi_mgmt, wifi_mgmt_total;
    uint64_t wifi_control, wifi_control_total;
    uint64_t wifi_data, wifi_data_total;
#endif

} IntervalStats;



int DisplayBanner(void);
void GetTime(char *);
int gmt2local(time_t);
void ts_print(register const struct timeval *, char *);
void ts_print2(u_int32_t, u_int32_t, char *);
char *copy_argv(char **);
void strtrim(char *);
void strip(char *);
double CalcPct(uint64_t, uint64_t);
void ReadPacketsFromFile(void);
void InitBinFrag(void);
void GoDaemon(void);
void SignalWaitingParent(void);
void CheckLogDir(void);
char *read_infile(char *);
void CleanupProtoNames(void);
void ErrorMessage(const char *, ...);
void LogMessage(const char *, ...);
NORETURN void FatalError(const char *, ...);
void CreatePidFile(char *);
void ClosePidFile(void);
void SetUidGid(int, int);
void SetChroot(char *, char **);
void DropStats(int);
void *SPAlloc(unsigned long, struct _SPMemControl *);
int SnortSnprintf(char *, size_t, const char *, ...);
int SnortSnprintfAppend(char *, size_t, const char *, ...);
char *SnortStrdup(const char *);
int SnortStrncpy(char *, const char *, size_t);
char *SnortStrndup(const char *, size_t);
int SnortStrnlen(const char *, int);
const char *SnortStrnPbrk(const char *s, int slen, const char *accept);
const char *SnortStrnStr(const char *s, int slen, const char *searchstr);
const char *SnortStrcasestr(const char *s, const char *substr);
void *SnortAlloc(unsigned long);
void *SnortAlloc2(size_t, const char *, ...);
char *CurrentWorkingDir(void);
char *GetAbsolutePath(char *dir);
char *StripPrefixDir(char *prefix, char *dir);

void TimeStats(void);

int ArchiveFile(const char *, const char *);

char *GetUniqueName(char *);
char *GetIP(char *);
char *GetHostname();
int GetLocalTimezone();


u_int32_t fasthex_STATIC(const u_char *xdata, int length,char *retbuf);
u_int32_t base64_STATIC(const u_char * xdata, int length,char *output);
u_int32_t ascii_STATIC(const u_char *xdata, int length,char *ret_val);

u_int32_t GetTimestampByComponent_STATIC(uint32_t sec, uint32_t usec, int tz,char *buf);
u_int32_t GetTimestampByStruct_STATIC(register const struct timeval *tvp, int tz,char *buf);
u_int32_t GetCurrentTimestamp_STATIC(char *buf);


u_int32_t string_sanitize_character(char *input,char ichar);



/***********************************************************
 If you use any of the functions in this section, you need
 to call free() on the char * that is returned after you are
 done using it. Otherwise, you will have created a memory
 leak.
***********************************************************/
char *GetTimestampByComponent(u_int32_t, u_int32_t, int);
char *GetTimestampByStruct(register const struct timeval *, int);
char *GetCurrentTimestamp();
char *base64(const u_char *, int);
char *ascii(const u_char *, int);
char *hex(const u_char *, int);
char *fasthex(const u_char *, int);
long int xatol(const char *, const char *);
unsigned long int xatou(const char *, const char *);
unsigned long int xatoup(const char *, const char *); // return > 0

int BY2Strtoul(char *,unsigned long *);
#endif /*__UTIL_H__*/
