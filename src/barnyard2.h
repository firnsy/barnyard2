/*
** Copyright (C) 2008-2013 Ian Firns (SecurixLive) <dev@securixlive.com>
**
** Copyright (C) 2005-2009 Sourcefire, Inc.
** Copyright (C) 1998-2005 Martin Roesch <roesch@sourcefire.com>
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

/*
** Description:
**   A dedicated snort unified2 log file parser
**
** Author(s):
**   firnsy <firnsy@securixlive.com>
**   SecurixLive.com Team <dev@securixlive.com>
**
** Comments:
**   Foundation is built upon the Snort 2.8.3 codebase (www.snort.org/dl) with
** ideas stolen liberally from:
**     1. the orginal barnyard (A. Baker, M. Roesch)
**
*/

#ifndef __BARNYARD2_H__
#define __BARNYARD2_H__

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>
#include <pcap.h>
#include <stdio.h>

#include "sfutil/sf_ipvar.h"
#include "map.h"
#include "sf_types.h"
#include "spooler.h"

/* TODO: check this should live in the plugin */
#if defined(HAVE_LIBPRELUDE)
# include <pthread.h>
#endif

/*  I N C L U D E S  **********************************************************/

/*  D E F I N E S  ************************************************************/
#define PROGRAM_NAME	"Barnyard"
#define VER_MAJOR	"2"
#define VER_MINOR	"1"
#define VER_REVISION	"14"
#define VER_BUILD	"337"

#define STD_BUF  1024

#define MAX_PIDFILE_SUFFIX 11 /* uniqueness extension to PID file, see '-R' */

#ifndef WIN32
# define DEFAULT_LOG_DIR            "/var/log/barnyard2"
# define DEFAULT_DAEMON_ALERT_FILE  "barnyard2.alert"
#else
# define DEFAULT_LOG_DIR            "log"
# define DEFAULT_DAEMON_ALERT_FILE  "log/alert.ids"
#endif  /* WIN32 */

#ifdef ACCESSPERMS
# define FILEACCESSBITS ACCESSPERMS
#else
# ifdef S_IAMB
#  define FILEACCESSBITS S_IAMB
# else
#  define FILEACCESSBITS 0x1FF
# endif
#endif    

#define TIMEBUF_SIZE    26


#ifndef ULONG_MAX
#  if __WORDSIZE == 64
#   define ULONG_MAX    18446744073709551615UL
#  else
#   define ULONG_MAX    4294967295UL
#  endif
#endif

#define DO_IP_CHECKSUMS		0x00000001
#define DO_TCP_CHECKSUMS	0x00000002
#define DO_UDP_CHECKSUMS	0x00000004
#define DO_ICMP_CHECKSUMS	0x00000008

#define LOG_UNIFIED         0x00000001
#define LOG_TCPDUMP         0x00000002
#define LOG_UNIFIED2        0x00000004

#define SIGNAL_SNORT_ROTATE_STATS  28
#define SIGNAL_SNORT_CHILD_READY   29

#define BARNYARD2_SUCCESS		0
#define BARNYARD2_EINVAL		1
#define BARNYARD2_ENOMEM		2
#define BARNYARD2_ENOENT		3
#define BARNYARD2_EOPEN			4
#define BARNYARD2_ETRUNC		5
#define BARNYARD2_ECORRUPT		6
#define BARNYARD2_READ_EOF		32
#define BARNYARD2_READ_PARTIAL	33
#define BARNYARD2_FILE_ERROR	34

#ifdef MPLS
# define MPLS_PAYLOADTYPE_IPV4         1
# define MPLS_PAYLOADTYPE_ETHERNET     2
# define MPLS_PAYLOADTYPE_IPV6         3
# define MPLS_PAYLOADTYPE_ERROR       -1
# define DEFAULT_MPLS_PAYLOADTYPE      MPLS_PAYLOADTYPE_IPV4
# define DEFAULT_LABELCHAIN_LENGTH    -1
#endif


/* SIDMAP V2 */
#define SIDMAPV1STRING "v1"
#define SIDMAPV2STRING "v2"
#define SIDMAPV1 0x01
#define SIDMAPV2 0x02
/* SIDMAP V2 */


/* This macro helps to simplify the differences between Win32 and
   non-Win32 code when printing out the name of the interface */
#ifndef WIN32
# define PRINT_INTERFACE(i)  (i ? i : "NULL")
//#else
//# define PRINT_INTERFACE(i)  print_interface(i)
#endif

/*  D A T A  S T R U C T U R E S  *********************************************/
typedef struct _VarEntry
{
    char *name;
    char *value;
    unsigned char flags;
    struct _VarEntry *prev;
    struct _VarEntry *next;

} VarEntry;

/* GetoptLong Option numbers ********************/
typedef enum _GetOptLongIds
{
    PID_PATH = 1,

    ARG_RESTART,
    CREATE_PID_FILE,
    PROCESS_ALL_EVENTS,
    NOLOCK_PID_FILE,

    NO_LOGGING_TIMESTAMPS,

#define EXIT_CHECK  // allow for rollback for now
#ifdef EXIT_CHECK
    ARG_EXIT_CHECK,
#endif

    DETECTION_SEARCH_METHOD,
    CONF_ERROR_OUT,
    DISABLE_ALERT_ON_EACH_PACKET_IN_STREAM,
    ALERT_ON_EACH_PACKET_IN_STREAM,
    EVENT_CACHE_SIZE,

#ifdef MPLS
    MAX_MPLS_LABELCHAIN_LEN,
    MPLS_PAYLOAD_TYPE,
#endif

    GET_OPT_LONG_IDS_MAX
} GetOptLongIds;

typedef struct _InputConfig
{
    char *keyword;
    char *opts;
    char *file_name;
    int file_line;
    struct _InputConfig *next;

} InputConfig;

typedef struct _OutputConfig
{
    char *keyword;
    char *opts;
    char *file_name;
    int file_line;
    struct _OutputConfig *next;

} OutputConfig;

typedef enum _PathType
{
    PATH_TYPE__FILE,
    PATH_TYPE__DIRECTORY

} PathType;

typedef enum _RunMode
{
    /* -V */
    RUN_MODE__VERSION = 1,

    /* neither of the above and barnyard2.conf presence (-c or implicit) */
    RUN_MODE__CONTINUOUS,

    RUN_MODE__BATCH,

    /* barnyard2.conf presence and -T */
    RUN_MODE__TEST,
} RunMode;


typedef enum _RunModeFlag
{
    /* -V */
    RUN_MODE_FLAG__VERSION      = 0x00000001,

    /* neither of the above and snort.conf presence (-c or implicit) */
    RUN_MODE_FLAG__CONTINUOUS   = 0x00000004,

    RUN_MODE_FLAG__BATCH        = 0x00000008,

    /* barnyard2.conf presence and -T */
    RUN_MODE_FLAG__TEST         = 0x00000010,

} RunModeFlag;

typedef enum _RunFlag
{
    RUN_FLAG__READ                = 0x00000001,     /* -r --pcap-dir, etc. */
    RUN_FLAG__DAEMON              = 0x00000002,     /* -D */
    RUN_FLAG__DAEMON_RESTART      = 0x00000004,     /* --restart */
    RUN_FLAG__CREATE_PID_FILE     = 0x00000040,     /* --pid-path and --create-pidfile */
    RUN_FLAG__NO_LOCK_PID_FILE    = 0x00000080,     /* --nolock-pidfile */
    RUN_FLAG__CONF_ERROR_OUT      = 0x00000400,     /* -x and --conf-error-out */

#if defined(WIN32) && defined(ENABLE_WIN32_SERVICE)
   ,RUN_FLAG__TERMINATE_SERVICE   = 0x04000000,
    RUN_FLAG__PAUSE_SERVICE       = 0x08000000
#endif

} RunFlag;

typedef enum _OutputFlag
{
    OUTPUT_FLAG__LINE_BUFFER       = 0x00000001,      /* -f */
    OUTPUT_FLAG__VERBOSE_DUMP      = 0x00000002,      /* -X */
    OUTPUT_FLAG__CHAR_DATA         = 0x00000004,      /* -C */
    OUTPUT_FLAG__APP_DATA          = 0x00000008,      /* -d */
    OUTPUT_FLAG__SHOW_DATA_LINK    = 0x00000010,      /* -e */
#ifndef NO_NON_ETHER_DECODER
    OUTPUT_FLAG__SHOW_WIFI_MGMT    = 0x00000020,      /* -w */
#endif
    OUTPUT_FLAG__USE_UTC           = 0x00000040,      /* -U */
    OUTPUT_FLAG__INCLUDE_YEAR      = 0x00000080,      /* -y */

    /* Note using this alters the packet - can't be used inline */
    OUTPUT_FLAG__OBFUSCATE         = 0x00000100,      /* -B */

    OUTPUT_FLAG__ALERT_IFACE       = 0x00000200,      /* -I */
    OUTPUT_FLAG__NO_TIMESTAMP      = 0x00000400,      /* --nostamps */
    OUTPUT_FLAG__ALERT_PKT_CNT     = 0x00000800,      /* -A packet-count */
    /* XXX XXX pv.outputVidInAlerts */
    OUTPUT_FLAG__ALERT_VLAN        = 0x00001000       /* config include_vlan_in_alerts */

} OutputFlag;

typedef enum _LoggingFlag
{
    LOGGING_FLAG__VERBOSE         = 0x00000001,      /* -v */
    LOGGING_FLAG__QUIET           = 0x00000002,      /* -q */
    LOGGING_FLAG__SYSLOG          = 0x00000004       /* -M */
#ifdef WIN32
   ,LOGGING_FLAG__SYSLOG_REMOTE   = 0x00000008       /* -s and -E */
#endif

} LoggingFlag;

typedef struct _VarNode
{
    char *name;
    char *value;
    char *line;
    struct _VarNode *next;

} VarNode;


/* struct to contain the program variables and command line args */
typedef struct _Barnyard2Config
{
/* Does not need cleanup */
    RunMode run_mode;
    int checksums_mode;
    char ignore_ports[0x10000];
    int run_mode_flags;
    int run_flags;
    int output_flags;
    int logging_flags;
    int thiszone;
    int	quiet_flag;
    int	verbose_flag;
    int	verbose_bytedump_flag;
    int	show2hdr_flag;
    int	char_data_flag;
    int data_flag;
    int obfuscation_flag;
    int alert_on_each_packet_in_stream_flag;
    
    int	logtosyslog_flag;
    int	test_mode_flag;
    
    int use_utc;
    int include_year;
    
    int line_buffer_flag;
    char nostamp;
    int user_id;
    int group_id;
    mode_t file_mask;
    
    /* -h and -B */
#ifdef SUP_IP6
    sfip_t homenet;
    sfip_t obfuscation_net;
#else
    u_long homenet;
    u_long netmask;
    uint32_t obfuscation_net;
    uint32_t obfuscation_mask;
#endif

#ifdef MPLS
    uint8_t mpls_payload_type;  /* --mpls_payload_type */
    long int mpls_stack_depth;  /* --max_mpls_labelchain_len */
#endif

    /* batch mode options */
    int batch_mode_flag;
    int batch_total_files;

    
    /* continual mode options */
    int process_new_records_only_flag;
    Waldo waldo;

    int	daemon_flag;
    int daemon_restart_flag;
    
    /* runtime parameters */
    char pid_filename[STD_BUF];
    char pid_path[STD_BUF];     /* --pid-path or config pidpath */
    char pidfile_suffix[MAX_PIDFILE_SUFFIX+1]; /* room for a null */
    char create_pid_file;
    char nolock_pid_file;
    int done_processing;
    int restart_flag;
    int print_version;
    int usr_signal;
    int cant_hup_signal;
    unsigned int event_cache_size;
    uint8_t verbose;                /* -v */
    uint8_t localtime;

/* Need to be handled by Barnyard2ConfFree() */

    VarEntry *var_table;
#ifdef SUP_IP6
    vartable_t *ip_vartable;
#endif
    SigSuppress_list *ssHead;
    
    ClassType *classifications;
    ReferenceSystemNode *references;
    SigNode *sigHead;  /* Signature list Head */
    
    /* plugin active flags*/
    InputConfig *input_configs;
    OutputConfig *output_configs;
    PluginSignalFuncNode *plugin_post_config_funcs;
    
    char *config_file;           /* -c */
    char *config_dir;
    char *hostname;             /* -h or config hostname */
    char *interface;	        /* -i or config interface */
    
    char *class_file;          /* -C or config class_map */
    char *sid_msg_file;        /* -S or config sid_map */
    short sidmap_version;      /* Set by ReadSidFile () */
    char *gen_msg_file;        /* -G or config gen_map */

    char *reference_file;      /* -R or config reference_map */
    char *log_dir;             /* -l or config log_dir */
    char *orig_log_dir;        /* set in case of chroot */
    char *chroot_dir;          /* -t or config chroot */

    char *bpf_filter;          /* config bpf_filter */
    char **batch_filelist;
    char *archive_dir;

    Spooler *spooler; /* Used to know if we need to call spoolerClose */

} Barnyard2Config;

/* struct to collect packet statistics */
typedef struct _PacketCount
{
    uint64_t total_records;
    uint64_t total_events;
    uint64_t total_packets;
    uint64_t total_processed;
    uint64_t total_unknown;
    uint64_t total_suppressed;

    uint64_t s5tcp1;
    uint64_t s5tcp2;
    uint64_t ipv6opts;
    uint64_t eth;
    uint64_t ethdisc;
    uint64_t ipv6disc;
    uint64_t ip6ext;
    uint64_t other;
    uint64_t tcp;
    uint64_t udp;
    uint64_t icmp;
    uint64_t arp;
#ifndef NO_NON_ETHER_DECODER
    uint64_t eapol;
#endif
    uint64_t vlan;
    uint64_t nested_vlan;
    uint64_t ipv6;
    uint64_t ipv6_up;
    uint64_t ipv6_upfail;
    uint64_t frag6;
    uint64_t icmp6;
    uint64_t tdisc;
    uint64_t udisc;
    uint64_t tcp6;
    uint64_t udp6;
    uint64_t teredo;
    uint64_t ipdisc;
    uint64_t icmpdisc;
    uint64_t embdip;
    uint64_t ip;
    uint64_t ipx;
    uint64_t ethloopback;

    uint64_t invalid_checksums;
    uint64_t bad_ttl;

#ifdef GRE
    uint64_t ip4ip4;
    uint64_t ip4ip6;
    uint64_t ip6ip4;
    uint64_t ip6ip6;

    uint64_t gre;
    uint64_t gre_ip;
    uint64_t gre_eth;
    uint64_t gre_arp;
    uint64_t gre_ipv6;
    uint64_t gre_ipv6ext;
    uint64_t gre_ipx;
    uint64_t gre_loopback;
    uint64_t gre_vlan;
    uint64_t gre_ppp;
#endif

    uint64_t discards;
    uint64_t alert_pkts;
    uint64_t log_pkts;
    uint64_t pass_pkts;

    uint64_t frags;           /* number of frags that have come in */
    uint64_t frag_trackers;   /* number of tracking structures generated */
    uint64_t rebuilt_frags;   /* number of packets rebuilt */
    uint64_t frag_incomp;     /* number of frags cleared due to memory issues */
    uint64_t frag_timeout;    /* number of frags cleared due to timeout */
    uint64_t rebuild_element; /* frags that were element of rebuilt pkt */
    uint64_t frag_mem_faults; /* number of times the memory cap was hit */

    uint64_t tcp_stream_pkts; /* number of packets tcp reassembly touches */
    uint64_t rebuilt_tcp;     /* number of phoney tcp packets generated */
    uint64_t tcp_streams;     /* number of tcp streams created */
    uint64_t rebuilt_segs;    /* number of tcp segments used in rebuilt pkts */
    uint64_t queued_segs;     /* number of tcp segments stored for rebuilt pkts */
    uint64_t str_mem_faults;  /* number of times the stream memory cap was hit */

#ifndef NO_NON_ETHER_DECODER
#ifdef DLT_IEEE802_11
  /* wireless statistics */
    uint64_t wifi_mgmt;
    uint64_t wifi_data;
    uint64_t wifi_control;
    uint64_t assoc_req;
    uint64_t assoc_resp;
    uint64_t reassoc_req;
    uint64_t reassoc_resp;
    uint64_t probe_req;
    uint64_t probe_resp;
    uint64_t beacon;
    uint64_t atim;
    uint64_t dissassoc;
    uint64_t auth;
    uint64_t deauth;
    uint64_t ps_poll;
    uint64_t rts;
    uint64_t cts;
    uint64_t ack;
    uint64_t cf_end;
    uint64_t cf_end_cf_ack;
    uint64_t data;
    uint64_t data_cf_ack;
    uint64_t data_cf_poll;
    uint64_t data_cf_ack_cf_poll;
    uint64_t cf_ack;
    uint64_t cf_poll;
    uint64_t cf_ack_cf_poll;
#endif
#endif  // NO_NON_ETHER_DECODER

#ifdef MPLS
    uint64_t mpls;
#endif
} PacketCount;

typedef struct _SnortPacketHeader
{
	struct timeval		ts;
	uint32_t			caplen;
	uint32_t			pktlen;
} SnortPacketHeader;

/*  E X T E R N S  ************************************************************/
extern Barnyard2Config *barnyard2_conf;
extern int datalink;          /* the datalink value */
extern PacketCount pc;        /* packet count information */
extern char **protocol_names;


extern char *progname;        /* name of the program (from argv[0]) */
extern char **progargs;
extern char *username;
extern char *groupname;
extern struct passwd *pw;
extern struct group *gr;

extern u_int snaplen;
extern int exit_signal;

extern Barnyard2Config *barnyard2_conf_for_parsing;

/*  P R O T O T Y P E S  ******************************************************/
Barnyard2Config * Barnyard2ConfNew(void);

int Barnyard2Main(int argc, char *argv[]);
int Barnyard2Sleep(unsigned int);
int SignalCheck(void);

void CleanExit(int);
void SigCantHupHandler(int signal);
void FreeVarList(VarNode *);
void Barnyard2ConfFree(Barnyard2Config *);
void CleanupPreprocessors(Barnyard2Config *);
void CleanupPlugins(Barnyard2Config *);


static INLINE int BcTestMode(void)
{
    return barnyard2_conf->run_mode == RUN_MODE__TEST;
}

static INLINE int BcContinuousMode(void)
{
    return barnyard2_conf->run_mode == RUN_MODE__CONTINUOUS;
}

static INLINE int BcBatchMode(void)
{
    return barnyard2_conf->run_mode == RUN_MODE__BATCH;
}

static INLINE int BcVersionMode(void)
{
    return barnyard2_conf->run_mode == RUN_MODE__VERSION;
}

static INLINE int BcDaemonMode(void)
{
    return barnyard2_conf->run_flags & RUN_FLAG__DAEMON;
}

static INLINE int BcDaemonRestart(void)
{
    return barnyard2_conf->run_flags & RUN_FLAG__DAEMON_RESTART;
}

static INLINE int BcLogSyslog(void)
{
    return barnyard2_conf->logging_flags & LOGGING_FLAG__SYSLOG;
}

static INLINE int BcAlertOnEachPacketInStream(void)
{
    return barnyard2_conf->alert_on_each_packet_in_stream_flag;
}

static INLINE int BcAlertInterface(void)
{
    return barnyard2_conf->output_flags & OUTPUT_FLAG__ALERT_IFACE;
}

#ifdef WIN32
static INLINE int BcLogSyslogRemote(void)
{
    return barnyard2_conf->logging_flags & LOGGING_FLAG__SYSLOG_REMOTE;
}
#endif

static INLINE int BcLogVerbose(void)
{
    return barnyard2_conf->logging_flags & LOGGING_FLAG__VERBOSE;
}

static INLINE int BcLogQuiet(void)
{
    return barnyard2_conf->logging_flags & LOGGING_FLAG__QUIET;
}

static INLINE int BcConfErrorOut(void)
{
    return barnyard2_conf->run_flags & RUN_FLAG__CONF_ERROR_OUT;
}

static INLINE int BcOutputIncludeYear(void)
{
    return barnyard2_conf->output_flags & OUTPUT_FLAG__INCLUDE_YEAR;
}

static INLINE int BcOutputUseUtc(void)
{
    return barnyard2_conf->output_flags & OUTPUT_FLAG__USE_UTC;
}

static INLINE int BcOutputDataLink(void)
{
    return barnyard2_conf->output_flags & OUTPUT_FLAG__SHOW_DATA_LINK;
}

static INLINE int BcProcessNewRecordsOnly(void)
{
    return barnyard2_conf->process_new_records_only_flag;
}

static INLINE int BcVerboseByteDump(void)
{
    return barnyard2_conf->output_flags & OUTPUT_FLAG__VERBOSE_DUMP;
}

static INLINE int BcObfuscate(void)
{
    return barnyard2_conf->output_flags & OUTPUT_FLAG__OBFUSCATE;
}

static INLINE int BcOutputAppData(void)
{
    return barnyard2_conf->output_flags & OUTPUT_FLAG__APP_DATA;
}

static INLINE int BcOutputCharData(void)
{
    return barnyard2_conf->output_flags & OUTPUT_FLAG__CHAR_DATA;
}

static INLINE int BcNoOutputTimestamp(void)
{
    return barnyard2_conf->output_flags & OUTPUT_FLAG__NO_TIMESTAMP;
}

static INLINE int BcLineBufferedLogging(void)
{
    return barnyard2_conf->output_flags & OUTPUT_FLAG__LINE_BUFFER;
}

static INLINE int BcNoLockPidFile(void)
{
    return barnyard2_conf->run_flags & RUN_FLAG__NO_LOCK_PID_FILE;
}

static INLINE int BcCreatePidFile(void)
{
    return barnyard2_conf->run_flags & RUN_FLAG__CREATE_PID_FILE;
}

#if defined(WIN32) && defined(ENABLE_WIN32_SERVICE)
static INLINE int BcTerminateService(void)
{
    return barnyard2_conf->run_flags & RUN_FLAG__TERMINATE_SERVICE;
}

static INLINE int BcPauseService(void)
{
    return barnyard2_conf->run_flags & RUN_FLAG__PAUSE_SERVICE;
}
#endif

static INLINE int BcUid(void)
{
    return barnyard2_conf->user_id;
}

static INLINE int BcGid(void)
{
    return barnyard2_conf->group_id;
}

static INLINE const char * BcArchiveDir(void)
{
    return barnyard2_conf->archive_dir;
}

#ifdef MPLS
static INLINE long int BcMplsStackDepth(void)
{
    return barnyard2_conf->mpls_stack_depth;
}

static INLINE long int BcMplsPayloadType(void)
{
    return barnyard2_conf->mpls_payload_type;
}

#endif

static INLINE short BcSidMapVersion(void)
{
    return barnyard2_conf->sidmap_version;
}

static INLINE SigNode ** BcGetSigNodeHead(void)
{
    return &barnyard2_conf->sigHead;
}

static INLINE Barnyard2Config * BcGetConfig(void)
{
    return barnyard2_conf;
}

static INLINE char * BcGetSourceFile(u_int8_t source_file)
{
    switch(source_file)
    {

    case SOURCE_SID_MSG:
       	return barnyard2_conf->sid_msg_file;
	break;


    case SOURCE_GEN_MSG:
	return barnyard2_conf->gen_msg_file;
	break;
	
    default:
	return "UKNOWN FILE\n";
	break;
    }
}

static INLINE SigSuppress_list ** BCGetSigSuppressHead(void)
{
    return &barnyard2_conf->ssHead;
}

static INLINE void SigSuppressCount(void)
{
    pc.total_suppressed++;
    return;
}


#endif  /* __BARNYARD2_H__ */
