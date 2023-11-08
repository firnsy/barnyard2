/* $Id$ */
/*
** Copyright (C) 2002-2009 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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
 *
 * Program: barnyard2
 * Alot of code borrowed from snort. (all credit due)
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <timersub.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/stat.h>

#ifndef WIN32
#include <netdb.h>
#endif

#ifdef HAVE_GETOPT_LONG
//#define _GNU_SOURCE
/* A GPL copy of getopt & getopt_long src code is now in sfutil */
# undef HAVE_GETOPT_LONG
#endif
#include <getopt.h>

#ifndef RB_EXTRADATA
#ifdef TIMESTATS
# include <time.h>   /* added for new time stats function in util.c */
#endif
#endif

#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif

#ifndef WIN32
# include <grp.h>
# include <pwd.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
#endif  /* !WIN32 */

#if !defined(CATCH_SEGV) && !defined(WIN32)
# include <sys/resource.h>
#endif

#include "decode.h"
#include "barnyard2.h"
#include "rules.h"
#include "plugbase.h"
#include "debug.h"
#include "util.h"
#include "parser.h"
#include "log.h"
#include "map.h"
#include "mstring.h"
#include "strlcpyu.h"
#include "output-plugins/spo_log_tcpdump.h"

#ifdef HAVE_LIBPRELUDE
# include "output-plugins/spo_alert_prelude.h"
#endif

/* Macros *********************************************************************/
#ifndef DLT_LANE8023
/*
 * Old OPEN BSD Log format is 17.
 * Define DLT_OLDPFLOG unless DLT_LANE8023 (Suse 6.3) is already
 * defined in bpf.h.
 */
# define DLT_OLDPFLOG 17
#endif

/* Data types *****************************************************************/
typedef enum _GetOptArgType
{
    LONGOPT_ARG_NONE = 0,
    LONGOPT_ARG_REQUIRED,
    LONGOPT_ARG_OPTIONAL

} GetOptArgType;

/* Globals ********************************************************************/
PacketCount pc;  /* packet count information */

unsigned short stat_dropped = 0;
uint32_t *netmasks = NULL;   /* precalculated netmask array */
char **protocol_names = NULL;

char *barnyard2_conf_file = NULL;   /* -c */
char *barnyard2_conf_dir = NULL;

Barnyard2Config *barnyard2_cmd_line_conf = NULL;
Barnyard2Config *barnyard2_conf = NULL;

static struct timeval starttime;
static struct timeval endtime;

VarNode *cmd_line_var_list = NULL;

int exit_signal = 0;

static int usr_signal = 0;

#ifdef RB_EXTRADATA
static int alarm_raised = 0;
#endif

static volatile int hup_signal = 0;
volatile int barnyard2_initializing = 1;

InputConfigFuncNode  *input_config_funcs = NULL;
OutputConfigFuncNode *output_config_funcs = NULL;

PluginSignalFuncNode *plugin_shutdown_funcs = NULL;
PluginSignalFuncNode *plugin_clean_exit_funcs = NULL;
PluginSignalFuncNode *plugin_restart_funcs = NULL;

InputFuncNode *InputList = NULL;
OutputFuncNode *AlertList = NULL;   /* Alert function list */
OutputFuncNode *LogList = NULL;     /* Log function list */

int datalink;   /* the datalink value */
uint32_t pcap_snaplen = SNAPLEN;

static int exit_logged = 0;

static int barnyard2_argc = 0;
static char **barnyard2_argv = NULL;

/* command line options for getopt */
#ifndef WIN32
/* Unix does not support an argument to -s <wink marty!> OR -E, -W */
static char *valid_options = "?a:Ac:C:d:Def:Fg:G:h:i:Il:m:noOqr:R:S:t:Tu:UvVw:xXy";
#else
/* Win32 does not support:  -D, -g, -m, -t, -u */
/* Win32 no longer supports an argument to -s, either! */
static char *valid_options = "?a:Ac:C:d:eEf:FG:h:i:Il:noOqr:R:S:TUvVw:xXy";
#endif

static struct option long_options[] =
{
   {"snaplen", LONGOPT_ARG_REQUIRED, NULL, 'P'},
   {"version", LONGOPT_ARG_NONE, NULL, 'V'},
   {"help", LONGOPT_ARG_NONE, NULL, '?'},
   {"conf-error-out", LONGOPT_ARG_NONE, NULL,'x'},
   {"process-all-events", LONGOPT_ARG_NONE, NULL, PROCESS_ALL_EVENTS},
   {"restart", LONGOPT_ARG_NONE, NULL, ARG_RESTART},
   {"pid-path", LONGOPT_ARG_REQUIRED, NULL, PID_PATH},
   {"create-pidfile", LONGOPT_ARG_NONE, NULL, CREATE_PID_FILE},
   {"nolock-pidfile", LONGOPT_ARG_NONE, NULL, NOLOCK_PID_FILE},
   {"nostamps", LONGOPT_ARG_NONE, NULL, NO_LOGGING_TIMESTAMPS},
   {"gen-msg", LONGOPT_ARG_REQUIRED, NULL, 'G'},
   {"sid-msg", LONGOPT_ARG_REQUIRED, NULL, 'S'},
   {"reference", LONGOPT_ARG_REQUIRED, NULL, 'R'},
   {"classification", LONGOPT_ARG_REQUIRED, NULL, 'C'},
   {"disable-alert-on-each-packet-in-stream", LONGOPT_ARG_NONE, NULL, DISABLE_ALERT_ON_EACH_PACKET_IN_STREAM},
   {"event-cache-size", LONGOPT_ARG_REQUIRED, NULL, EVENT_CACHE_SIZE},
   {"alert-on-each-packet-in-stream", LONGOPT_ARG_NONE, NULL, ALERT_ON_EACH_PACKET_IN_STREAM},
   {"process-new-records-only", LONGOPT_ARG_NONE, NULL, 'n'},

#ifdef MPLS
   {"max-mpls-labelchain-len", LONGOPT_ARG_REQUIRED, NULL, MAX_MPLS_LABELCHAIN_LEN},
   {"mpls-payload-type", LONGOPT_ARG_REQUIRED, NULL, MPLS_PAYLOAD_TYPE},
#endif

   {0, 0, 0, 0}
};


/* Externs *******************************************************************/
/* for getopt */
extern char *optarg;
extern int optind;
extern int opterr;
extern int optopt;



/* Private function prototypes ************************************************/
static void InitNetmasks(void);
static void InitProtoNames(void);

static void Barnyard2Init(int, char **);
static void InitPidChrootAndPrivs(void);
static void ParseCmdLine(int, char **);
static int ShowUsage(char *);
static void PrintVersion(void);
static void SetBarnyard2ConfDir(void);
static void InitGlobals(void);
static Barnyard2Config * MergeBarnyard2Confs(Barnyard2Config *, Barnyard2Config *);
static void InitSignals(void);
#if defined(NOCOREFILE) && !defined(WIN32)
static void SetNoCores(void);
#endif

static void Barnyard2Cleanup(int,int);

static void FreeInputConfigs(InputConfig *);
static void FreeOutputConfigs(OutputConfig *);
static void FreePlugins(Barnyard2Config *);

static void Barnyard2PostInit(void);
static char * ConfigFileSearch(void);

int SignalCheck(void);

/* Signal handler declarations ************************************************/

static void SigExitHandler(int);
static void SigUsrHandler(int);
static void SigHupHandler(int);

#ifdef RB_EXTRADATA
static void SigAlrmHandler(int);
#endif


/*  F U N C T I O N   D E F I N I T I O N S  **********************************/

/*
 *
 * Function: main(int, char *)
 *
 * Purpose:  Handle program entry and exit, call main prog sections
 *           This can handle both regular (command-line) style
 *           startup, as well as Win32 Service style startup.
 *
 * Arguments: See command line args in README file
 *
 * Returns: 0 => normal exit, 1 => exit on error
 *
 */
int main(int argc, char *argv[]) 
{
    barnyard2_argc = argc;
    barnyard2_argv = argv;
    
    argc = 0;
    argv = NULL; 
    
#if defined(WIN32) && defined(ENABLE_WIN32_SERVICE)
    /* Do some sanity checking, because some people seem to forget to
     * put spaces between their parameters
     */
    if ((argc > 1) &&
        ((_stricmp(argv[1], (SERVICE_CMDLINE_PARAM SERVICE_INSTALL_CMDLINE_PARAM)) == 0) ||
         (_stricmp(argv[1], (SERVICE_CMDLINE_PARAM SERVICE_UNINSTALL_CMDLINE_PARAM)) == 0) ||
         (_stricmp(argv[1], (SERVICE_CMDLINE_PARAM SERVICE_SHOW_CMDLINE_PARAM)) == 0)))
    {
        FatalError("You must have a space after the '%s' command-line parameter\n",
                   SERVICE_CMDLINE_PARAM);
    }

    /* If the first parameter is "/SERVICE", then start Snort as a Win32 service */
    if((argc > 1) && (_stricmp(argv[1],SERVICE_CMDLINE_PARAM) == 0))
    {
        return Barnyard2ServiceMain(barnyard2_argc, barnyard2_argv);
    }
#endif /* WIN32 && ENABLE_WIN32_SERVICE */
    
    return Barnyard2Main(barnyard2_argc, barnyard2_argv);
}

/*
 *
 * Function: Barnyard2Main(int, char *)
 *
 * Purpose:  The real place that the program handles entry and exit.  Called
 *           called by main(), or by Barnyard2ServiceMain().
 *
 * Arguments: See command line args in README file
 *
 * Returns: 0 => normal exit, 1 => exit on error
 *
 */
int Barnyard2Main(int argc, char *argv[])
{
    InitSignals();

#if defined(NOCOREFILE) && !defined(WIN32)
    SetNoCores();
#endif

#ifdef WIN32
    if (!init_winsock())
        FatalError("Could not Initialize Winsock!\n");
#endif

restart:

    Barnyard2Init(argc, argv);

    if (BcDaemonMode())
    {
        GoDaemon();
    }

    Barnyard2PostInit();
    
	/* check for waldo file usage */
	if (barnyard2_conf->waldo.state & WALDO_STATE_ENABLED)
	{
		int				ret;

		ret = spoolerReadWaldo(&barnyard2_conf->waldo);

		/* show waldo file contents on successful load */
		if (ret == WALDO_FILE_SUCCESS)
		{
			LogMessage("Using waldo file '%s':\n"
						"    spool directory = %s\n"
						"    spool filebase  = %s\n"
						"    time_stamp      = %lu\n"
						"    record_idx      = %lu\n", 
						barnyard2_conf->waldo.filepath,
						barnyard2_conf->waldo.data.spool_dir,
						barnyard2_conf->waldo.data.spool_filebase,
						barnyard2_conf->waldo.data.timestamp,
						barnyard2_conf->waldo.data.record_idx);
		}
		else if (ret == WALDO_FILE_EEXIST)
		{
			LogMessage("Using empty waldo file '%s'\n", barnyard2_conf->waldo.filepath);
		}
		else if (ret == WALDO_FILE_ETRUNC)
		{
			LogMessage("WARNING: Ignoring corrupt/truncated waldo"
						"file '%s'\n", barnyard2_conf->waldo.filepath);
		}
	}

    /* Batch processing mode */
    if(BcBatchMode())
    {
        int idx;
		if( barnyard2_conf->batch_total_files == 0 )
        {
            LogMessage("No files to process!\n");
        }
        else
        {
            LogMessage("Processing %d files...\n", barnyard2_conf->batch_total_files);
            for(idx = 0; idx < barnyard2_conf->batch_total_files; idx++)
            {
		ProcessBatch("", barnyard2_conf->batch_filelist[idx]);
		if( SignalCheck())
		{
		    /* Clean Things up */
		    Barnyard2Cleanup(0,0);
		    /* Relaunch status */
		    goto restart;
		}
	    }
        }
    }
    /* Continual processing mode */
    else if (BcContinuousMode())
    {
	ProcessContinuousWithWaldo(&barnyard2_conf->waldo);
	
	if( SignalCheck())
	{	    
	    /* Clean Things up */
	    Barnyard2Cleanup(0,0);
	    /* Relaunch status */
	    goto restart;
	}
    }
    
#ifndef WIN32
    closelog();
#endif

    DropStats(1);

    return 0;
}

static void InitPidChrootAndPrivs(void)
{
    /* create the PID file */
    /* TODO should be part of the GoDaemon process */
    if (BcDaemonMode() || *barnyard2_conf->pidfile_suffix || BcCreatePidFile())
    {
#ifdef WIN32
        CreatePidFile("WIN32");
#else            
        CreatePidFile(PRINT_INTERFACE(barnyard2_conf->interface));
#endif /* WIN32 */
    }

#ifndef WIN32
    /* Drop the Chrooted Settings */
    if (barnyard2_conf->chroot_dir)
        SetChroot(barnyard2_conf->chroot_dir, &barnyard2_conf->log_dir);

    /* Drop privileges if requested, when initialization is done */
    SetUidGid(BcUid(), BcGid());
#endif  /* WIN32 */
}

/*
 * This function will print versioning information regardless of whether or
 * not the quiet flag is set.  If the quiet flag has been set and we want
 * to honor it, check it before calling this function.
 */
static void PrintVersion(void)
{
    /* Unset quiet flag so LogMessage will print, then restore just
     * in case anything other than exiting after this occurs */
    int save_quiet_flag = barnyard2_conf->logging_flags & LOGGING_FLAG__QUIET;

    barnyard2_conf->logging_flags &= ~LOGGING_FLAG__QUIET;
    DisplayBanner();
    
    barnyard2_conf->logging_flags |= save_quiet_flag;
}

/*
 * Function: ShowUsage(char *)
 *
 * Purpose:  Display the program options and exit
 *
 * Arguments: argv[0] => name of the program (argv[0])
 *
 * Returns: 0 => success
 */
static int ShowUsage(char *program_name)
{
    fprintf(stdout, "USAGE: %s [-options] <filter options>\n", program_name);
#if defined(WIN32) && defined(ENABLE_WIN32_SERVICE)
    fprintf(stdout, "       %s %s %s [-options] <filter options>\n", program_name
                                                                   , SERVICE_CMDLINE_PARAM
                                                                   , SERVICE_INSTALL_CMDLINE_PARAM);
    fprintf(stdout, "       %s %s %s\n", program_name
                                       , SERVICE_CMDLINE_PARAM
                                       , SERVICE_UNINSTALL_CMDLINE_PARAM);
    fprintf(stdout, "       %s %s %s\n", program_name
                                       , SERVICE_CMDLINE_PARAM
                                       , SERVICE_SHOW_CMDLINE_PARAM);
#endif

#ifdef WIN32
# define FPUTS_WIN32(msg) fputs(msg,stdout)
# define FPUTS_UNIX(msg)  NULL
# define FPUTS_BOTH(msg)  fputs(msg,stdout)
#else
# define FPUTS_WIN32(msg) 
# define FPUTS_UNIX(msg)  fputs(msg,stdout)
# define FPUTS_BOTH(msg)  fputs(msg,stdout)
#endif

    FPUTS_BOTH ("Gernal Options:\n");

//    FPUTS_BOTH ("        -A         Dump the Application Layer\n");
    FPUTS_BOTH ("        -c <file>  Use configuration file <file>\n");
    FPUTS_BOTH ("        -C <file>  Read the classification map from <file>\n");
    FPUTS_UNIX ("        -D         Run barnyard2 in background (daemon) mode\n");
    FPUTS_BOTH ("        -e         Display the second layer header info\n");
    FPUTS_WIN32("        -E         Log alert messages to NT Eventlog. (Win32 only)\n");
    FPUTS_BOTH ("        -F         Turn off fflush() calls after binary log writes\n");
    FPUTS_UNIX ("        -g <gname> Run barnyard2 gid as <gname> group (or gid) after initialization\n");
    FPUTS_BOTH ("        -G <file>  Read the gen-msg map from <file>\n");
    FPUTS_BOTH ("        -h <name>  Define the hostname <name>. For logging purposes only\n");
    FPUTS_BOTH ("        -i <if>    Define the interface <if>. For logging purposes only\n");
    FPUTS_BOTH ("        -I         Add Interface name to alert output\n");
    FPUTS_BOTH ("        -l <ld>    Log to directory <ld>\n");
    FPUTS_UNIX ("        -m <umask> Set umask = <umask>\n");
    FPUTS_BOTH ("        -O         Obfuscate the logged IP addresses\n");
    FPUTS_BOTH ("        -q         Quiet. Don't show banner and status report\n");
    FPUTS_BOTH ("        -r <id>    Include 'id' in barnyard2_intf<id>.pid file name\n");
    FPUTS_BOTH ("        -R <file>  Read the reference map from <file>\n");
//    FPUTS_BOTH ("        -s         Log alert messages to syslog\n");
    FPUTS_BOTH ("        -S <file>  Read the sid-msg map from <file>\n");
    FPUTS_UNIX ("        -t <dir>   Chroots process to <dir> after initialization\n");
    FPUTS_BOTH ("        -T         Test and report on the current barnyard2 configuration\n");
    FPUTS_UNIX ("        -u <uname> Run barnyard2 uid as <uname> user (or uid) after initialization\n");
    FPUTS_BOTH ("        -U         Use UTC for timestamps\n");
    FPUTS_BOTH ("        -v         Be verbose\n");
    FPUTS_BOTH ("        -V         Show version number\n");
//    FPUTS_BOTH ("        -X         Dump the raw packet data starting at the link layer\n");
//    FPUTS_BOTH ("        -x         Dump application data as chars only\n");
    FPUTS_BOTH ("        -y         Include year in timestamp in the alert and log files\n");
    FPUTS_BOTH ("        -?         Show this information\n");
    FPUTS_BOTH ("\n");
    FPUTS_BOTH ("Continual Processing Options:\n");
    FPUTS_UNIX ("        -a <dir>   Archive processed files to <dir>\n");
    FPUTS_BOTH ("        -f <base>  Use <base> as the base filename pattern\n");
    FPUTS_BOTH ("        -d <dir>   Spool files from <dir>\n");
    FPUTS_BOTH ("        -n         Only process new events\n");
    FPUTS_BOTH ("        -w <file>  Enable bookmarking using <file>\n");
	FPUTS_BOTH ("\n");
    FPUTS_BOTH ("Batch Processing Mode Options:\n");
    FPUTS_BOTH ("        -o         Enable batch processing mode\n");
	FPUTS_BOTH ("\n");

    FPUTS_BOTH ("Longname options and their corresponding single char version\n");
    FPUTS_BOTH ("   --disable-alert-on-each-packet-in-stream  Alert once per event\n");
    FPUTS_BOTH ("   --event-cache-size <integer>      Set Spooler MAX event cache size \n");
    FPUTS_BOTH ("   --reference <file>                Same as -R\n");
    FPUTS_BOTH ("   --classification <file>           Same as -C\n");
    FPUTS_BOTH ("   --gen-msg <file>                  Same as -G\n");
    FPUTS_BOTH ("   --sid-msg <file>                  Same as -S\n");
    FPUTS_BOTH ("   --process-new-records-only        Same as -n\n");
    FPUTS_BOTH ("   --pid-path <dir>                  Specify the directory for the barnyard2 PID file\n");
    FPUTS_BOTH ("   --help                            Same as -?\n");
    FPUTS_BOTH ("   --version                         Same as -V\n");
    FPUTS_UNIX ("   --create-pidfile                  Create PID file, even when not in Daemon mode\n");
    FPUTS_UNIX ("   --nolock-pidfile                  Do not try to lock barnyard2 PID file\n");
#ifdef MPLS
    FPUTS_BOTH ("   --max-mpls-labelchain-len         Specify the max MPLS label chain\n");
    FPUTS_BOTH ("   --mpls-payload-type               Specify the protocol (ipv4, ipv6, ethernet) that is encapsulated by MPLS\n");
#endif
//    FPUTS_BOTH ("   --conf-error-out                Same as -x\n");
#undef FPUTS_WIN32
#undef FPUTS_UNIX
#undef FPUTS_BOTH
    return 0;
}

/*
 * Function: ParseCmdLine(int, char **)
 *
 * Parses command line arguments
 *
 * Arguments:
 *  int
 *      count of arguments passed to the routine
 *  char **
 *      2-D character array, contains list of command line args
 *
 * Returns: None
 *
 */

static void ParseCmdLine(int argc, char **argv)
{
    int ch;
    int i;
    int option_index = -1;
    char *pcap_filter = NULL;
    Barnyard2Config *bc;
    int syslog_configured = 0;
#ifndef WIN32
    int daemon_configured = 0;
#endif
#ifdef WIN32
    char errorbuf[PCAP_ERRBUF_SIZE];
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Parsing command line...\n"););

    if (barnyard2_cmd_line_conf != NULL)
    {
        FatalError("%s(%d) Trying to parse the command line again.\n",
                   __FILE__, __LINE__);
    }
    
    barnyard2_cmd_line_conf = Barnyard2ConfNew();
    barnyard2_conf = barnyard2_cmd_line_conf;     /* Set the global for log messages */
    bc = barnyard2_cmd_line_conf;
    
    /* alert_on_each_packet_in_stream_flag enabled by default */
    bc->alert_on_each_packet_in_stream_flag = 1;
    
    /* Look for a -D and/or -M switch so we can start logging to syslog
     * with "barnyard2" tag right away */
    for (i = 0; i < argc; i++)
    {
        if (strcmp("-M", argv[i]) == 0)
        {
            if (syslog_configured)
                continue;

            /* If daemon or logging to syslog use "snort" as identifier and
             * start logging there now */
            openlog("barnyard2", LOG_PID | LOG_CONS, LOG_DAEMON); 

            bc->logging_flags |= LOGGING_FLAG__SYSLOG;
            syslog_configured = 1;
        }
#ifndef WIN32
        else if ((strcmp("-D", argv[i]) == 0) ||
                 (strcmp("--restart", argv[i]) == 0))
        {
            if (daemon_configured)
                continue;

            /* If daemon or logging to syslog use "barnyard2" as identifier and
             * start logging there now */
            openlog("barnyard2", LOG_PID | LOG_CONS, LOG_DAEMON); 

            if (strcmp("--restart", argv[i]) == 0)
                bc->run_flags |= RUN_FLAG__DAEMON_RESTART;

            ConfigDaemon(bc, optarg);
            daemon_configured = 1;
        }
#endif
        else if (strcmp("-q", argv[i]) == 0)
        {
            /* Turn on quiet mode if configured so any log messages that may
             * be printed while parsing the command line before the quiet option
             * is read won't be printed */
            ConfigQuiet(bc, NULL);
        }
    }

    /*
    **  Set this so we know whether to return 1 on invalid input.
    **  Snort uses '?' for help and getopt uses '?' for telling us there
    **  was an invalid option, so we can't use that to tell invalid input.
    **  Instead, we check optopt and it will tell us.
    */
    optopt = 0;
    optind = 0; /* in case we are being re-invoked , think HUP */

    /* loop through each command line var and process it */
    while ((ch = getopt_long(argc, argv, valid_options, long_options, &option_index)) != -1)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Processing cmd line switch: %c\n", ch););

        switch (ch)
        {
            case PID_PATH:
                ConfigPidPath(bc, optarg);
                break;

            case CREATE_PID_FILE:
                ConfigCreatePidFile(bc, NULL);
                break;

            case NOLOCK_PID_FILE:
                bc->run_flags |= RUN_FLAG__NO_LOCK_PID_FILE;
                break;

            case NO_LOGGING_TIMESTAMPS:
                ConfigNoLoggingTimestamps(bc, NULL);
                break;

            case DISABLE_ALERT_ON_EACH_PACKET_IN_STREAM:
                ConfigDisableAlertOnEachPacketInStream(bc, NULL);
                break;

           case EVENT_CACHE_SIZE:
                ConfigSetEventCacheSize(bc,optarg);
                break;

            case ALERT_ON_EACH_PACKET_IN_STREAM:
                ConfigAlertOnEachPacketInStream(bc, NULL);
                break;

#ifdef MPLS
            case MAX_MPLS_LABELCHAIN_LEN:
                ConfigMaxMplsLabelChain(bc, optarg);
                break;

            case MPLS_PAYLOAD_TYPE:
                ConfigMplsPayloadType(bc, optarg);
                break;
#endif

            case 'a':  /* use archive directory <x> */
                ConfigArchiveDir(bc, optarg);
                break;

            case 'A':  /* dump the application layer data */
                ConfigDumpPayload(bc, NULL);
                break;

            case 'B':  /* obfuscate with a substitution mask */
                ConfigObfuscationMask(bc, optarg);
                break;

            case 'c':  /* use configuration file x */
                barnyard2_conf_file = SnortStrdup(optarg);
                break;

            case 'C':  /* set the classification file */
                ConfigClassificationFile(bc, optarg);
                break;

            case 'd':  /* dump the application layer data */
                bc->run_mode_flags |= RUN_MODE_FLAG__CONTINUOUS;
                ConfigSpoolDirectory(bc, optarg);
                break;

            case ARG_RESTART:  /* Restarting from daemon mode */
            case 'D':  /* daemon mode */
                /* These are parsed at the beginning so as to start logging
                 * to syslog right away */
                break;

            case 'e':  /* show second level header info */
                ConfigDecodeDataLink(bc, NULL);
                break;
#ifdef WIN32
            case 'E':  /* log alerts to Event Log */
                ParseOutput(bc, NULL, "alert_syslog");
                bc->logging_flags &= ~LOGGING_FLAG__SYSLOG_REMOTE;
                break;
#endif
            case 'f':
                bc->run_mode_flags |= RUN_MODE_FLAG__CONTINUOUS;
                ConfigSpoolFilebase(bc, optarg);
                break;

            case 'F':
                bc->output_flags |= OUTPUT_FLAG__LINE_BUFFER;
                break;

            case 'g':   /* setgid */
                ConfigSetGid(bc, optarg);
                break;



            case 'h':
                ConfigHostname(bc, optarg);
                break;

            case 'i':
                ConfigInterface(bc, optarg);
                break;

            case 'I':  /* add interface name to alert string */
                ConfigAlertWithInterfaceName(bc, NULL);
                break;

            case 'l':  /* use log dir <X> */
                ConfigLogDir(bc, optarg);
                break;

            case 'M':
                /* This is parsed at the beginning so as to start logging
                 * to syslog right away */
                break;
                
            case 'm':  /* set the umask for the output files */
                ConfigUmask(bc, optarg);
                break;

            case 'n': /* process new records only */
                ConfigProcessNewRecordsOnly(bc, NULL);
                break;

            case 'o':  /* use configuration file x */
                bc->run_mode_flags |= RUN_MODE_FLAG__BATCH;
                break;

            case 'O':  /* obfuscate the logged IP addresses for privacy */
                ConfigObfuscate(bc, NULL);
                break;

            case 'q':  /* no stdout output mode */
                /* This is parsed at the beginning so as to start logging
                 * in quiet mode right away */
                break;

            case 'r': /* augment pid file name suffix */
                if ((strlen(optarg) >= MAX_PIDFILE_SUFFIX) || (strlen(optarg) <= 0) ||
                    (strstr(optarg, "..") != NULL) || (strstr(optarg, "/") != NULL))
                {
                        FatalError("Invalid pidfile suffix: %s.  Suffix must "
                                   "less than %u characters and not have "
                                   "\"..\" or \"/\" in the name.\n", optarg,
                                   MAX_PIDFILE_SUFFIX);
                }

                SnortStrncpy(bc->pidfile_suffix, optarg, sizeof(bc->pidfile_suffix));
                break;

            case 'R': /* augment pid file name suffix */
                ConfigReferenceFile(bc, optarg);
                break;

            case 's':  /* log alerts to syslog */
#ifndef WIN32
                ParseOutput(bc, "alert_syslog");
#else
                bc->logging_flags |= LOGGING_FLAG__SYSLOG_REMOTE;
#endif
                break;

     	    case 'S':  /* set a rules file variable */
		bc->sid_msg_file = strndup(optarg,PATH_MAX);
		break;
		
   	    case 'G':  /* snort preprocessor identifier */
		bc->gen_msg_file = strndup(optarg,PATH_MAX);
		break;

            case 't':  /* chroot to the user specified directory */
                ConfigChrootDir(bc, optarg);
                break;

            case 'T':  /* test mode, verify that the rules load properly */
                bc->run_mode_flags |= RUN_MODE_FLAG__TEST;
                break;    

            case 'u':  /* setuid */
                ConfigSetUid(bc, optarg);
                break;

            case 'U':  /* use UTC */
                ConfigUtc(bc, NULL);
                break;

            case 'v':  /* be verbose */
                ConfigVerbose(bc, NULL);
                break;

            case 'V':  /* prog ver already gets printed out, so we just exit */
                bc->run_mode_flags |= RUN_MODE_FLAG__VERSION;
                bc->logging_flags |= LOGGING_FLAG__QUIET;
                break;

#if !defined(NO_NON_ETHER_DECODER) && defined(DLT_IEEE802_11)
//          case 'w':  /* show 802.11 all frames info */
//              bc->output_flags |= OUTPUT_FLAG__SHOW_WIFI_MGMT;
//              break;
#endif
            case 'w':
                bc->run_mode_flags |= RUN_MODE_FLAG__CONTINUOUS;
                ConfigWaldoFile(bc, optarg);
                break;

            case 'X':  /* display verbose packet bytecode dumps */
                ConfigDumpPayloadVerbose(bc, NULL);
                break;
                
            case 'x':  /* dump the application layer as text only */
                ConfigDumpCharsOnly(bc, NULL);
                break;
                
            case 'y':  /* Add year to timestamp in alert and log files */
                ConfigShowYear(bc, NULL);
                break;

            case '?':  /* show help and exit with 0 since this is what was requested */
                PrintVersion();
                ShowUsage(argv[0]);
                exit(0);
                break;

            default:
                FatalError("Invalid option: %c.\n", ch);
                break;
        }
    }

    /* when batch processing check for any remaining arguments which should */
    /* be a parsed as a list of files to process. */
    if ((bc->run_mode_flags & RUN_MODE_FLAG__BATCH) && (optind < argc))
    {
	int idx = 0;
	
	bc->batch_total_files = argc - optind;
	bc->batch_filelist = SnortAlloc(bc->batch_total_files * sizeof(char *));
	
	while (optind < argc)
	{
	    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Extra args: %s\n", argv[optind]););
	    bc->batch_filelist[idx] = SnortStrdup(argv[optind]);
	    
	    idx++;
	    optind++;
	}
	
	DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Total files: %i\n", bc->batch_total_files););
    }
    
    if ((bc->run_mode_flags & RUN_MODE_FLAG__TEST) &&
        (bc->run_flags & RUN_FLAG__DAEMON))
    {
        FatalError("Cannot use test mode and daemon mode together.\n"
                   "To verify configuration, run first in test "
                   "mode and then restart in daemon mode.\n");
    }
    else if ((bc->run_mode_flags & RUN_MODE_FLAG__BATCH) &&
	     (bc->run_flags & RUN_MODE_FLAG__CONTINUOUS))
    {
        FatalError("Cannot use batch mode and continuous mode together.\n");
    }
    
    
    if ((bc->run_mode_flags & RUN_MODE_FLAG__TEST) &&
        (barnyard2_conf_file == NULL))
    {
        FatalError("Test mode must be run with a snort configuration "
                   "file.  Use the '-c' option on the command line to "
                   "specify a configuration file.\n");
    }
    
    if (pcap_filter != NULL)
        free(pcap_filter);
    
    /* Set the run mode based on what we've got from command line */

    /* Version overrides all */
    if (bc->run_mode_flags & RUN_MODE_FLAG__VERSION)
    {
        bc->run_mode = RUN_MODE__VERSION;
    }
    /* Next if we want to test a snort conf */
    else if (bc->run_mode_flags & RUN_MODE_FLAG__TEST)
    {
        bc->run_mode = RUN_MODE__TEST;
    }
    /* Now if there is a barnyard2 conf.  If a barnyard2 conf wasn't given on the
     * command line, we'll look in a default place if the next ones
     * don't match */
    else if ((bc->run_mode_flags & RUN_MODE_FLAG__CONTINUOUS) && (barnyard2_conf_file != NULL))
    {
        bc->run_mode = RUN_MODE__CONTINUOUS;
    }
    else if ((bc->run_mode_flags & RUN_MODE_FLAG__BATCH) && (barnyard2_conf_file != NULL))
    {
        bc->run_mode = RUN_MODE__BATCH;
    }

    if (!bc->run_mode)
        bc->run_mode = RUN_MODE__CONTINUOUS;

    /* If no mode is set, try and find snort conf in some default location */
    if (((bc->run_mode == RUN_MODE__CONTINUOUS) || (bc->run_mode == RUN_MODE__BATCH) ||
        (bc->run_mode == RUN_MODE__TEST)) && (barnyard2_conf_file == NULL))
    {
        barnyard2_conf_file = ConfigFileSearch();
        if (barnyard2_conf_file == NULL)
        {
            /* unable to determine a run mode */
            DisplayBanner();
            ShowUsage(argv[0]);
            
            ErrorMessage("\n");
            ErrorMessage("\n");
            ErrorMessage("Uh, you need to tell me to do something...");
            ErrorMessage("\n");
            ErrorMessage("\n");
            FatalError("");
        }
    }

    SetBarnyard2ConfDir();
}

/* locate one of the possible default config files */
/* allocates memory to hold filename */
static char *ConfigFileSearch(void)
{
    struct stat st;
    int i;
    char *conf_files[]={"/etc/barnyard2.conf", "./barnyard2.conf", NULL};
    char *fname = NULL;
    char *rval = NULL;

    i = 0;

    /* search the default set of config files */
    while(conf_files[i])
    {
        fname = conf_files[i];

        if(stat(fname, &st) != -1)
        {
            rval = SnortStrdup(fname);
            break;
        }
        i++;
    }

    /* search for .barnyard2rc in the HOMEDIR */
    if(!rval)
    {
        char *home_dir = NULL;

        if((home_dir = getenv("HOME")) != NULL)
        {
            char *snortrc = "/.barnyard2rc";
            int path_len;

            path_len = strlen(home_dir) + strlen(snortrc) + 1;

            /* create the full path */
            fname = (char *)SnortAlloc(path_len);

            SnortSnprintf(fname, path_len, "%s%s", home_dir, snortrc);

            if(stat(fname, &st) != -1)
                rval = fname;
            else
                free(fname);
        }
    }

    return rval;
}

/* Signal Handlers ************************************************************/
static void SigExitHandler(int signal)
{
    if (exit_signal != 0)
        return;

    if (barnyard2_initializing)
        _exit(0);
    
    exit_signal = signal;
    return;
}

static void SigUsrHandler(int signal)
{
    if ( (usr_signal != 0) || 
	 (exit_signal != 0))
        return;
    
    usr_signal = signal;
    return;
}

static void SigHupHandler(int signal)
{
    if(exit_signal  != 0)
	return;
    
    exit_signal = 1;
    hup_signal = 1;
    
    return;
}

#ifdef RB_EXTRADATA
static void SigAlrmHandler(int signal)
{
    alarm_raised = 1;
}
#endif

/****************************************************************************
 *
 * Function: CleanExit()
 *
 * Purpose:  Clean up misc file handles and such and exit
 *
 * Arguments: exit value;
 *
 * Returns: void function
 *
 ****************************************************************************/
void CleanExit(int exit_val)
{
    LogMessage("Barnyard2 exiting\n");

#ifndef WIN32
    closelog();
#endif
    
    Barnyard2Cleanup(exit_val,1);
}


static void Barnyard2Cleanup(int exit_val,int exit_needed)
{
    PluginSignalFuncNode *idxPlugin = NULL;
    PluginSignalFuncNode *idxPluginNext = NULL;

    /* This function can be called more than once. */
    static int already_exiting = 0;
    
    if( already_exiting != 0 )
    {
        return;
    }

    already_exiting = 1;
    
    barnyard2_initializing = 0;  /* just in case we cut out early */
    
    if (BcContinuousMode() || BcBatchMode())
    {
        /* Do some post processing on any incomplete Plugin Data */
	idxPlugin = plugin_clean_exit_funcs;
        while(idxPlugin)
        {
	    idxPluginNext = idxPlugin->next;
            idxPlugin->func(SIGQUIT, idxPlugin->arg);
	    free(idxPlugin);
            idxPlugin = idxPluginNext;
        }
	plugin_clean_exit_funcs = NULL;
    }




	/*
	  Right now we will just free them if they are initialized since
	  in the context we operate if we receive HUP we mainly just "restart"
	*/
	idxPlugin = plugin_restart_funcs;
	while(idxPlugin)
        {
            idxPluginNext = idxPlugin->next;
            free(idxPlugin);
            idxPlugin = idxPluginNext;
        }
	plugin_restart_funcs = NULL;
    

	idxPlugin = plugin_shutdown_funcs;
	while(idxPlugin)
        {
            idxPluginNext = idxPlugin->next;
            free(idxPlugin);
            idxPlugin = idxPluginNext;
        }
	plugin_shutdown_funcs = NULL;

    
    if (!exit_val)
    {
        struct timeval difftime;
        struct timezone tz;
	
	memset((char *) &tz, 0, sizeof(tz)); /* bzero() deprecated, replaced by memset() */
        gettimeofday(&endtime, &tz);
	
        TIMERSUB(&endtime, &starttime, &difftime);
	
        if (exit_signal)
        {
            LogMessage("Run time prior to being shutdown was %lu.%lu seconds\n", 
                       (unsigned long)difftime.tv_sec,
                       (unsigned long)difftime.tv_usec);
        }
    }

    if (BcContinuousMode() || BcBatchMode() || BcTestMode())
    {
        /* Do some post processing on any incomplete Plugin Data */
        idxPlugin = plugin_clean_exit_funcs;
        while(idxPlugin)
        {
	    idxPluginNext = idxPlugin->next;
            idxPlugin->func(SIGQUIT, idxPlugin->arg);
	    free(idxPlugin);
            idxPlugin = idxPluginNext;
        }
	plugin_clean_exit_funcs = NULL;
    }

    /* Print Statistics */
    if (!BcTestMode() && !BcVersionMode())
    {
	if(!stat_dropped)
	{
	    DropStats(2);
	}
	else
	{
	    stat_dropped = 0;
	}
    }

    /* Cleanup some spooler stuff */
    if(barnyard2_conf->spooler)
    {
	spoolerEventCacheFlush(barnyard2_conf->spooler);
	
	if(barnyard2_conf->spooler->header)
	{
	    free(barnyard2_conf->spooler->header);
	    barnyard2_conf->spooler->header = NULL;
	}

	if(barnyard2_conf->spooler->record.header)
	{
	    free(barnyard2_conf->spooler->record.header);
	    barnyard2_conf->spooler->record.header = NULL;
	}

	if(barnyard2_conf->spooler->record.data)
	{
	    free(barnyard2_conf->spooler->record.data);
	    barnyard2_conf->spooler->record.data = NULL;
	}
    }
    
    CleanupProtoNames();
    ClosePidFile();
    
    /* remove pid file */
    if (SnortStrnlen(barnyard2_conf->pid_filename, sizeof(barnyard2_conf->pid_filename)) > 0)
    {
        int ret;
        ret = unlink(barnyard2_conf->pid_filename);       
	
        if (ret != 0)
        {    
            ErrorMessage("Could not remove pid file %s: %s\n",
                         barnyard2_conf->pid_filename, strerror(errno));
        }
    }

    spoolerCloseWaldo(&barnyard2_conf->waldo);

    if(barnyard2_conf->spooler)
    {
	spoolerClose(barnyard2_conf->spooler);
	barnyard2_conf->spooler = NULL;
    }

    
    /* free allocated memory */
    if (barnyard2_conf == barnyard2_cmd_line_conf)
    {
        Barnyard2ConfFree(barnyard2_cmd_line_conf);
        barnyard2_cmd_line_conf = NULL;
        barnyard2_conf = NULL;
    }
    else
    {
        Barnyard2ConfFree(barnyard2_cmd_line_conf);
        barnyard2_cmd_line_conf = NULL;
        Barnyard2ConfFree(barnyard2_conf);
        barnyard2_conf = NULL;
    }

    FreeOutputList(AlertList);
    FreeOutputList(LogList);    
    AlertList = NULL;
    LogList = NULL;

    FreeOutputConfigFuncs();

    FreeInputPlugins();
    
    /* Global lists */
    ParserCleanup();
    
    /* Stuff from plugbase */
    ClearDumpBuf();
    
    if (netmasks != NULL)
    {
        free(netmasks);
        netmasks = NULL;
    }
    
    if (barnyard2_conf_file != NULL)
    {
        free(barnyard2_conf_file);
	barnyard2_conf_file = NULL;
    }
    
    if (barnyard2_conf_dir != NULL)
    {
        free(barnyard2_conf_dir);
	barnyard2_conf_dir = NULL;
    }
    
    if(exit_needed)
	_exit(exit_val);

    already_exiting = 0;
    return;
}

void Restart(void)
{
    int daemon_mode = BcDaemonMode();

#ifndef WIN32
    if ((getuid() != 0) || (barnyard2_conf->chroot_dir != NULL))
    {
        LogMessage("Reload via Signal HUP does not work if you aren't root "
                   "or are chroot'ed.\n");
        return;
    }
#endif

    LogMessage("\n");
    LogMessage("***** Restarting Barnyard2 *****\n");
    LogMessage("\n");
    Barnyard2Cleanup(0,0);

    if (daemon_mode)
    {
        int i;

        for (i = 0; i < barnyard2_argc; i++)
        {
            if (!strcmp(barnyard2_argv[i], "--restart"))
            {
                break;
            }
            else if (!strncmp(barnyard2_argv[i], "-D", 2))
            {
                /* Replace -D with --restart */
                /* a probable memory leak - but we're exec()ing anyway */
                barnyard2_argv[i] = SnortStrdup("--restart");
                break;
            }
        }
    }

#ifdef PARANOID
    execv(barnyard2_argv[0], barnyard2_argv);
#else
    execvp(barnyard2_argv[0], barnyard2_argv);
#endif

    /* only get here if we failed to restart */
    LogMessage("Restarting %s failed: %s\n", barnyard2_argv[0], strerror(errno));

#ifndef WIN32
    closelog();
#endif

    exit(-1);
}


/*
 *  Check for signal activity 
 */
int SignalCheck(void)
{
    switch (exit_signal)
    {

    case SIGTERM:
	if (!exit_logged)
	{
	    ErrorMessage("*** Caught Term-Signal\n");
	    exit_logged = 1;
	}
	
	CleanExit(exit_signal);
	break;
	
    case SIGINT:
	if (!exit_logged)
	{
	    ErrorMessage("*** Caught Int-Signal\n");
	    exit_logged = 1;
	}
	
	CleanExit(exit_signal);
	break;
	
    case SIGQUIT:
	if (!exit_logged)
	{
	    ErrorMessage("*** Caught Quit-Signal\n");
	    exit_logged = 1;
	}
	
	CleanExit(exit_signal);
	break;
	
    case SIGKILL:
	if (!exit_logged)
        {
            ErrorMessage("*** Caught Kill-Signal\n");
            exit_logged = 1;
        }
	
	CleanExit(exit_signal);
	break;

    default:
	break;
    }
    
    exit_signal = 0;
    
    switch (usr_signal)
    {
    case SIGUSR1:
	ErrorMessage("*** Caught Usr-Signal\n");
	DropStats(0);
	break;
	
    case SIGNAL_SNORT_ROTATE_STATS:
	ErrorMessage("*** Caught Usr-Signal: 'Rotate Stats'\n");
	break;
    }
    
    usr_signal = 0;
    
    if (hup_signal)
    {
        ErrorMessage("*** Caught Hup-Signal\n");
	DropStats(0);
	stat_dropped = 1;
	ErrorMessage("*** Resetting Stats\n");
	memset(&pc,'\0',sizeof(PacketCount));
        hup_signal = 0;
        return 1;
    }
    
    return 0;
}

#ifdef RB_EXTRADATA
/* check for alarm activity */
int AlarmCheck(void)
{
    return alarm_raised;
}

/* start alarm */
void AlarmStart(int time_alarm)
{
    alarm(time_alarm);
}

/* clear alarm */
void AlarmClear(void)
{
    alarm_raised = 0;
}
#endif

static void InitGlobals(void)
{
    memset(&pc, 0, sizeof(PacketCount));
    InitNetmasks();
    InitProtoNames();
}

/* XXX Alot of this initialization can be skipped if not running
 * in IDS mode */
Barnyard2Config * Barnyard2ConfNew(void)
{
    Barnyard2Config *bc = (Barnyard2Config *)SnortAlloc(sizeof(Barnyard2Config));

    bc->user_id = -1;
    bc->group_id = -1;

    memset(bc->pid_path, 0, sizeof(bc->pid_path));
    memset(bc->pid_filename, 0, sizeof(bc->pid_filename));
    memset(bc->pidfile_suffix, 0, sizeof(bc->pidfile_suffix));

    memset(bc->waldo.data.spool_dir, 0, sizeof(bc->waldo.data.spool_dir));
    memset(bc->waldo.data.spool_filebase, 0, sizeof(bc->waldo.data.spool_filebase));
    memset(bc->waldo.filepath, 0, sizeof(bc->waldo.filepath));

    return bc;
}

void Barnyard2ConfFree(Barnyard2Config *bc)
{
    if (bc == NULL)
        return;
       
    if (bc->log_dir != NULL)
    {
        free(bc->log_dir);
	bc->log_dir = NULL;
    }
    
    if (bc->orig_log_dir != NULL)
    {
        free(bc->orig_log_dir);
	bc->orig_log_dir = NULL;
    }
    
    if (bc->interface != NULL)
    {
        free(bc->interface);
	bc->interface = NULL;
    }
    
    if (bc->chroot_dir != NULL)
    {
        free(bc->chroot_dir);
	bc->chroot_dir = NULL;
    }
    
    if (bc->archive_dir != NULL)
    {
        free(bc->archive_dir);
	bc->archive_dir = NULL;
    }
    
    if(bc->config_file != NULL)
    {
	free(bc->config_file);
	bc->config_file = NULL;
    }
    
    if(bc->config_dir != NULL)
    {
	free(bc->config_dir);
	bc->config_dir = NULL;
    }
    
    if(bc->hostname != NULL)
    {
	free(bc->hostname);
	bc->hostname = NULL;
    }
    
    if(bc->class_file != NULL)
    {
	free(bc->class_file);
	bc->class_file = NULL;
    }
    
    if( bc->sid_msg_file != NULL)
    {
	free(bc->sid_msg_file);
	bc->sid_msg_file = NULL;
    }

    if( bc->gen_msg_file != NULL)
    {
	free(bc->gen_msg_file);
	bc->gen_msg_file = NULL;
    }

    if( bc->reference_file != NULL)
    {
	free(bc->reference_file);
	bc->reference_file = NULL;
    }

    if( bc->bpf_filter != NULL)
    {
	free(bc->bpf_filter);
	bc->bpf_filter = NULL;
    }
    
    if (bc->batch_total_files > 0)
    {
	int idx;
	for(idx = 0; idx< bc->batch_total_files; idx++)
	{
	    free(bc->batch_filelist[idx]);
	    bc->batch_filelist[idx] = NULL;
	}
	free(bc->batch_filelist);
    }

    FreeSigSuppression(&bc->ssHead);
    FreeSigNodes(&bc->sigHead);
    FreeClassifications(&bc->classifications);
    FreeReferences(&bc->references);
    
    FreeInputConfigs(bc->input_configs);
    bc->input_configs = NULL;
    
    FreeOutputConfigs(bc->output_configs);
    bc->output_configs = NULL;
    
    VarTablesFree(bc);
    FreePlugins(bc);
    
    free(bc);
}

/****************************************************************************
 *
 * Function: InitNetMasks()
 *
 * Purpose: Loads the netmask struct in network order.  Yes, I know I could
 *          just load the array when I define it, but this is what occurred
 *          to me when I wrote this at 3:00 AM.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
static void InitNetmasks(void)
{
    if (netmasks == NULL)
        netmasks = (uint32_t *)SnortAlloc(33 * sizeof(uint32_t));

    netmasks[0]  = 0x00000000;
    netmasks[1]  = 0x80000000;
    netmasks[2]  = 0xC0000000;
    netmasks[3]  = 0xE0000000;
    netmasks[4]  = 0xF0000000;
    netmasks[5]  = 0xF8000000;
    netmasks[6]  = 0xFC000000;
    netmasks[7]  = 0xFE000000;
    netmasks[8]  = 0xFF000000;
    netmasks[9]  = 0xFF800000;
    netmasks[10] = 0xFFC00000;
    netmasks[11] = 0xFFE00000;
    netmasks[12] = 0xFFF00000;
    netmasks[13] = 0xFFF80000;
    netmasks[14] = 0xFFFC0000;
    netmasks[15] = 0xFFFE0000;
    netmasks[16] = 0xFFFF0000;
    netmasks[17] = 0xFFFF8000;
    netmasks[18] = 0xFFFFC000;
    netmasks[19] = 0xFFFFE000;
    netmasks[20] = 0xFFFFF000;
    netmasks[21] = 0xFFFFF800;
    netmasks[22] = 0xFFFFFC00;
    netmasks[23] = 0xFFFFFE00;
    netmasks[24] = 0xFFFFFF00;
    netmasks[25] = 0xFFFFFF80;
    netmasks[26] = 0xFFFFFFC0;
    netmasks[27] = 0xFFFFFFE0;
    netmasks[28] = 0xFFFFFFF0;
    netmasks[29] = 0xFFFFFFF8;
    netmasks[30] = 0xFFFFFFFC;
    netmasks[31] = 0xFFFFFFFE;
    netmasks[32] = 0xFFFFFFFF;
}

/****************************************************************************
 *
 * Function: InitProtoNames()
 *
 * Purpose: Initializes the protocol names
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
static void InitProtoNames(void)
{
    int i;

    if (protocol_names == NULL)
        protocol_names = (char **)SnortAlloc(sizeof(char *) * NUM_IP_PROTOS);

    for (i = 0; i < NUM_IP_PROTOS; i++)
    {
        struct protoent *pt = getprotobynumber(i);

        if (pt != NULL)
        {
            size_t j;

            protocol_names[i] = SnortStrdup(pt->p_name);
            for (j = 0; j < strlen(protocol_names[i]); j++)
                protocol_names[i][j] = toupper(protocol_names[i][j]);
        }
        else
        {
            char protoname[10];

            SnortSnprintf(protoname, sizeof(protoname), "PROTO:%03d", i);
            protocol_names[i] = SnortStrdup(protoname);
        }
    }
}


static void SetBarnyard2ConfDir(void)
{
    /* extract the config directory from the config filename */
    if (barnyard2_conf_file != NULL)
    {
#ifndef WIN32
        char *path_sep = strrchr(barnyard2_conf_file, '/');
#else
        char *path_sep = strrchr(barnyard2_conf_file, '\\');
#endif

        /* is there a directory seperator in the filename */
        if (path_sep != NULL)
        {
            path_sep++;  /* include path separator */
            barnyard2_conf_dir = SnortStrndup(barnyard2_conf_file, path_sep - barnyard2_conf_file);
        }
        else
        {
            barnyard2_conf_dir = SnortStrdup("./");
        }

        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Config file = %s, config dir = "
                    "%s\n", barnyard2_conf_file, barnyard2_conf_dir););
    }
}

static void FreePlugins(Barnyard2Config *bc)
{
    if (bc == NULL)
        return;
    
    FreePluginSigFuncs(bc->plugin_post_config_funcs);
    bc->plugin_post_config_funcs = NULL;
}

static Barnyard2Config * MergeBarnyard2Confs(Barnyard2Config *cmd_line, Barnyard2Config *config_file)
{
    /* Move everything from the command line config over to the
     * config_file config */

    if (cmd_line == NULL)
    {
        FatalError("%s(%d) Merging barnyard2 configs: barnyard2 conf is NULL.\n",
                   __FILE__, __LINE__);
    }
   
    ResolveOutputPlugins(cmd_line, config_file);

    if (config_file == NULL)
    {
        if (cmd_line->log_dir == NULL)
            cmd_line->log_dir = SnortStrdup(DEFAULT_LOG_DIR);
    }
    else if ((cmd_line->log_dir == NULL) && (config_file->log_dir == NULL))
    {
        config_file->log_dir = SnortStrdup(DEFAULT_LOG_DIR);
    }
    else if (cmd_line->log_dir != NULL)
    {
        if (config_file->log_dir != NULL)
            free(config_file->log_dir);

        config_file->log_dir = SnortStrdup(cmd_line->log_dir);
    }
    
    if (config_file == NULL)
        return cmd_line;

    if(cmd_line->ssHead)
    {
	config_file->ssHead = cmd_line->ssHead;
	cmd_line->ssHead = NULL;
    }
    
    if( (cmd_line->sid_msg_file) &&
	(config_file->sid_msg_file))
    {
	FatalError("The sid map file was included two times command line (-S) [%s] and in the configuration file (config sid_map) [%s].\n"
		   "It only need to be defined once.\n",
		   cmd_line->sid_msg_file,
		   config_file->sid_msg_file);
    }    

    if( (cmd_line->gen_msg_file) &&
	(config_file->gen_msg_file))
    {
	FatalError("The gen map file was included two times command line (-G) [%s] and in the configuration file (config gen_map) [%s].\n"
		   "It only need to be defined once.\n",
		   cmd_line->gen_msg_file,
		   config_file->gen_msg_file);
    }

    if( (cmd_line->sid_msg_file != NULL) &&
	(config_file->sid_msg_file == NULL))
    {
	config_file->sid_msg_file = cmd_line->sid_msg_file;
	cmd_line->sid_msg_file = NULL;
    }
    
    if( (cmd_line->gen_msg_file != NULL) &&
        (config_file->gen_msg_file == NULL))
    {
        config_file->gen_msg_file = cmd_line->gen_msg_file;
        cmd_line->gen_msg_file = NULL;
    }


    if( cmd_line->event_cache_size > config_file->event_cache_size)
    {
	config_file->event_cache_size = cmd_line->event_cache_size;
    }
    
    /* In case */
    if(cmd_line->sidmap_version > config_file->sidmap_version)
    {
	config_file->sidmap_version = cmd_line->sidmap_version;
    }

    
    /* Used because of a potential chroot */
    config_file->orig_log_dir = SnortStrdup(config_file->log_dir);

    config_file->run_mode = cmd_line->run_mode;
    config_file->run_mode_flags |= cmd_line->run_mode_flags;

    if ((cmd_line->run_mode == RUN_MODE__TEST) &&
        (config_file->run_flags & RUN_FLAG__DAEMON))
    {
        /* Just ignore deamon setting in conf file */
        config_file->run_flags &= ~RUN_FLAG__DAEMON;
    }

    config_file->run_flags |= cmd_line->run_flags;

    config_file->output_flags |= cmd_line->output_flags;

    config_file->logging_flags |= cmd_line->logging_flags;

    if (cmd_line->pid_path[0] != '\0')
        ConfigPidPath(config_file, cmd_line->pid_path);
    
    if( (config_file->alert_on_each_packet_in_stream_flag == 0) &&
	(cmd_line->alert_on_each_packet_in_stream_flag == 1))
    {
	config_file->alert_on_each_packet_in_stream_flag = 0;
    }
    else
    {
	config_file->alert_on_each_packet_in_stream_flag  = cmd_line->alert_on_each_packet_in_stream_flag;
    }
    
    config_file->process_new_records_only_flag = cmd_line->process_new_records_only_flag;

#ifdef SUP_IP6
    if (cmd_line->obfuscation_net.family != 0)
        memcpy(&config_file->obfuscation_net, &cmd_line->obfuscation_net, sizeof(sfip_t));

    if (cmd_line->homenet.family != 0)
        memcpy(&config_file->homenet, &cmd_line->homenet, sizeof(sfip_t));
#else
    if (cmd_line->obfuscation_mask != 0)
    {
        config_file->obfuscation_mask = cmd_line->obfuscation_mask;
        config_file->obfuscation_net = cmd_line->obfuscation_net;
    }

    if (cmd_line->netmask != 0)
    {
        config_file->netmask = cmd_line->netmask;
        config_file->homenet = cmd_line->homenet;
    }
#endif

    if (cmd_line->hostname != NULL)
    {
        if (config_file->hostname != NULL)
            free(config_file->hostname);
        config_file->hostname = SnortStrdup(cmd_line->hostname);
    }

    if (cmd_line->interface != NULL)
    {
        if (config_file->interface != NULL)
            free(config_file->interface);
        config_file->interface = SnortStrdup(cmd_line->interface);
    }

    if (cmd_line->bpf_filter != NULL)
        config_file->bpf_filter = SnortStrdup(cmd_line->bpf_filter);

    if (cmd_line->group_id != -1)
        config_file->group_id = cmd_line->group_id;

    if (cmd_line->user_id != -1)
        config_file->user_id = cmd_line->user_id;

    if (cmd_line->archive_dir != NULL)
    {
        if (config_file->archive_dir != NULL)
            free(config_file->archive_dir);

        config_file->archive_dir = SnortStrdup(cmd_line->archive_dir);
    }

    /* Only configurable on command line */
    if (cmd_line->file_mask != 0)
        config_file->file_mask = cmd_line->file_mask;

    if (cmd_line->pidfile_suffix[0] != '\0')
    {
        SnortStrncpy(config_file->pidfile_suffix, cmd_line->pidfile_suffix,
                     sizeof(config_file->pidfile_suffix));
    }

    if (cmd_line->chroot_dir != NULL)
    {
        if (config_file->chroot_dir != NULL)
            free(config_file->chroot_dir);
        config_file->chroot_dir = SnortStrdup(cmd_line->chroot_dir);
    }

    /* waldo file components */
    if (cmd_line->waldo.data.spool_filebase[0] != '\0')
    {
        ConfigSpoolFilebase(config_file, cmd_line->waldo.data.spool_filebase);
    }

    if (cmd_line->waldo.data.spool_dir[0] != '\0')
    {
        ConfigSpoolDirectory(config_file, cmd_line->waldo.data.spool_dir);
    }

    if (cmd_line->waldo.filepath[0] != '\0')
    {
        ConfigWaldoFile(config_file, cmd_line->waldo.filepath);
    }

    /* batch list */
    if (cmd_line->batch_total_files > 0 )
    {
        config_file->batch_total_files = cmd_line->batch_total_files;
        config_file->batch_filelist = cmd_line->batch_filelist;
        cmd_line->batch_filelist = NULL;
        cmd_line->batch_total_files = 0;
    }

    return config_file;
}

void FreeVarList(VarNode *head)
{
    while (head != NULL)
    {
        VarNode *tmp = head;
        
        head = head->next;

        if (tmp->name != NULL)
            free(tmp->name);

        if (tmp->value != NULL)
            free(tmp->value);

        if (tmp->line != NULL)
            free(tmp->line);

        free(tmp);
    }
}

static void Barnyard2Init(int argc, char **argv)
{
    InitGlobals();

    /* chew up the command line */
    ParseCmdLine(argc, argv);

    switch (barnyard2_conf->run_mode)
    {
        case RUN_MODE__VERSION:
            break;

        case RUN_MODE__CONTINUOUS:
            LogMessage("Running in Continuous mode\n");
            break;

        case RUN_MODE__BATCH:
            LogMessage("Running in Batch mode\n");
            break;

        case RUN_MODE__TEST:
            LogMessage("Running in Test mode\n");
            break;

        default:
            break;
    }

    LogMessage("\n");
    LogMessage("        --== Initializing Barnyard2 ==--\n");

    if (!BcVersionMode())
    {
        /* Every run mode except version will potentially need output
         * If output plugins should become dynamic, this needs to move */
        RegisterInputPlugins();
        RegisterOutputPlugins();
    }

    /* if we're using the rules system, it gets initialized here */
    if (barnyard2_conf_file != NULL)
    {
        Barnyard2Config *bc;

        /* initialize all the plugin modules */
//        RegisterPreprocessors();

#ifdef DEBUG
//        DumpPreprocessors();
#endif

        LogMessage("Parsing config file \"%s\"\n", barnyard2_conf_file);
        bc = ParseBarnyard2Conf();

        bc->config_dir = strdup(barnyard2_conf_dir);
        bc->config_file = strdup(barnyard2_conf_file);

        /* Merge the command line and config file confs to take care of
         * command line overriding config file.
         * Set the global barnyard2_conf that will be used during run time */
        barnyard2_conf = MergeBarnyard2Confs(barnyard2_cmd_line_conf, bc);
	
	DisplaySigSuppress(BCGetSigSuppressHead());

	if(ReadSidFile(barnyard2_conf))
	{
	    FatalError("[%s()], failed while processing [%s] \n",
		       __FUNCTION__,
		       bc->sid_msg_file);
	}
	
	if(ReadGenFile(barnyard2_conf))
	{
	    FatalError("[%s()], failed while processing [%s] \n",
		       __FUNCTION__,
		       bc->gen_msg_file);
	}

	if(barnyard2_conf->event_cache_size == 0)
	{
	    barnyard2_conf->event_cache_size = 2048;
	}
	
	LogMessage("Barnyard2 spooler: Event cache size set to [%u] \n",
		   barnyard2_conf->event_cache_size);
	
    }

    /* Resolve classification integer for signature and free some memory */
    if(barnyard2_conf->sidmap_version == SIDMAPV2)
    {
	if(SignatureResolveClassification(barnyard2_conf->classifications,
					  (SigNode *)*BcGetSigNodeHead(),
					  barnyard2_conf->sid_msg_file,
					  barnyard2_conf->class_file))
	{
	    FatalError("[%s()], Call to SignatureResolveClassification failed \n",
		       __FUNCTION__);
	}
    }

    /* pcap_snaplen is already initialized to SNAPLEN */
    //  if (barnyard2_conf->pkt_snaplen != -1)
    //      pcap_snaplen = (uint32_t)snort_conf->pkt_snaplen;

    /* Display barnyard2 version information here so that we can also show dynamic
     * plugin versions, if loaded.  */
    if (BcVersionMode())
    {
        PrintVersion();
        CleanExit(0);
    }

    /* Validate the log directory for logging packets - probably should
     * add test mode as well, but not expected behavior */
    if ((BcContinuousMode() || BcBatchMode()))    
    {
        CheckLogDir();
        LogMessage("Log directory = %s\n", barnyard2_conf->log_dir);
    }

    if (BcOutputUseUtc())
        barnyard2_conf->thiszone = 0;
    else
        barnyard2_conf->thiszone = gmt2local(0);  /* ripped from tcpdump */

    ConfigureInputPlugins(barnyard2_conf);
    ConfigureOutputPlugins(barnyard2_conf);

    if (BcContinuousMode() || BcBatchMode() || BcTestMode())
    {
        /* Have to split up configuring preprocessors between internal and dynamic
         * because the dpd structure has a pointer to the stream api and stream5
         * needs to be configured first to set this */
//        ConfigurePreprocessors(snort_conf, 0);
    }

    if (barnyard2_conf->file_mask != 0)
        umask(barnyard2_conf->file_mask);
    else
        umask(077);    /* set default to be sane */

}

static void Barnyard2PostInit(void)
{
    InitPidChrootAndPrivs();

#ifdef HAVE_LIBPRELUDE
    AlertPreludeSetupAfterSetuid();
#endif

    PostConfigInitPlugins(barnyard2_conf->plugin_post_config_funcs);

#ifdef DEBUG
        DumpInputPlugins();
        DumpOutputPlugins();
#endif

    LogMessage("\n");
    LogMessage("        --== Initialization Complete ==--\n");

    /* Tell 'em who wrote it, and what "it" is */
    if (!BcLogQuiet())
        PrintVersion();

    if (BcTestMode())
    {
        LogMessage("\n");
        LogMessage("Barnyard2 successfully loaded configuration file!\n");
        CleanExit(0);
    }

    if (BcDaemonMode())
    {
        LogMessage("Barnyard2 initialization completed successfully (pid=%u)\n",getpid());
    }
    
    barnyard2_initializing = 0;
}

#if defined(NOCOREFILE) && !defined(WIN32)
static void SetNoCores(void)
{
    struct rlimit rlim;

    getrlimit(RLIMIT_CORE, &rlim);
    rlim.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rlim);
}
#endif

static void InitSignals(void)
{
#if !defined(WIN32) && !defined(__CYGWIN32__) && !defined(__CYGWIN__) && \
    !defined( __CYGWIN64__)
# if defined(LINUX) || defined(FREEBSD) || defined(OPENBSD) || \
     defined(SOLARIS) || defined(BSD) || defined(MACOS)
    sigset_t set;

    sigemptyset(&set);
#  if defined(HAVE_LIBPRELUDE)
    pthread_sigmask(SIG_SETMASK, &set, NULL);
#  else
    sigprocmask(SIG_SETMASK, &set, NULL);
#  endif /* HAVE_LIBPRELUDE */
# else
    sigsetmask(0);
# endif /* LINUX, BSD, SOLARIS */
#endif  /* !WIN32 */

    /* Make this prog behave nicely when signals come along.
     * Windows doesn't like all of these signals, and will
     * set errno for some.  Ignore/reset this error so it
     * doesn't interfere with later checks of errno value.  */
    signal(SIGTERM, SigExitHandler);
    signal(SIGINT, SigExitHandler);
    signal(SIGQUIT, SigExitHandler);
    signal(SIGUSR1, SigUsrHandler);

#ifdef RB_EXTRADATA /* define an own SigAlrmHandler and discard the previous and unused one */
    signal(SIGALRM, SigAlrmHandler);
#else
    #ifdef TIMESTATS
        /* Establish a handler for SIGALRM signals and set an alarm to go off
         * in approximately one hour.  This is used to drop statistics at
         * an interval which the alarm will tell us to do. */
        signal(SIGALRM, SigAlrmHandler);
    #endif
#endif


    signal(SIGHUP, SigHupHandler);

    errno = 0;
}

static void FreeInputConfigs(InputConfig *head)
{
    while (head != NULL)
    {
        InputConfig *tmp = head;

        head = head->next;

        if (tmp->keyword != NULL)
            free(tmp->keyword);

        if (tmp->opts != NULL)
            free(tmp->opts);

        if (tmp->file_name != NULL)
            free(tmp->file_name);

        free(tmp);
    }
}

static void FreeOutputConfigs(OutputConfig *head)
{
    while (head != NULL)
    {
        OutputConfig *tmp = head;

        head = head->next;

        if (tmp->keyword != NULL)
            free(tmp->keyword);

        if (tmp->opts != NULL)
            free(tmp->opts);

        if (tmp->file_name != NULL)
            free(tmp->file_name);

        free(tmp);
    }
}

