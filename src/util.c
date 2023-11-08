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


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <dirent.h>
#include <fnmatch.h>
#endif /* !WIN32 */

#include <stdarg.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>

#ifndef WIN32
#include <grp.h>
#include <pwd.h>
#include <netdb.h>
#include <limits.h>
#endif /* !WIN32 */

#include <fcntl.h>

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "barnyard2.h"
#include "mstring.h"
#include "debug.h"
#include "util.h"
#include "parser.h"
#include "plugbase.h"
#include "sf_types.h"

#ifdef PATH_MAX
#define PATH_MAX_UTIL PATH_MAX
#else
#define PATH_MAX_UTIL 1024
#endif /* PATH_MAX */

extern Barnyard2Config *barnyard2_conf;
extern int exit_signal;

/*
 * you may need to adjust this on the systems which don't have standard
 * paths defined
 */
#ifndef _PATH_VARRUN
static char _PATH_VARRUN[STD_BUF];
#endif


#ifdef NAME_MAX
#define NAME_MAX_UTIL NAME_MAX
#else
#define NAME_MAX_UTIL 256
#endif /* NAME_MAX */

#define FILE_MAX_UTIL  (PATH_MAX_UTIL + NAME_MAX_UTIL)



/****************************************************************************
 *
 * Function: CalcPct(uint64_t, uint64_t)
 *
 * Purpose:  Calculate the percentage of a value compared to a total
 *
 * Arguments: cnt => the numerator in the equation
 *            total => the denominator in the calculation
 *
 * Returns: pct -> the percentage of cnt to value
 *
 ****************************************************************************/
double CalcPct(uint64_t cnt, uint64_t total)
{
    double pct = 0.0;

    if (total == 0.0)
    {
        pct = (double)cnt;
    }
    else
    {
        pct = (double)cnt / (double)total;
    }

    pct *= 100.0;

    return pct;
}


/****************************************************************************
 *
 * Function: DisplayBanner()
 *
 * Purpose:  Show valuable proggie info
 *
 * Arguments: None.
 *
 * Returns: 0 all the time
 *
 ****************************************************************************/
int DisplayBanner(void)
{
    fprintf(stderr, "\n"
        "  ______   -*> Barnyard2 <*-\n"
        " / ,,_  \\  Version %s.%s.%s (Build %s)%s%s\n"
        " |o\"  )~|  By Ian Firns (SecurixLive): http://www.securixlive.com/\n"
		" + '''' +  (C) Copyright 2008-2013 Ian Firns <firnsy@securixlive.com>\n"
        "\n"
        , VER_MAJOR, VER_MINOR, VER_REVISION, VER_BUILD,
#ifdef DEBUG
		" DEBUG",
#else
		"",
#endif
#ifdef SUP_IP6
		" IPv6"
#else
		""
#endif
#ifdef ENABLE_TCL
		" TCL"
#else
		""
#endif
); 
    return 0;
}



/****************************************************************************
 *
 * Function: ts_print(register const struct, char *)
 *
 * Purpose: Generate a time stamp and stuff it in a buffer.  This one has
 *          millisecond precision.  Oh yeah, I ripped this code off from
 *          TCPdump, props to those guys.
 *
 * Arguments: timeval => clock struct coming out of libpcap
 *            timebuf => buffer to stuff timestamp into
 *
 * Returns: void function
 *
 ****************************************************************************/
void ts_print(register const struct timeval *tvp, char *timebuf)
{
    register int s;
    int    localzone;
    time_t Time;
    struct timeval tv;
    struct timezone tz;
    struct tm *lt;    /* place to stick the adjusted clock data */

    /* if null was passed, we use current time */
    if(!tvp)
    {
        /* manual page (for linux) says tz is never used, so.. */
	memset((char *) &tz, 0, sizeof(tz)); /* bzero() deprecated, replaced by memset() */
        gettimeofday(&tv, &tz);
        tvp = &tv;
    }

    localzone = barnyard2_conf->thiszone;
   
    /*
    **  If we're doing UTC, then make sure that the timezone is correct.
    */
    if(BcOutputUseUtc())
        localzone = 0;
        
    s = (tvp->tv_sec + localzone) % 86400;
    Time = (tvp->tv_sec + localzone) - s;

    lt = gmtime(&Time);

    if(BcOutputIncludeYear())
    {
        (void) SnortSnprintf(timebuf, TIMEBUF_SIZE, 
                        "%02d/%02d/%02d-%02d:%02d:%02d.%06u ", 
                        lt->tm_mon + 1, lt->tm_mday, lt->tm_year - 100, 
                        s / 3600, (s % 3600) / 60, s % 60, 
                        (u_int) tvp->tv_usec);
    } 
    else 
    {
        (void) SnortSnprintf(timebuf, TIMEBUF_SIZE,
                        "%02d/%02d-%02d:%02d:%02d.%06u ", lt->tm_mon + 1,
                        lt->tm_mday, s / 3600, (s % 3600) / 60, s % 60,
                        (u_int) tvp->tv_usec);
    }
}

/****************************************************************************
 *
 * Function: ts_print2(uint32_t, uint32_t, char *)
 *
 * Purpose: Generate a time stamp and stuff it in a buffer.  This one has
 *          millisecond precision. Oh yeah, I ripped this code off from
 *          TCPdump, props to those guys.
 *
 * Arguments: timeval => clock struct coming out of libpcap
 *            timebuf => buffer to stuff timestamp into
 *
 * Returns: void function
 *
 ****************************************************************************/
void ts_print2(uint32_t sec, uint32_t usec, char *timebuf)
{
    register int s;
    int    localzone;
    time_t Time;
    struct tm *lt;    /* place to stick the adjusted clock data */

    localzone = barnyard2_conf->thiszone;
   
    /*
    **  If we're doing UTC, then make sure that the timezone is correct.
    */
    if(BcOutputUseUtc())
        localzone = 0;
        
    s = (sec + localzone) % 86400;
    Time = (sec + localzone) - s;

    lt = gmtime(&Time);

    if(BcOutputIncludeYear())
    {
        (void) SnortSnprintf(timebuf, TIMEBUF_SIZE, 
                        "%02d/%02d/%02d-%02d:%02d:%02d.%06u ", 
                        lt->tm_mon + 1, lt->tm_mday, lt->tm_year - 100, 
                        s / 3600, (s % 3600) / 60, s % 60, 
                        (u_int) usec);
    } 
    else 
    {
        (void) SnortSnprintf(timebuf, TIMEBUF_SIZE,
                        "%02d/%02d-%02d:%02d:%02d.%06u ", lt->tm_mon + 1,
                        lt->tm_mday, s / 3600, (s % 3600) / 60, s % 60,
                        (u_int) usec);
    }
}

/****************************************************************************
 *
 * Function: gmt2local(time_t)
 *
 * Purpose: Figures out how to adjust the current clock reading based on the
 *          timezone you're in.  Ripped off from TCPdump.
 *
 * Arguments: time_t => offset from GMT
 *
 * Returns: offset seconds from GMT
 *
 ****************************************************************************/
int gmt2local(time_t t)
{
    register int dt, dir;
    register struct tm *gmt, *loc;
    struct tm sgmt;

    if(t == 0)
        t = time(NULL);

    gmt = &sgmt;
    *gmt = *gmtime(&t);
    loc = localtime(&t);

    dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
        (loc->tm_min - gmt->tm_min) * 60;

    dir = loc->tm_year - gmt->tm_year;

    if(dir == 0)
        dir = loc->tm_yday - gmt->tm_yday;

    dt += dir * 24 * 60 * 60;

    return(dt);
}




/****************************************************************************
 *
 * Function: copy_argv(u_char **)
 *
 * Purpose: Copies a 2D array (like argv) into a flat string.  Stolen from
 *          TCPDump.
 *
 * Arguments: argv => 2D array to flatten
 *
 * Returns: Pointer to the flat string
 *
 ****************************************************************************/
char *copy_argv(char **argv)
{
    char **p;
    u_int len = 0;
    char *buf;
    char *src, *dst;
    //void ftlerr(char *,...);

    p = argv;
    if(*p == 0)
        return 0;

    while(*p)
        len += strlen(*p++) + 1;

    buf = (char *) calloc(1,len);

    if(buf == NULL)
    {
        FatalError("calloc() failed: %s\n", strerror(errno));
    }
    p = argv;
    dst = buf;

    while((src = *p++) != NULL)
    {
        while((*dst++ = *src++) != '\0');
        dst[-1] = ' ';
    }

    dst[-1] = '\0';

    /* Check for an empty string */
    dst = buf;
    while (isspace((int)*dst))
        dst++;

    if (strlen(dst) == 0)
    {
        free(buf);
        buf = NULL;
    }

    return buf;
}

void strtrim(char *str)
{
    char *end;

     // trim leading space
     while(isspace(*str)) str++;
    
     if(*str == 0)  // All spaces?
         return;
      
     // trim trailing space
     end = str + strlen(str) - 1;
     while(end > str && isspace(*end)) end--;
     
     // write new null terminator
     *(end+1) = 0;
}

/****************************************************************************
 *
 * Function: strip(char *)
 *
 * Purpose: Strips a data buffer of CR/LF/TABs.  Replaces CR/LF's with
 *          NULL and TABs with spaces.
 *
 * Arguments: data => ptr to the data buf to be stripped
 *
 * Returns: void
 *
 * 3/7/07 - changed to return void - use strlen to get size of string
 *
 * Note that this function will turn all '\n' and '\r' into null chars
 * so, e.g. 'Hello\nWorld\n' => 'Hello\x00World\x00'
 * note that the string is now just 'Hello' and the length is shortened
 * by more than just an ending '\n' or '\r'
 ****************************************************************************/
void strip(char *data)
{
    int size;
    char *end;
    char *idx;

    idx = data;
    end = data + strlen(data);
    size = end - idx;

    while(idx != end)
    {
        if((*idx == '\n') ||
                (*idx == '\r'))
        {
            *idx = 0;
            size--;
        }
        if(*idx == '\t')
        {
            *idx = ' ';
        }
        idx++;
    }
}

/*
 * Function: ErrorMessage(const char *, ...)
 *
 * Purpose: Print a message to stderr.
 *
 * Arguments: format => the formatted error string to print out
 *            ... => format commands/fillers
 *
 * Returns: void function
 */
void ErrorMessage(const char *format,...)
{
    char buf[STD_BUF+1];
    va_list ap;

    if (barnyard2_conf == NULL)
        return;

    va_start(ap, format);

    if(BcDaemonMode() || BcLogSyslog())
    {
        vsnprintf(buf, STD_BUF, format, ap);
        buf[STD_BUF] = '\0';
        syslog(LOG_CONS | LOG_DAEMON | LOG_ERR, "%s", buf);
    }
    else
    {
        vfprintf(stderr, format, ap);
    }
    va_end(ap);
}

/*
 * Function: LogMessage(const char *, ...)
 *
 * Purpose: Print a message to stdout or with logfacility.
 *
 * Arguments: format => the formatted error string to print out
 *            ... => format commands/fillers
 *
 * Returns: void function
 */
void LogMessage(const char *format,...)
{
    char buf[STD_BUF+1];
    va_list ap;

    if (barnyard2_conf == NULL)
        return;

    if (BcLogQuiet() && !BcDaemonMode() && !BcLogSyslog())
        return;

    va_start(ap, format);

    if(BcDaemonMode() || BcLogSyslog())
    {
        vsnprintf(buf, STD_BUF, format, ap);
        buf[STD_BUF] = '\0';
        syslog(LOG_DAEMON | LOG_NOTICE, "%s", buf);
    }
    else
    {
        vfprintf(stderr, format, ap);
    }

    va_end(ap);
}


/*
 * Function: CreateApplicationEventLogEntry(const char *)
 *
 * Purpose: Add an entry to the Win32 "Application" EventLog
 *
 * Arguments: szMessage => the formatted error string to print out
 *
 * Returns: void function
 */
#if defined(WIN32) && defined(ENABLE_WIN32_SERVICE)
void CreateApplicationEventLogEntry(const char *msg)
{
    HANDLE hEventLog; 
    char*  pEventSourceName = "SnortService";

    /* prepare to write to Application log on local host
      * with Event Source of SnortService
      */
    AddEventSource(pEventSourceName);
    hEventLog = RegisterEventSource(NULL, pEventSourceName);
    if (hEventLog == NULL)
    {
        /* Could not register the event source. */
        return;
    }
 
    if (!ReportEvent(hEventLog,   /* event log handle               */
            EVENTLOG_ERROR_TYPE,  /* event type                     */
            0,                    /* category zero                  */
            EVMSG_SIMPLE,         /* event identifier               */
            NULL,                 /* no user security identifier    */
            1,                    /* one substitution string        */
            0,                    /* no data                        */
            &msg,                 /* pointer to array of strings    */
            NULL))                /* pointer to data                */
    {
        /* Could not report the event. */
    }
 
    DeregisterEventSource(hEventLog); 
} 
#endif  /* WIN32 && ENABLE_WIN32_SERVICE */


/*
 * Function: FatalError(const char *, ...)
 *
 * Purpose: When a fatal error occurs, this function prints the error message
 *          and cleanly shuts down the program
 *
 * Arguments: format => the formatted error string to print out
 *            ... => format commands/fillers
 *
 * Returns: void function
 */
NORETURN void FatalError(const char *format,...)
{
    char buf[STD_BUF+1];
    va_list ap;

    va_start(ap, format);
    vsnprintf(buf, STD_BUF, format, ap);
    va_end(ap);

    buf[STD_BUF] = '\0';

    if ((barnyard2_conf != NULL) && (BcDaemonMode() || BcLogSyslog()))
    {
        syslog(LOG_CONS | LOG_DAEMON | LOG_ERR, "FATAL ERROR: %s", buf);
    }
    else
    {
        fprintf(stderr, "ERROR: %s", buf);
        fprintf(stderr,"Fatal Error, Quitting..\n");
#if defined(WIN32) && defined(ENABLE_WIN32_SERVICE)
        CreateApplicationEventLogEntry(buf);
#endif
    }

    CleanExit(1);
    
}


/****************************************************************************
 *
 * Function: CreatePidFile(char *)
 *
 * Purpose:  Creates a PID file
 *
 * Arguments: Interface opened.
 *
 * Returns: void function
 *
 ****************************************************************************/
static FILE *pid_lockfile = NULL;
static FILE *pid_file = NULL;
void CreatePidFile(char *intf)
{
    struct stat pt;
    int pid = (int) getpid();
#ifdef WIN32
    char dir[STD_BUF + 1];
#endif

    if (1)	// TODO: Read mode flag 
    {
        if(!BcLogQuiet())
        {
            LogMessage("Checking PID path...\n");
        }

        if (strlen(barnyard2_conf->pid_path) != 0)
        {
            if((stat(barnyard2_conf->pid_path, &pt) == -1) ||
                !S_ISDIR(pt.st_mode) || access(barnyard2_conf->pid_path, W_OK) == -1)
            {
#ifndef WIN32
                /* Save this just in case it's reset with LogMessage call */
				int err = errno;
				
				LogMessage("WARNING: %s is invalid, trying "
                           "/var/run...\n", barnyard2_conf->pid_path);
                if (err)
                {
                    LogMessage("Previous Error, errno=%d, (%s)\n",
                               err, strerror(err) == NULL ? "Unknown error" : strerror(err));
                }
#endif
                memset(barnyard2_conf->pid_path, '\0', sizeof(barnyard2_conf->pid_path));
            }
            else
            {
                LogMessage("PID path stat checked out ok, "
                           "PID path set to %s\n", barnyard2_conf->pid_path);
            }
        }

        if (strlen(barnyard2_conf->pid_path) == 0)
        {
#ifndef _PATH_VARRUN
# ifndef WIN32
            SnortStrncpy(_PATH_VARRUN, "/var/run/", sizeof(_PATH_VARRUN));
# else
            if (GetCurrentDirectory(sizeof(dir) - 1, dir))
                SnortStrncpy(_PATH_VARRUN, dir, sizeof(_PATH_VARRUN));
# endif  /* WIN32 */
#else
            LogMessage("PATH_VARRUN is set to %s on this operating "
                       "system\n", _PATH_VARRUN);
#endif  /* _PATH_VARRUN */

            stat(_PATH_VARRUN, &pt);

            if(!S_ISDIR(pt.st_mode) || access(_PATH_VARRUN, W_OK) == -1)
            {
                LogMessage("WARNING: _PATH_VARRUN is invalid, trying "
                           "/var/log...\n");
                SnortStrncpy(barnyard2_conf->pid_path, "/var/log/", sizeof(barnyard2_conf->pid_path));
                stat(barnyard2_conf->pid_path, &pt);

                if(!S_ISDIR(pt.st_mode) || access(barnyard2_conf->pid_path, W_OK) == -1)
                {
                    LogMessage("WARNING: %s is invalid, logging Snort "
                               "PID path to log directory (%s)\n", barnyard2_conf->pid_path,
                               barnyard2_conf->log_dir);
                    CheckLogDir();
                    SnortSnprintf(barnyard2_conf->pid_path, sizeof(barnyard2_conf->pid_path),
                                  "%s/", barnyard2_conf->log_dir);
                }
            }
            else
            {
                LogMessage("PID path stat checked out ok, "
                           "PID path set to %s\n", _PATH_VARRUN);
                SnortStrncpy(barnyard2_conf->pid_path, _PATH_VARRUN, sizeof(barnyard2_conf->pid_path));
            }
        }
    }

    if(intf == NULL || strlen(barnyard2_conf->pid_path) == 0)
    {
        /* barnyard2_conf->pid_path should have some value by now
         * so let us just be sane.
         */
        FatalError("CreatePidFile() failed to lookup interface or pid_path is unknown!\n");
    }

    SnortSnprintf(barnyard2_conf->pid_filename, sizeof(barnyard2_conf->pid_filename),
				  "%s/barnyard2_%s%s.pid", barnyard2_conf->pid_path, intf, barnyard2_conf->pidfile_suffix);

#ifndef WIN32
    if (!BcNoLockPidFile())
    {
        char pid_lockfilename[STD_BUF+1];
        int lock_fd;

        /* First, lock the PID file */
        SnortSnprintf(pid_lockfilename, STD_BUF, "%s.lck", barnyard2_conf->pid_filename);
        pid_lockfile = fopen(pid_lockfilename, "w");

        if (pid_lockfile)
        {
            struct flock lock;
            lock_fd = fileno(pid_lockfile);

            lock.l_type = F_WRLCK;
            lock.l_whence = SEEK_SET;
            lock.l_start = 0;
            lock.l_len = 0;

            if (fcntl(lock_fd, F_SETLK, &lock) == -1)
            {
                ClosePidFile();
                FatalError("Failed to Lock PID File \"%s\" for PID \"%d\"\n", barnyard2_conf->pid_filename, pid);
            }
        }
    }
#endif

    /* Okay, were able to lock PID file, now open and write PID */
    pid_file = fopen(barnyard2_conf->pid_filename, "w");
    if(pid_file)
    {
        LogMessage("Writing PID \"%d\" to file \"%s\"\n", pid, barnyard2_conf->pid_filename);
        fprintf(pid_file, "%d\n", pid);
        fflush(pid_file);
    }
    else
    {
        ErrorMessage("Failed to create pid file %s", barnyard2_conf->pid_filename);
        barnyard2_conf->pid_filename[0] = 0;
    }
}

/****************************************************************************
 *
 * Function: ClosePidFile(char *)
 *
 * Purpose:  Releases lock on a PID file
 *
 * Arguments: None
 *
 * Returns: void function
 *
 ****************************************************************************/
void ClosePidFile(void)
{
    if (pid_file)
    {
        fclose(pid_file);
        pid_file = NULL;
    }
    if (pid_lockfile)
    {
        fclose(pid_lockfile);
        pid_lockfile = NULL;
    }
}

/****************************************************************************
 *
 * Function: SetUidGid()
 *
 * Purpose:  Sets safe UserID and GroupID if needed
 *
 * Arguments: none
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetUidGid(int user_id, int group_id)
{
#ifndef WIN32

    if ((group_id != -1) && (getgid() != (gid_t)group_id))
    {
        if (setgid(group_id) < 0)
            FatalError("Cannot set gid: %d\n", group_id);

        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Set gid to %d\n", group_id););
    }

    if ((user_id != -1) && (getuid() != (uid_t)user_id))
    {
        struct passwd *pw = getpwuid(user_id);

        if (pw != NULL)
        {
            /* getpwuid and initgroups may use the same static buffers */
            char *username = SnortStrdup(pw->pw_name);

            if ((getuid() == 0) && (initgroups(username, group_id) < 0))
            {
                free(username);
                FatalError("Can not initgroups(%s,%d)",
                           username, group_id);
            }

            free(username);
        }

        /** just to be on a safe side... **/
        endgrent();
        endpwent();

        if (setuid(user_id) < 0)
            FatalError("Can not set uid: %d\n", user_id);

        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Set uid to %d\n", user_id););
    }
#endif  /* WIN32 */
}

/* exiting should be 0 for if not exiting and 1 if exiting */
void DropStats(int exiting)
{
    uint64_t total = 0;

    LogMessage("================================================"
               "===============================\n");

    LogMessage("Record Totals:\n");
    LogMessage("   Records:"     FMTu64("12") "\n", pc.total_records);
    LogMessage("   Events:"      FMTu64("13") " (%.3f%%)\n", pc.total_events,
               CalcPct(pc.total_events, pc.total_records));
    LogMessage("   Packets:"     FMTu64("12") " (%.3f%%)\n", pc.total_packets,
               CalcPct(pc.total_packets, pc.total_records));
#ifdef RB_EXTRADATA
    LogMessage("   Extra Data:"  FMTu64("9") " (%.3f%%)\n", pc.total_extra_data,
               CalcPct(pc.total_extra_data, pc.total_records));
#endif
    LogMessage("   Unknown:"     FMTu64("12") " (%.3f%%)\n", pc.total_unknown,
               CalcPct(pc.total_unknown, pc.total_records));
    LogMessage("   Suppressed:"  FMTu64("9") " (%.3f%%)\n", pc.total_suppressed,
               CalcPct(pc.total_suppressed, pc.total_records));

    total = pc.total_packets;

    LogMessage("================================================"
               "===============================\n");

    LogMessage("Packet breakdown by protocol (includes rebuilt packets):\n");

    LogMessage("      ETH: " FMTu64("-10") " (%.3f%%)\n", 
               pc.eth, CalcPct(pc.eth, total));
    LogMessage("  ETHdisc: " FMTu64("-10") " (%.3f%%)\n", 
               pc.ethdisc, CalcPct(pc.ethdisc, total));
#ifdef GIDS
#ifndef IPFW
    LogMessage(" IPTables: " FMTu64("-10") " (%.3f%%)\n", 
               pc.iptables, CalcPct(pc.iptables, total));
#else
    LogMessage("     IPFW: " FMTu64("-10") " (%.3f%%)\n", 
               pc.ipfw, CalcPct(pc.ipfw, total));
#endif  /* IPFW */
#endif  /* GIDS */
    LogMessage("     VLAN: " FMTu64("-10") " (%.3f%%)\n", 
               pc.vlan, CalcPct(pc.vlan, total));

    if (pc.nested_vlan != 0)
    LogMessage("Nested VLAN: " FMTu64("-10") " (%.3f%%)\n", 
               pc.nested_vlan, CalcPct(pc.nested_vlan, total));

    LogMessage("     IPV6: " FMTu64("-10") " (%.3f%%)\n", 
               pc.ipv6, CalcPct(pc.ipv6, total));
    LogMessage("  IP6 EXT: " FMTu64("-10") " (%.3f%%)\n", 
               pc.ip6ext, CalcPct(pc.ip6ext, total));
    LogMessage("  IP6opts: " FMTu64("-10") " (%.3f%%)\n", 
               pc.ipv6opts, CalcPct(pc.ipv6opts, total));
    LogMessage("  IP6disc: " FMTu64("-10") " (%.3f%%)\n", 
               pc.ipv6disc, CalcPct(pc.ipv6disc, total));

    LogMessage("      IP4: " FMTu64("-10") " (%.3f%%)\n", 
               pc.ip, CalcPct(pc.ip, total));
    LogMessage("  IP4disc: " FMTu64("-10") " (%.3f%%)\n", 
               pc.ipdisc, CalcPct(pc.ipdisc, total));

    LogMessage("    TCP 6: " FMTu64("-10") " (%.3f%%)\n", 
               pc.tcp6, CalcPct(pc.tcp6, total));
    LogMessage("    UDP 6: " FMTu64("-10") " (%.3f%%)\n", 
               pc.udp6, CalcPct(pc.udp6, total));
    LogMessage("    ICMP6: " FMTu64("-10") " (%.3f%%)\n", 
               pc.icmp6, CalcPct(pc.icmp6, total));
    LogMessage("  ICMP-IP: " FMTu64("-10") " (%.3f%%)\n", 
               pc.embdip, CalcPct(pc.embdip, total));

    LogMessage("      TCP: " FMTu64("-10") " (%.3f%%)\n", 
               pc.tcp, CalcPct(pc.tcp, total));
    LogMessage("      UDP: " FMTu64("-10") " (%.3f%%)\n", 
               pc.udp, CalcPct(pc.udp, total));
    LogMessage("     ICMP: " FMTu64("-10") " (%.3f%%)\n", 
               pc.icmp, CalcPct(pc.icmp, total));

    LogMessage("  TCPdisc: " FMTu64("-10") " (%.3f%%)\n", 
               pc.tdisc, CalcPct(pc.tdisc, total));
    LogMessage("  UDPdisc: " FMTu64("-10") " (%.3f%%)\n", 
               pc.udisc, CalcPct(pc.udisc, total));
    LogMessage("  ICMPdis: " FMTu64("-10") " (%.3f%%)\n", 
               pc.icmpdisc, CalcPct(pc.icmpdisc, total));

    LogMessage("     FRAG: " FMTu64("-10") " (%.3f%%)\n", 
               pc.frags, CalcPct(pc.frags, total));
    LogMessage("   FRAG 6: " FMTu64("-10") " (%.3f%%)\n", 
               pc.frag6, CalcPct(pc.frag6, total));

    LogMessage("      ARP: " FMTu64("-10") " (%.3f%%)\n", 
               pc.arp, CalcPct(pc.arp, total));
#ifndef NO_NON_ETHER_DECODER
    LogMessage("    EAPOL: " FMTu64("-10") " (%.3f%%)\n", 
               pc.eapol, CalcPct(pc.eapol, total));
#endif
    LogMessage("  ETHLOOP: " FMTu64("-10") " (%.3f%%)\n", 
               pc.ethloopback, CalcPct(pc.ethloopback, total));
    LogMessage("      IPX: " FMTu64("-10") " (%.3f%%)\n", 
               pc.ipx, CalcPct(pc.ipx, total));
#ifdef GRE
    LogMessage("IPv4/IPv4: " FMTu64("-10") " (%.3f%%)\n", 
               pc.ip4ip4, CalcPct(pc.ip4ip4, total));
    LogMessage("IPv4/IPv6: " FMTu64("-10") " (%.3f%%)\n", 
               pc.ip4ip6, CalcPct(pc.ip4ip6, total));
    LogMessage("IPv6/IPv4: " FMTu64("-10") " (%.3f%%)\n", 
               pc.ip6ip4, CalcPct(pc.ip6ip4, total));
    LogMessage("IPv6/IPv6: " FMTu64("-10") " (%.3f%%)\n", 
               pc.ip6ip6, CalcPct(pc.ip6ip6, total));
    LogMessage("      GRE: " FMTu64("-10") " (%.3f%%)\n", 
               pc.gre, CalcPct(pc.gre, total));
    LogMessage("  GRE ETH: " FMTu64("-10") " (%.3f%%)\n", 
               pc.gre_eth, CalcPct(pc.gre_eth, total));
    LogMessage(" GRE VLAN: " FMTu64("-10") " (%.3f%%)\n", 
               pc.gre_vlan, CalcPct(pc.gre_vlan, total));
    LogMessage(" GRE IPv4: " FMTu64("-10") " (%.3f%%)\n", 
               pc.gre_ip, CalcPct(pc.gre_ip, total));
    LogMessage(" GRE IPv6: " FMTu64("-10") " (%.3f%%)\n", 
               pc.gre_ipv6, CalcPct(pc.gre_ipv6, total));
    LogMessage("GRE IP6 E: " FMTu64("-10") " (%.3f%%)\n", 
               pc.gre_ipv6ext, CalcPct(pc.gre_ipv6ext, total));
    LogMessage(" GRE PPTP: " FMTu64("-10") " (%.3f%%)\n", 
               pc.gre_ppp, CalcPct(pc.gre_ppp, total));
    LogMessage("  GRE ARP: " FMTu64("-10") " (%.3f%%)\n", 
               pc.gre_arp, CalcPct(pc.gre_arp, total));
    LogMessage("  GRE IPX: " FMTu64("-10") " (%.3f%%)\n", 
               pc.gre_ipx, CalcPct(pc.gre_ipx, total));
    LogMessage(" GRE LOOP: " FMTu64("-10") " (%.3f%%)\n", 
               pc.gre_loopback, CalcPct(pc.gre_loopback, total));
#endif  /* GRE */
#ifdef MPLS
    LogMessage("     MPLS: " FMTu64("-10") " (%.3f%%)\n", 
                   pc.mpls, CalcPct(pc.mpls, total));
#endif
    LogMessage("    OTHER: " FMTu64("-10") " (%.3f%%)\n", 
               pc.other, CalcPct(pc.other, total));
    LogMessage("  DISCARD: " FMTu64("-10") " (%.3f%%)\n", 
               pc.discards, CalcPct(pc.discards, total));
    LogMessage("InvChkSum: " FMTu64("-10") " (%.3f%%)\n", 
               pc.invalid_checksums, CalcPct(pc.invalid_checksums, total));

    LogMessage("   S5 G 1: " FMTu64("-10") " (%.3f%%)\n", 
               pc.s5tcp1, CalcPct(pc.s5tcp1, total));
    LogMessage("   S5 G 2: " FMTu64("-10") " (%.3f%%)\n", 
               pc.s5tcp2, CalcPct(pc.s5tcp2, total));

    LogMessage("    Total: " FMTu64("-10") "\n", total);

#ifndef NO_NON_ETHER_DECODER
#ifdef DLT_IEEE802_11
    if(datalink == DLT_IEEE802_11)
    {
        LogMessage("================================================"
                   "===============================\n");
        LogMessage("Wireless Stats:\n");
        LogMessage("Breakdown by type:\n");
        LogMessage("    Management Packets: " FMTu64("-10") " (%.3f%%)\n", 
                   pc.wifi_mgmt, CalcPct(pc.wifi_mgmt, total));
        LogMessage("    Control Packets:    " FMTu64("-10") " (%.3f%%)\n", 
                   pc.wifi_control, CalcPct(pc.wifi_control, total));
        LogMessage("    Data Packets:       " FMTu64("-10") " (%.3f%%)\n", 
                   pc.wifi_data, CalcPct(pc.wifi_data, total));
    }
#endif  /* DLT_IEEE802_11 */
#endif  // NO_NON_ETHER_DECODER

    LogMessage("=============================================="
               "=================================\n");

    return;
}

/****************************************************************************
 *
 * Function: CleanupProtoNames()
 *
 * Purpose: Frees the protocol names
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void CleanupProtoNames(void)
{
    int i;

    for(i = 0; i < 256; i++)
    {
        if( protocol_names[i] != NULL )
        {
            free( protocol_names[i] );
            protocol_names[i] = NULL;
        }
    }

    if(protocol_names)
    {
	free(protocol_names);
	protocol_names = NULL;
    }

}

 /****************************************************************************
  *
  * Function: CheckLogDir()
  *
  * Purpose: CyberPsychotic sez: basically we only check if logdir exist and
  *          writable, since it might screw the whole thing in the middle. Any
  *          other checks could be performed here as well.
  *
  * Arguments: None.
  *
  * Returns: void function
  *
  ****************************************************************************/
void CheckLogDir(void)
{
    struct stat st;
    
	if (barnyard2_conf->log_dir == NULL)
		return;

    if (stat(barnyard2_conf->log_dir, &st) == -1)
        FatalError("Stat check on log dir (%s) failed: %s.\n", barnyard2_conf->log_dir, strerror(errno));

    if (!S_ISDIR(st.st_mode) || (access(barnyard2_conf->log_dir, W_OK) == -1))
    {
        FatalError("Can not get write access to logging directory \"%s\". "
                   "(directory doesn't exist or permissions are set incorrectly "
                   "or it is not a directory at all)\n",
                   barnyard2_conf->log_dir);
    }
}

/* Signal handler for child process signaling the parent
 * that is is ready */
static int parent_wait = 1;
static void SigChildReadyHandler(int signal)
{
#ifdef DEBUG
    LogMessage("Received Signal from Child\n");
#endif
    parent_wait = 0;
}

/****************************************************************************
 *
 * Function: GoDaemon()
 *
 * Purpose: Puts the program into daemon mode, nice and quiet like....
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void GoDaemon(void)
{
#ifndef WIN32
    int exit_val = 0;
    int ret = 0;
    pid_t fs;
    
    LogMessage("Initializing daemon mode\n");

    if (BcDaemonRestart())
        return;

    /* Don't daemonize if we've already daemonized and
     * received a SIGHUP. */
    if(getppid() != 1)
    {
        /* Register signal handler that parent can trap signal */
        signal(SIGNAL_SNORT_CHILD_READY, SigChildReadyHandler);
        if (errno != 0) errno=0;

        /* now fork the child */
        fs = fork();

        if(fs > 0)
        {
            /* Parent */

            /* Don't exit quite yet.  Wait for the child
             * to signal that is there and created the PID
             * file.
             */
            while (parent_wait)
            {
                /* Continue waiting until receiving signal from child */
                int status;
                if (waitpid(fs, &status, WNOHANG) == fs)
                {
                    /* If the child is gone, parent should go away, too */
                    if (WIFEXITED(status))
                    {
                        LogMessage("Child exited unexpectedly\n");
                        exit_val = -1;
                        break;
                    }

                    if (WIFSIGNALED(status))
                    {
                        LogMessage("Child terminated unexpectedly\n");
                        exit_val = -2;
                        break;
                    }
                }
#ifdef DEBUG
                LogMessage("Parent waiting for child...\n");
#endif

                sleep(1);
            }

            LogMessage("Daemon parent exiting\n");

            exit(exit_val);                /* parent */
        }

        if(fs < 0)
        {
            /* Daemonizing failed... */
            perror("fork");
            exit(1);
        }

        /* Child */
        setsid();
    }

    close(0);
    close(1);
    close(2);

#ifdef DEBUG
    /* redirect stdin/stdout/stderr to a file */
    open("/tmp/barnyard2.debug", O_CREAT | O_RDWR);  /* stdin, fd 0 */

    /* Change ownership to that which we will drop privileges to */
    if ((barnyard2_conf->user_id != -1) || (barnyard2_conf->group_id != -1))
    {
        uid_t user_id = getuid();
        gid_t group_id = getgid();

        if (barnyard2_conf->user_id != -1)
            user_id = barnyard2_conf->user_id;
        if (barnyard2_conf->group_id != -1)
            group_id = barnyard2_conf->group_id;

        chown("/tmp/barnyard2.debug", user_id, group_id);
    }
#else
    /* redirect stdin/stdout/stderr to /dev/null */
    (void)open("/dev/null", O_RDWR);  /* stdin, fd 0 */
#endif

    ret = dup(0);  /* stdout, fd 0 => fd 1 */
    ret = dup(0);  /* stderr, fd 0 => fd 2 */

    SignalWaitingParent();
#endif /* ! WIN32 */
}

/* Signal the parent that child is ready */
void SignalWaitingParent(void)
{
#ifndef WIN32
    pid_t parentpid = getppid();
#ifdef DEBUG
    LogMessage("Signaling parent %d from child %d\n", parentpid, getpid());
#endif

    if (kill(parentpid, SIGNAL_SNORT_CHILD_READY))
    {
        LogMessage("Daemon initialized, failed to signal parent pid: %d, failure: %d, %s\n", parentpid, errno, strerror(errno));
    }
    else
    {
        LogMessage("Daemon initialized, signaled parent pid: %d\n", parentpid);
    }
#endif
}

/* Self preserving memory allocator */
void *SPAlloc(unsigned long size, struct _SPMemControl *spmc)
{
    void *tmp;

    spmc->mem_usage += size;

    if(spmc->mem_usage > spmc->memcap)
    {
        spmc->sp_func(spmc);
    }

    tmp = (void *) calloc(size, sizeof(char));

    if(tmp == NULL)
    {
        FatalError("Unable to allocate memory!  (%lu requested, %lu in use)\n",
                size, spmc->mem_usage);
    }

    return tmp;
}

/* Guaranteed to be '\0' terminated even if truncation occurs.
 *
 * returns  SNORT_SNPRINTF_SUCCESS if successful
 * returns  SNORT_SNPRINTF_TRUNCATION on truncation
 * returns  SNORT_SNPRINTF_ERROR on error
 */
int SnortSnprintf(char *buf, size_t buf_size, const char *format, ...)
{
    va_list ap;
    int ret;

    if (buf == NULL || buf_size <= 0 || format == NULL)
        return SNORT_SNPRINTF_ERROR;

    /* zero first byte in case an error occurs with
     * vsnprintf, so buffer is null terminated with
     * zero length */
    buf[0] = '\0';
    buf[buf_size - 1] = '\0';

    va_start(ap, format);

    ret = vsnprintf(buf, buf_size, format, ap);

    va_end(ap);

    if (ret < 0)
        return SNORT_SNPRINTF_ERROR;

    if (buf[buf_size - 1] != '\0' || (size_t)ret >= buf_size)
    {
        /* result was truncated */
        buf[buf_size - 1] = '\0';
        return SNORT_SNPRINTF_TRUNCATION;
    }

    return SNORT_SNPRINTF_SUCCESS;
}

/* Appends to a given string
 * Guaranteed to be '\0' terminated even if truncation occurs.
 * 
 * returns SNORT_SNPRINTF_SUCCESS if successful
 * returns SNORT_SNPRINTF_TRUNCATION on truncation
 * returns SNORT_SNPRINTF_ERROR on error
 */
int SnortSnprintfAppend(char *buf, size_t buf_size, const char *format, ...)
{
    int str_len;
    int ret;
    va_list ap;

    if (buf == NULL || buf_size <= 0 || format == NULL)
        return SNORT_SNPRINTF_ERROR;

    str_len = SnortStrnlen(buf, buf_size);

    /* since we've already checked buf and buf_size an error
     * indicates no null termination, so just start at
     * beginning of buffer */
    if (str_len == SNORT_STRNLEN_ERROR)
    {
        buf[0] = '\0';
        str_len = 0;
    }

    buf[buf_size - 1] = '\0';

    va_start(ap, format);

    ret = vsnprintf(buf + str_len, buf_size - (size_t)str_len, format, ap);

    va_end(ap);

    if (ret < 0)
        return SNORT_SNPRINTF_ERROR;

    if (buf[buf_size - 1] != '\0' || (size_t)ret >= buf_size)
    {
        /* truncation occured */
        buf[buf_size - 1] = '\0';
        return SNORT_SNPRINTF_TRUNCATION;
    }

    return SNORT_SNPRINTF_SUCCESS;
}

/* Guaranteed to be '\0' terminated even if truncation occurs.
 *
 * Arguments:  dst - the string to contain the copy
 *             src - the string to copy from
 *             dst_size - the size of the destination buffer
 *                        including the null byte.
 *
 * returns SNORT_STRNCPY_SUCCESS if successful
 * returns SNORT_STRNCPY_TRUNCATION on truncation
 * returns SNORT_STRNCPY_ERROR on error
 *
 * Note: Do not set dst[0] = '\0' on error since it's possible that
 * dst and src are the same pointer - it will at least be null
 * terminated in any case
 */
int SnortStrncpy(char *dst, const char *src, size_t dst_size)
{
    char *ret = NULL;

    if (dst == NULL || src == NULL || dst_size <= 0)
        return SNORT_STRNCPY_ERROR;

    dst[dst_size - 1] = '\0';

    ret = strncpy(dst, src, dst_size);

    /* Not sure if this ever happens but might as
     * well be on the safe side */
    if (ret == NULL)
        return SNORT_STRNCPY_ERROR;

    if (dst[dst_size - 1] != '\0')
    {
        /* result was truncated */
        dst[dst_size - 1] = '\0';
        return SNORT_STRNCPY_TRUNCATION;
    }

    return SNORT_STRNCPY_SUCCESS;
}

char *SnortStrndup(const char *src, size_t dst_size)
{
	char *ret = SnortAlloc(dst_size + 1);
    int ret_val;

	ret_val = SnortStrncpy(ret, src, dst_size + 1);

    if(ret_val == SNORT_STRNCPY_ERROR) 
	{
		free(ret);
		return NULL;
	}

	return ret;
}

/* Determines whether a buffer is '\0' terminated and returns the
 * string length if so
 *
 * returns the string length if '\0' terminated
 * returns SNORT_STRNLEN_ERROR if not '\0' terminated
 */
int SnortStrnlen(const char *buf, int buf_size)
{
    int i = 0;

    if (buf == NULL || buf_size <= 0)
        return SNORT_STRNLEN_ERROR;

    for (i = 0; i < buf_size; i++)
    {
        if (buf[i] == '\0')
            break;
    }

    if (i == buf_size)
        return SNORT_STRNLEN_ERROR;

    return i;
}

char * SnortStrdup(const char *str)
{
    char *copy = NULL;

    if (!str)
    {
        FatalError("Unable to duplicate string: NULL!\n");
    }

    copy = strdup(str);

    if (copy == NULL)
    {
        FatalError("Unable to duplicate string: %s!\n", str);
    }

    return copy;
}

/*
 * Find first occurrence of char of accept in s, limited by slen.
 * A 'safe' version of strpbrk that won't read past end of buffer s
 * in cases that s is not NULL terminated.
 *
 * This code assumes 'accept' is a static string.
 */
const char *SnortStrnPbrk(const char *s, int slen, const char *accept)
{
    char ch;
    const char *s_end;
    if (!s || !*s || !accept || slen == 0)
        return NULL;

    s_end = s + slen;
    while (s < s_end)
    {
        ch = *s;
        if (strchr(accept, ch))
            return s;
        s++;
    }
    return NULL;
}

/*
 * Find first occurrence of searchstr in s, limited by slen.
 * A 'safe' version of strstr that won't read past end of buffer s
 * in cases that s is not NULL terminated.
 */
const char *SnortStrnStr(const char *s, int slen, const char *searchstr)
{
    char ch, nc;
    int len;
    if (!s || !*s || !searchstr || slen == 0)
        return NULL;

    if ((ch = *searchstr++) != 0)
    {
        len = strlen(searchstr);
        do
        {
            do
            {
                if ((nc = *s++) == 0)
                {
                    return NULL;
                }
                slen--;
                if (slen == 0)
                    return NULL;
            } while (nc != ch);
            if (slen - len < 0)
                return NULL;
        } while (memcmp(s, searchstr, len) != 0);
        s--;
        slen++;
    }
    return s;
}

/*
 * Find first occurrence of substring in s, ignore case.
*/
const char *SnortStrcasestr(const char *s, const char *substr)
{
    char ch, nc;
    int len;

    if (!s || !*s || !substr)
        return NULL;

    if ((ch = *substr++) != 0)
    {
        ch = tolower((char)ch);
        len = strlen(substr);
        do
        {
            do
            {
                if ((nc = *s++) == 0)
                {
                    return NULL;
                }
            } while ((char)tolower((uint8_t)nc) != ch);
        } while (strncasecmp(s, substr, len) != 0);
        s--;
    }
    return s;
}

void *SnortAlloc(unsigned long size)
{
    void *tmp;

    tmp = (void *) calloc(size, sizeof(char));

    if(tmp == NULL)
    {
        FatalError("Unable to allocate memory!  (%lu requested)\n", size);
    }

    return tmp;
}

void * SnortAlloc2(size_t size, const char *format, ...)
{
    void *tmp;

    tmp = (void *)calloc(size, sizeof(char));

    if(tmp == NULL)
    {
        va_list ap;
        char buf[STD_BUF];

        buf[STD_BUF - 1] = '\0';

        va_start(ap, format);

        vsnprintf(buf, STD_BUF - 1, format, ap);

        va_end(ap);

        FatalError("%s", buf);
    }

    return tmp;
}

/** 
 * Chroot and adjust the barnyard2_conf->log_dir reference 
 * 
 * @param directory directory to chroot to
 * @param logstore ptr to barnyard2_conf->log_dir which must be dynamically allocated
 */
void SetChroot(char *directory, char **logstore)
{
#ifdef WIN32
    FatalError("SetChroot() should not be called under Win32!\n");
#else
    char *absdir;
    size_t abslen;
    char *logdir;
    
    if(!directory || !logstore)
    {
        FatalError("Null parameter passed\n");
    }

    logdir = *logstore;

    if(logdir == NULL || *logdir == '\0')
    {
        FatalError("Null log directory\n");
    }    

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"SetChroot: %s\n",
                                       CurrentWorkingDir()););
    
    logdir = GetAbsolutePath(logdir);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "SetChroot: %s\n",
                                       CurrentWorkingDir()));
    
    logdir = SnortStrdup(logdir);

    /* We're going to reset logstore, so free it now */
    free(*logstore);
    *logstore = NULL;

    /* change to the directory */
    if(chdir(directory) != 0)
    {
        FatalError("SetChroot: Can not chdir to \"%s\": %s\n", directory, 
                   strerror(errno));
    }

    /* always returns an absolute pathname */
    absdir = CurrentWorkingDir();

    if(absdir == NULL)                          
    {
        FatalError("NULL Chroot found\n");
    }
    
    abslen = strlen(absdir);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "ABS: %s %d\n", absdir, abslen););
    
    /* make the chroot call */
    if(chroot(absdir) < 0)
    {
        FatalError("Can not chroot to \"%s\": absolute: %s: %s\n",
                   directory, absdir, strerror(errno));
    }

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"chroot success (%s ->", absdir););
    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"%s)\n ", CurrentWorkingDir()););
    
    /* change to "/" in the new directory */
    if(chdir("/") < 0)
    {
        FatalError("Can not chdir to \"/\" after chroot: %s\n", 
                   strerror(errno));
    }    

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"chdir success (%s)\n",
                            CurrentWorkingDir()););


    if(strncmp(absdir, logdir, strlen(absdir)))
    {
        FatalError("Absdir is not a subset of the logdir");
    }
    
    if(abslen >= strlen(logdir))
    {
        *logstore = SnortStrdup("/");
    }
    else
    {
        *logstore = SnortStrdup(logdir + abslen);
    }

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"new logdir from %s to %s\n",
                            logdir, *logstore));

    LogMessage("Chroot directory = %s\n", directory);

#if 0
    /* XXX XXX */
    /* install the I can't do this signal handler */
    signal(SIGHUP, SigCantHupHandler);
#endif
#endif /* !WIN32 */
}


/**
 * Return a ptr to the absolute pathname of snort.  This memory must
 * be copied to another region if you wish to save it for later use.
 */
char *CurrentWorkingDir(void)
{
    static char buf[PATH_MAX_UTIL + 1];
    
    if(getcwd((char *) buf, PATH_MAX_UTIL) == NULL)
    {
        return NULL;
    }

    buf[PATH_MAX_UTIL] = '\0';

    return (char *) buf;
}

/**
 * Given a directory name, return a ptr to a static 
 */
char *GetAbsolutePath(char *dir)
{
    char *savedir, *dirp;
    static char buf[PATH_MAX_UTIL + 1];

    if(dir == NULL)
    {
        return NULL;
    }

    savedir = strdup(CurrentWorkingDir());

    if(savedir == NULL)
    {
        return NULL;
    }

    if(chdir(dir) < 0)
    {
        LogMessage("Can't change to directory: %s\n", dir);
        free(savedir);
        return NULL;
    }

    dirp = CurrentWorkingDir();

    if(dirp == NULL)
    {
        LogMessage("Unable to access current directory\n");
        free(savedir);
        return NULL;
    }
    else
    {
        strncpy(buf, dirp, PATH_MAX_UTIL);
        buf[PATH_MAX_UTIL] = '\0';
    }

    if(chdir(savedir) < 0)
    {
        LogMessage("Can't change back to directory: %s\n", dir);
        free(savedir);                
        return NULL;
    }

    free(savedir);
    return (char *) buf;
}

int String2Long(char *string, long *result)
{
    long value;
    char *endptr;
    if(!string)
        return -1;

    value = strtol(string, &endptr, 10);
    
    while(isspace(*endptr))
        endptr++;
    
    if(*endptr != '\0')
        return -1;
    
    if(result)
        *result = value;

    return 0;
}

int String2ULong(char *string, unsigned long *result)
{
    unsigned long value;
    char *endptr;

    if(!string)
        return -1;

    value = strtoul(string, &endptr, 10);
    
    while(isspace(*endptr))
        endptr++;
    
    if(*endptr != '\0')
        return -1;
    
    if(result)
        *result = value;

    return 0;
}

int Move(const char *source, const char *dest)
{
    if(link(source, dest) != 0)
    {
        if(errno == EXDEV || errno == EPERM)
        {
            /* can't hardlink, do it the hard way */
            char *command;
            size_t command_len;
            command_len = strlen("mv") + 1 + strlen(source) + 1 + strlen(dest);
            command = (char *)SnortAlloc(command_len + 1);
            snprintf(command, command_len + 1, "mv %s %s", source, dest);
            if(system(command) != 0)
            {
                LogMessage("Failed to archive file \"%s\" to \"%s\": %s",
                        source, dest, strerror(errno));
            }
            free(command);
        }
        LogMessage("Failed to archive file \"%s\" to \"%s\": %s",
                source, dest, strerror(errno));
    }
    else
    {
        if (unlink(source) != 0) { /* oops, unlink/remove has failed */
		LogMessage("Failed to unlink \"%s\": %s",
			source, strerror(errno));
	}
    }
    return 0;
}

int ArchiveFile(const char *filepath, const char *archive_dir)
{
    char *dest;
    size_t dest_len;
    if(!filepath || !archive_dir)
        return -1;  /* Invalid argument */

    /* Archive the file */
    dest_len = strlen(archive_dir) + 1 + strlen(strrchr(filepath, '/') + 1);
    dest = (char *)SnortAlloc(dest_len + 1);
    snprintf(dest, dest_len + 1, "%s/%s", archive_dir, 
            strrchr(filepath, '/') + 1);

    Move(filepath, dest);
    free(dest);
    return 0;
}

/****************************************************************************
 *
 * Function: GetUniqueName(char * iface)
 *
 * Purpose: To return a string that has a high probability of being unique
 *          for a given sensor.
 *
 * Arguments: char * iface - The network interface you are sniffing
 *
 * Returns: A char * -- its a static char * so you should not free it
 *
 ***************************************************************************/
char *GetUniqueName(char * iface)
{
    char * rptr;
    static char uniq_name[256];

    if (iface == NULL) LogMessage("Interface is NULL. Name may not be unique for the host\n");
	if (iface != NULL)
	{
		SnortSnprintf(uniq_name, 255, "%s:%s\n",GetHostname(), iface);
	}
	else 
	{
	    SnortSnprintf(uniq_name, 255, "%s\n", GetHostname());
    }

    rptr = uniq_name; 
    
    if (BcLogVerbose()) LogMessage("Node unique name is: %s\n", rptr);
    return rptr;
}    

/****************************************************************************
 *
 * Function: GetHostname()
 *
 * Purpose: To return a string representing the hostname
 *
 * Arguments: None
 *
 * Returns: A static char * representing the hostname. 
 *
 ***************************************************************************/
char *GetHostname()
{
#ifdef WIN32
    DWORD bufflen = 256;
    static char buff[256];
    GetComputerName(buff, &bufflen);
    return buff;
#else
    char				*error = "unknown";
	static char			hostname[255];

	if (barnyard2_conf->hostname) 
		return barnyard2_conf->hostname;
	else if (gethostname(hostname, 255) == 0)
		return hostname;
    else if(getenv("HOSTNAME")) 
		return getenv("HOSTNAME");
    else if(getenv("HOST")) 
		return getenv("HOST");
    else 
		return error;
#endif
}

/****************************************************************************
 *
 * Function: GetTimestamp(register const struct timeval *tvp, int tz)
 *
 * Purpose: Get an ISO-8601 formatted timestamp for tvp within the tz
 *          timezone. 
 *
 * Arguments: sec is time in seconds.
 *            usec is microsecond component.
 *            tz is a timezone. 
 *
 * Returns: char * -- You must free this char * when you are done with it.
 *
 ***************************************************************************/
char *GetTimestampByComponent(uint32_t sec, uint32_t usec, int tz)
{
    struct tm			*lt;  /* localtime */
    char				*buf;
    time_t				Time;
    int					msec;
    
    buf = (char *)SnortAlloc(SMALLBUFFER * sizeof(char));
    
    Time = sec;
    msec = usec / 1000;

    if (BcOutputUseUtc())
    {
	lt = gmtime(&Time);
        SnortSnprintf(buf, SMALLBUFFER,
		      "%04i-%02i-%02i %02i:%02i:%02i.%03i",
		      1900 + lt->tm_year, lt->tm_mon + 1, lt->tm_mday,
		      lt->tm_hour, lt->tm_min, lt->tm_sec, msec);
    }
    else
    {
	lt = localtime(&Time);
        SnortSnprintf(buf, SMALLBUFFER,
		      "%04i-%02i-%02i %02i:%02i:%02i.%03i+%03i",
		      1900 + lt->tm_year, lt->tm_mon + 1, lt->tm_mday,
		      lt->tm_hour, lt->tm_min, lt->tm_sec, msec, tz);
    }
    
    return buf;
}

/* Same a above using a static buffer */
u_int32_t GetTimestampByComponent_STATIC(uint32_t sec, uint32_t usec, int tz,char *buf)
{
    struct tm                   *lt;  /* localtime */
    time_t                              Time;
    int                                 msec;
    
    if(buf == NULL)
    {
	/* XXX */
	return 1;
    }
    
    Time = sec;
    msec = usec / 1000;

    if (BcOutputUseUtc())
    {
        lt = gmtime(&Time);
        SnortSnprintf(buf, SMALLBUFFER,
                      "%04i-%02i-%02i %02i:%02i:%02i.%03i",
                      1900 + lt->tm_year, lt->tm_mon + 1, lt->tm_mday,
                      lt->tm_hour, lt->tm_min, lt->tm_sec, msec);
    }
    else
    {
        lt = localtime(&Time);
        SnortSnprintf(buf, SMALLBUFFER,
                      "%04i-%02i-%02i %02i:%02i:%02i.%03i+%03i",
                      1900 + lt->tm_year, lt->tm_mon + 1, lt->tm_mday,
                      lt->tm_hour, lt->tm_min, lt->tm_sec, msec, tz);
    }
    
    return 0;
}


/****************************************************************************
 *
 * Function: GetTimestampByStruct(register const struct timeval *tvp, int tz)
 *
 * Purpose: Get an ISO-8601 formatted timestamp for tvp within the tz
 *          timezone. 
 *
 * Arguments: tvp is a timeval pointer. tz is a timezone. 
 *
 * Returns: char * -- You must free this char * when you are done with it.
 *
 ***************************************************************************/
char *GetTimestampByStruct(register const struct timeval *tvp, int tz)
{
    struct tm *lt;  /* localtime */
    char * buf;
    int msec;

    buf = (char *)SnortAlloc(SMALLBUFFER * sizeof(char));

    msec = tvp->tv_usec / 1000;

    if (BcOutputUseUtc())
    {
        lt = gmtime((time_t *)&tvp->tv_sec);
        SnortSnprintf(buf, SMALLBUFFER, "%04i-%02i-%02i %02i:%02i:%02i.%03i",
                1900 + lt->tm_year, lt->tm_mon + 1, lt->tm_mday,
                lt->tm_hour, lt->tm_min, lt->tm_sec, msec);
    }
    else
    {
        lt = localtime((time_t *)&tvp->tv_sec);
        SnortSnprintf(buf, SMALLBUFFER,
                "%04i-%02i-%02i %02i:%02i:%02i.%03i+%03i",
                1900 + lt->tm_year, lt->tm_mon + 1, lt->tm_mday,
                lt->tm_hour, lt->tm_min, lt->tm_sec, msec, tz);
    }

    return buf;
}


/* Same as above using static buffer */
u_int32_t GetTimestampByStruct_STATIC(register const struct timeval *tvp, int tz,char *buf)
{
    struct tm *lt;  /* localtime */
    int msec;
    
    if(buf == NULL)
    {
	/* XXX */
	return 1;
    }
    
    msec = tvp->tv_usec / 1000;
    
    if (BcOutputUseUtc())
    {
        lt = gmtime((time_t *)&tvp->tv_sec);
        SnortSnprintf(buf, SMALLBUFFER, "%04i-%02i-%02i %02i:%02i:%02i.%03i",
		      1900 + lt->tm_year, lt->tm_mon + 1, lt->tm_mday,
		      lt->tm_hour, lt->tm_min, lt->tm_sec, msec);
    }
    else
    {
        lt = localtime((time_t *)&tvp->tv_sec);
        SnortSnprintf(buf, SMALLBUFFER,
		      "%04i-%02i-%02i %02i:%02i:%02i.%03i+%03i",
		      1900 + lt->tm_year, lt->tm_mon + 1, lt->tm_mday,
		      lt->tm_hour, lt->tm_min, lt->tm_sec, msec, tz);
    }
    
    return 0;
}


/****************************************************************************
 *
 * Function: GetLocalTimezone()
 *
 * Purpose: Find the offset from GMT for current host
 *
 * Arguments: none 
 *
 * Returns: int representing the offset from GMT
 *
 ***************************************************************************/
int GetLocalTimezone()
{
    time_t      ut;
    struct tm * ltm;
    long        seconds_away_from_utc;

    time(&ut);
    ltm = localtime(&ut);

#if defined(WIN32) || defined(SOLARIS) || defined(AIX) || defined(HPUX) ||\
    defined(__CYGWIN__) || defined( __CYGWIN64__) || defined(__CYGWIN__)
    /* localtime() sets the global timezone variable,
       which is defined in <time.h> */
    seconds_away_from_utc = timezone;
#else
    seconds_away_from_utc = ltm->tm_gmtoff;
#endif

    return  seconds_away_from_utc/3600;
}

/****************************************************************************
 *
 * Function: GetCurrentTimestamp()
 *
 * Purpose: Generate an ISO-8601 formatted timestamp for the current time.
 *
 * Arguments: none 
 *
 * Returns: char * -- You must free this char * when you are done with it.
 *
 ***************************************************************************/
char *GetCurrentTimestamp(void)
{
    struct tm *lt;
    struct timezone tz;
    struct timeval tv;
    struct timeval *tvp;
    char * buf;
    int tzone;
    int msec;

    buf = (char *)SnortAlloc(SMALLBUFFER * sizeof(char));

    memset((char *)&tz, 0, sizeof(tz)); /* bzero() deprecated, replaced by memset() */
    gettimeofday(&tv,&tz);
    tvp = &tv;

    msec = tvp->tv_usec/1000;

    if (BcOutputUseUtc())
    {
        lt = gmtime((time_t *)&tvp->tv_sec);
        SnortSnprintf(buf, SMALLBUFFER, "%04i-%02i-%02i %02i:%02i:%02i.%03i",
                1900 + lt->tm_year, lt->tm_mon + 1, lt->tm_mday,
                lt->tm_hour, lt->tm_min, lt->tm_sec, msec);
    }
    else
    {
        lt = localtime((time_t *)&tvp->tv_sec);

        tzone = GetLocalTimezone();

        SnortSnprintf(buf, SMALLBUFFER,
                "%04i-%02i-%02i %02i:%02i:%02i.%03i+%03i",
                1900 + lt->tm_year, lt->tm_mon + 1, lt->tm_mday,
                lt->tm_hour, lt->tm_min, lt->tm_sec, msec, tzone);
    }

    return buf;
}

/* Same as above using static */
u_int32_t GetCurrentTimestamp_STATIC(char *buf)
{
    struct tm *lt;
    struct timezone tz;
    struct timeval tv;
    struct timeval *tvp;
    int tzone;
    int msec;

    if(buf == NULL)
    {
	/* XXX */
	return 1;
    }


    bzero((char *)&tz,sizeof(tz));
    gettimeofday(&tv,&tz);
    tvp = &tv;

    msec = tvp->tv_usec/1000;

    if (BcOutputUseUtc())
    {
        lt = gmtime((time_t *)&tvp->tv_sec);
        SnortSnprintf(buf, SMALLBUFFER, "%04i-%02i-%02i %02i:%02i:%02i.%03i",
		      1900 + lt->tm_year, lt->tm_mon + 1, lt->tm_mday,
		      lt->tm_hour, lt->tm_min, lt->tm_sec, msec);
    }
    else
    {
        lt = localtime((time_t *)&tvp->tv_sec);

        tzone = GetLocalTimezone();

        SnortSnprintf(buf, SMALLBUFFER,
		      "%04i-%02i-%02i %02i:%02i:%02i.%03i+%03i",
		      1900 + lt->tm_year, lt->tm_mon + 1, lt->tm_mday,
		      lt->tm_hour, lt->tm_min, lt->tm_sec, msec, tzone);
    }
    
    return 0;
}




/****************************************************************************
 * Function: base64(char * xdata, int length)
 *
 * Purpose: Insert data into the database
 *
 * Arguments: xdata  => pointer to data to base64 encode
 *            length => how much data to encode 
 *
 * Make sure you allocate memory for the output before you pass
 * the output pointer into this function. You should allocate 
 * (1.5 * length) bytes to be safe.
 *
 * Returns: data base64 encoded as a char *
 *
 ***************************************************************************/
char * base64(const u_char * xdata, int length)
{
    int count, cols, bits, c, char_count;
    unsigned char alpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";  /* 64 bytes */
    char * payloadptr;
    char * output;
    char_count = 0;
    bits = 0;
    cols = 0;

    output = (char *)SnortAlloc( ((unsigned int) (length * 1.5 + 4)) * sizeof(char) );

    payloadptr = output;

    for(count = 0; count < length; count++)
    {
        c = xdata[count];

        if(c > 255)
        {
            ErrorMessage("plugbase.c->base64(): encountered char > 255 (decimal %d)\n If you see this error message a char is more than one byte on your machine\n This means your base64 results can not be trusted", c);
        }

        bits += c;
        char_count++;

        if(char_count == 3)
        {
            *output = alpha[bits >> 18]; output++;
            *output = alpha[(bits >> 12) & 0x3f]; output++;
            *output = alpha[(bits >> 6) & 0x3f]; output++;
            *output = alpha[bits & 0x3f]; output++; 
            cols += 4;
            if(cols == 72)
            {
                *output = '\n'; output++;
                cols = 0;
            }
            bits = 0;
            char_count = 0;
        }
        else
        {
            bits <<= 8;
        }
    }

    if(char_count != 0)
    {
        bits <<= 16 - (8 * char_count);
        *output = alpha[bits >> 18]; output++;
        *output = alpha[(bits >> 12) & 0x3f]; output++;
        if(char_count == 1)
        {
            *output = '='; output++;
            *output = '='; output++;
        }
        else
        {
            *output = alpha[(bits >> 6) & 0x3f]; 
            output++; *output = '='; 
            output++;
        }
    }
    *output = '\0';
    return payloadptr;
} 

/* Same as above but uses a static buffer provided as a 3rd argument to function.. */
u_int32_t base64_STATIC(const u_char * xdata, int length,char *output)
{
    int count, cols, bits, c, char_count;
    unsigned char alpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";  /* 64 bytes */
    

    char_count = 0;
    bits = 0;
    cols = 0;

    if( ((length * 1.5) + 4 ) > MAX_QUERY_LENGTH)
    {
	/* XXX */
	return 1;
    }
    
    memset(output,'\0',MAX_QUERY_LENGTH);


    for(count = 0; count < length; count++)
    {
        c = xdata[count];

        if(c > 255)
        {
            ErrorMessage("plugbase.c->base64(): encountered char > 255 (decimal %d)\n If you see this error message a char is more than one byte on your machine\n This means your base64 results can not be trusted", c);
        }

        bits += c;
        char_count++;

        if(char_count == 3)
        {
            *output = alpha[bits >> 18]; output++;
            *output = alpha[(bits >> 12) & 0x3f]; output++;
            *output = alpha[(bits >> 6) & 0x3f]; output++;
            *output = alpha[bits & 0x3f]; output++;
            cols += 4;
            if(cols == 72)
            {
                *output = '\n'; output++;
                cols = 0;
            }
            bits = 0;
            char_count = 0;
        }
        else
        {
            bits <<= 8;
        }
    }

    if(char_count != 0)
    {
        bits <<= 16 - (8 * char_count);
        *output = alpha[bits >> 18]; output++;
        *output = alpha[(bits >> 12) & 0x3f]; output++;
        if(char_count == 1)
        {
            *output = '='; output++;
            *output = '='; output++;
        }
        else
        {
            *output = alpha[(bits >> 6) & 0x3f];
            output++; *output = '=';
            output++;
        }
    }
    *output = '\0';


    return 0;
}



/****************************************************************************
 *
 * Function: ascii(u_char *xdata, int length)
 *
 * Purpose: This function takes takes a buffer "xdata" and its length then
 *          returns a string of only the printable ASCII characters.
 *
 * Arguments: xdata is the buffer, length is the length of the buffer in
 *            bytes
 *
 * Returns: char * -- You must free this char * when you are done with it.
 *
 ***************************************************************************/
char *ascii(const u_char *xdata, int length)
{
     char *d_ptr, *ret_val;
     int i,count = 0;
     int size;
     
     if(xdata == NULL)
     {
         return NULL;         
     }
     
     for(i=0;i<length;i++)
     {
         if(xdata[i] == '<')
             count+=4;              /* &lt; */
         else if(xdata[i] == '&')
             count+=5;              /* &amp; */
         else if(xdata[i] == '>')   /* &gt;  */
             count += 4;
     }

     size = length + count + 1;
     ret_val = (char *) calloc(1,size);
     
     if(ret_val == NULL)
     {
         LogMessage("plugbase.c: ascii(): Out of memory, can't log anything!\n");
         return NULL;
     }
     
     d_ptr = ret_val; 
     
     for(i=0;i<length;i++)
     {
         if((xdata[i] > 0x1F) && (xdata[i] < 0x7F))
         {
             if(xdata[i] == '<')
             {
                 SnortStrncpy(d_ptr, "&lt;", size - (d_ptr - ret_val));
                 d_ptr+=4;
             }
             else if(xdata[i] == '&')
             {
                 SnortStrncpy(d_ptr, "&amp;", size - (d_ptr - ret_val));
                 d_ptr += 5;
             }
             else if(xdata[i] == '>')
             {
                 SnortStrncpy(d_ptr, "&gt;", size - (d_ptr - ret_val));
                 d_ptr += 4;
             }
             else
             {
                 *d_ptr++ = xdata[i];
             }
         }
         else
         {
             *d_ptr++ = '.';
         }        
     }
     
     *d_ptr++ = '\0';
     
     return ret_val;
}

/* Same as above but working with a static buffer .. */
u_int32_t ascii_STATIC(const u_char *xdata, int length,char *ret_val)
{
    char *d_ptr;
    int i,count = 0;
    int size;
    
    if( (xdata == NULL) ||
	(ret_val == NULL))
    {
	return 1;
    }
    
    for(i=0;i<length;i++)
    {
	if(xdata[i] == '<')
	    count+=4;              /* &lt; */
	else if(xdata[i] == '&')
	    count+=5;              /* &amp; */
	else if(xdata[i] == '>')   /* &gt;  */
	    count += 4;
    }

    size = length + count + 1;

    if(size > MAX_QUERY_LENGTH)
    {
	return 1;
    }
    
    memset(ret_val,'\0',MAX_QUERY_LENGTH);
    
    d_ptr = ret_val;

    for(i=0;i<length;i++)
    {
	if((xdata[i] > 0x1F) && (xdata[i] < 0x7F))
	{
	    if(xdata[i] == '<')
	    {
		SnortStrncpy(d_ptr, "&lt;", size - (d_ptr - ret_val));
		d_ptr+=4;
	    }
	    else if(xdata[i] == '&')
	    {
		SnortStrncpy(d_ptr, "&amp;", size - (d_ptr - ret_val));
		d_ptr += 5;
	    }
	    else if(xdata[i] == '>')
	    {
		SnortStrncpy(d_ptr, "&gt;", size - (d_ptr - ret_val));
		d_ptr += 4;
	    }
	    else
	    {
		*d_ptr++ = xdata[i];
	    }
	}
	else
	{
	    *d_ptr++ = '.';
	}
    }

    *d_ptr++ = '\0';

    return 0;
    
}


/****************************************************************************
 *
 * Function: hex(u_char *xdata, int length)
 *
 * Purpose: This function takes takes a buffer "xdata" and its length then
 *          returns a string of hex with no spaces
 *
 * Arguments: xdata is the buffer, length is the length of the buffer in
 *            bytes
 *
 * Returns: char * -- You must free this char * when you are done with it.
 *
 ***************************************************************************/
char *hex(const u_char *xdata, int length)
{
    int x;
    char *rval = NULL;
    char *buf = NULL;

    if (xdata == NULL)
        return NULL;

    buf = (char *)calloc((length * 2) + 1, sizeof(char));

    if (buf != NULL)
    {
        rval = buf;

        for (x = 0; x < length; x++)
        {
            SnortSnprintf(buf, 3, "%02X", xdata[x]);
            buf += 2;
        } 

        rval[length * 2] = '\0';
    }

    return rval;
}





char *fasthex(const u_char *xdata, int length)
{
    char conv[] = "0123456789ABCDEF";
    char *retbuf = NULL; 
    const u_char *index;
    const u_char *end;
    char *ridx;

    index = xdata;
    end = xdata + length;
    retbuf = (char *)SnortAlloc(((length * 2) + 1) * sizeof(char));
    ridx = retbuf;

    while(index < end)
    {
        *ridx++ = conv[((*index & 0xFF)>>4)];
        *ridx++ = conv[((*index & 0xFF)&0x0F)];
        index++;
    }

    return retbuf;
}

/* same as above but working with a static buffer */
u_int32_t fasthex_STATIC(const u_char *xdata, int length,char *retbuf)
{
    char conv[] = "0123456789ABCDEF";
    const u_char *index;
    const u_char *end;
    char *ridx;

    if( (xdata == NULL) ||
	(retbuf == NULL) ||
	(((length *2) + 1) > MAX_QUERY_LENGTH))
    {
	/* XXX */
	return 1;
    }

    index = xdata;
    end = xdata + length;
    
    memset(retbuf,'\0',MAX_QUERY_LENGTH);
    
    ridx = retbuf;
    
    while(index < end)
    {
        *ridx++ = conv[((*index & 0xFF)>>4)];
        *ridx++ = conv[((*index & 0xFF)&0x0F)];
        index++;
    }
    
    return 0;
}


/*
 *   Fatal Integer Parser
 *   Ascii to Integer conversion with fatal error support
 */
long int xatol(const char *s , const char *etext)
{
    long int val;
    char *endptr;
    char *default_error = "xatol() error\n";

    if (etext == NULL)
        etext = default_error;

    if (s == NULL)
        FatalError("%s: String is NULL\n", etext);

    while (isspace((int)*s))
        s++;

    if (strlen(s) == 0)
        FatalError("%s: String is empty\n", etext);

    errno = 0;

    /*
     *  strtoul - errors on win32 : ERANGE (VS 6.0)
     *            errors on linux : ERANGE, EINVAL
     *               (for EINVAL, unsupported base which won't happen here)
     */ 
    val = strtol(s, &endptr, 0);

    if ((errno == ERANGE) || (*endptr != '\0'))
        FatalError("%s: Invalid integer input: %s\n", etext, s);

    return val;
}

/*
 *   Fatal Integer Parser
 *   Ascii to Integer conversion with fatal error support
 */
unsigned long int xatou(const char *s , const char *etext)
{
    unsigned long int val;
    char *endptr;
    char *default_error = "xatou() error\n";

    if (etext == NULL)
        etext = default_error;

    if (s == NULL)
        FatalError("%s: String is NULL\n", etext);

    while (isspace((int)*s))
        s++;

    if (strlen(s) == 0)
        FatalError("%s: String is empty\n", etext);

    if (*s == '-') 
    {
        FatalError("%s: Invalid unsigned integer - negative sign found, "
                   "input: %s\n", etext, s);
    }

    errno = 0;

    /*
     *  strtoul - errors on win32 : ERANGE (VS 6.0)
     *            errors on linux : ERANGE, EINVAL
     */ 
    val = strtoul(s, &endptr, 0);

    if ((errno == ERANGE) || (*endptr != '\0'))
        FatalError("%s: Invalid integer input: %s\n", etext, s);

    return val;
}

unsigned long int xatoup(const char *s , const char *etext)
{
    unsigned long int val = xatou(s, etext);
    if ( !val ) 
        FatalError("%s: must be > 0\n", etext);
    return val;
}



/* 
   Tough to be a solution for a issue where it was not needed
   but kept if its ever needed.
*/
u_int32_t string_sanitize_character(char *input,char ichar)
{
    char *cindex = NULL;

    u_int32_t orig_len = 0;
    u_int32_t end_len = 0;
    
    if( (input == NULL) ||
	(ichar == 0x00))
    {
	/* XXX */
	return 1;
    }
    
    orig_len = strlen(input) + 1;
    
    while( (cindex = index(input,ichar)) != NULL)
    {

	if( (end_len = strlen(cindex)) > orig_len)
        {
	    /* Could be far fetched ...but who know's...*/
	    /* XXX */
	    return 1;
        }

	memcpy(cindex,cindex+1,strlen((cindex)));
	cindex[end_len] = '\0';
	cindex = NULL;
    }

    return 0;
}


int BY2Strtoul(char *inStr,unsigned long *ul_ptr)
{
    char *endptr = NULL;
    
    if( (inStr == NULL) ||
        (ul_ptr == NULL))
    {
        return 1;
    }
    
    *ul_ptr = strtoul(inStr,&endptr,10);
    
    if ((errno == ERANGE && ( *ul_ptr == LONG_MAX || *ul_ptr == LONG_MIN)) ||
        (errno != 0 && *ul_ptr == 0))
    {
        FatalError("[%s()], strtoul error : [%s] for [%s]\n",
                   __FUNCTION__,
                   strerror(errno),
                   inStr);
    }
    
    if( *endptr != '\0' || (endptr == inStr))
    {
        LogMessage("[%s()], is not a digit [%s] \n",
                   __FUNCTION__,
                   inStr);
        return 1;
    }
    
    return 0;
}
