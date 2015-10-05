/*
** Copyright (C) 2002-2009 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 2000,2001 Andrew R. Baker <andrewb@uab.edu>
** Copyright (C) 2015 Colin Grady <colin.grady@gmail.com>
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

/* $Id$ */

/* spo_log_full
 * 
 * Purpose:  output plugin for full alerting
 *
 * Arguments:  alert file (eventually)
 *   
 * Effect:
 *
 * Alerts are written to a file in the snort full alert format
 *
 * Comments:   Allows use of full alerts with other output plugin types
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include <sys/types.h>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* !WIN32 */

#include <stdio.h>
#include <stdlib.h>

#include "barnyard2.h"
#include "decode.h"
#include "plugbase.h"
#include "debug.h"
#include "parser.h"
#include "util.h"
#include "log.h"
#include "mstring.h"
#include "map.h"
#include "unified2.h"

#include "sfutil/sf_textlog.h"
#include "log_text.h"

#include "output-plugins/spo_log_full.h"


#define FULL_LOG_FILE "log.full"
#define DEFAULT_LIMIT (128 * M_BYTES)
#define LOG_BUFFER    (4 * K_BYTES)


typedef struct _SpoLogFullData
{
    TextLog* log;

    u_int8_t encoding;

    char encoded_buffer[MAX_QUERY_LENGTH];
} SpoLogFullData;


static void LogFullInit(char *);
static SpoLogFullData *ParseLogFullArgs(char *);
static void LogFull(Packet *, void *, uint32_t, void *);
static void AppendPayload (SpoLogFullData *data, Packet *p);
static void LogFullCleanExit(int, void *);
static void LogFullRestart(int, void *);


void LogFullSetup (void)
{
    RegisterOutputPlugin("log_full", OUTPUT_TYPE_FLAG__LOG, LogFullInit);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output plugin: log_full is setup...\n"););
}

static void LogFullInit (char *args)
{
    SpoLogFullData *data;
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output: log_full Initialized\n"););

    data = ParseLogFullArgs(args);
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Linking log_full functions to call lists...\n"););

    AddFuncToOutputList(LogFull, OUTPUT_TYPE__LOG, data);
    AddFuncToCleanExitList(LogFullCleanExit, data);
    AddFuncToRestartList(LogFullRestart, data);
}

static void LogFull (Packet *p, void *event, uint32_t event_type, void *arg)
{
    SpoLogFullData *data;
    SigNode        *sn;

    if (p == NULL || event == NULL || arg == NULL)
    {
        return;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "Logging log data!\n"););

    // Get the meta
    data = (SpoLogFullData *)arg;
    sn = GetSigByGidSid(ntohl(((Unified2EventCommon *)event)->generator_id),
                        ntohl(((Unified2EventCommon *)event)->signature_id),
                        ntohl(((Unified2EventCommon *)event)->signature_revision));

    /* Log format:
     *  [Snort Log] <eth2> [1:1234:1] Some Snort Rule [Classification: Attempted Information Leak] [Priority: 2] {tcp} 1.2.3.4:12412 -> 2.3.4.5:80 || <encoded data>
     *
     */

    // Start the log with [Snort Log] text
    TextLog_Puts(data->log, "[Snort Log] ");

    // Print interface (if asked for)
    if (BcAlertInterface())
    {
        TextLog_Print(data->log, "<%s> ", PRINT_INTERFACE(barnyard2_conf->interface));
    }

    // Print the gen:sig:rev data
    if (event != NULL)
    {
        TextLog_Print(data->log, "[%lu:%lu:%lu] ", (unsigned long) ntohl(((Unified2EventCommon *)event)->generator_id),
                                                   (unsigned long) ntohl(((Unified2EventCommon *)event)->signature_id),
                                                   (unsigned long) ntohl(((Unified2EventCommon *)event)->signature_revision));
    }

    // Print the message name, if available
    if (sn != NULL)
    {
        TextLog_Print(data->log, "%s ", sn->msg);
    }
    else
    {
        TextLog_Puts(data->log, "Snort Alert ");
    }

    // Log the class and priority
    LogPriorityData(data->log, ntohl(((Unified2EventCommon *)event)->classification_id),
                               ntohl(((Unified2EventCommon *)event)->priority_id),
                               FALSE);

    if (p && IPH_IS_VALID(p))
    {
        // Log the protocol
        TextLog_Print(data->log, "{%s} ", protocol_names[GET_IPH_PROTO(p)]);

        if (p->frag_flag)
        {
            /* just print the straight IP header */
            if (!BcObfuscate())
            {
                TextLog_Print(data->log, "%s -> %s", inet_ntoa(GET_SRC_ADDR(p)), inet_ntoa(GET_DST_ADDR(p)));
            }
            else
            {
                /* print the header complete with port information */
                if (IS_IP4(p))
                {
                    TextLog_Print(data->log, "xxx.xxx.xxx.xxx:%d -> xxx.xxx.xxx.xxx:%d", p->sp, p->dp);
                }
                else if (IS_IP6(p))
                {
                    TextLog_Print(data->log, "x:x:x:x::x:x:x:x:%d -> x:x:x:x:x:x:x:x:%d", p->sp, p->dp);
                }
            }
        }
        else
        {
            switch(GET_IPH_PROTO(p))
            {
                case IPPROTO_UDP:
                case IPPROTO_TCP:
                    if (!BcObfuscate())
                    {
                        TextLog_Print(data->log, "%s:%d -> %s:%d", inet_ntoa(GET_SRC_ADDR(p)), p->sp, inet_ntoa(GET_DST_ADDR(p)), p->dp);
                    }
                    else
                    {
                        if (IS_IP4(p))
                        {
                            TextLog_Print(data->log, "xxx.xxx.xxx.xxx:%d -> xxx.xxx.xxx.xxx:%d", p->sp, p->dp);
                        }
                        else if (IS_IP6(p))
                        {
                            TextLog_Print(data->log, "x:x:x:x::x:x:x:x:%d -> x:x:x:x:x:x:x:x:%d", p->sp, p->dp);
                        }
                    }
                    break;

                case IPPROTO_ICMP:
                default:
                    if (!BcObfuscate())
                    {
                        TextLog_Print(data->log, "%s -> %s", inet_ntoa(GET_SRC_ADDR(p)), inet_ntoa(GET_DST_ADDR(p)));
                    }
                    else
                    {
                        if (IS_IP4(p))
                        {
                            TextLog_Puts(data->log, "xxx.xxx.xxx.xxx -> xxx.xxx.xxx.xxx");
                        }
                        else if (IS_IP6(p))
                        {
                            TextLog_Puts(data->log, "x:x:x:x::x:x:x:x -> x:x:x:x:x:x:x:x");
                        }
                    }
            }
        }

        // Add the payload data
        AppendPayload(data, p);
    }

    TextLog_NewLine(data->log);
    TextLog_Flush(data->log);
}

static void AppendPayload (SpoLogFullData *data, Packet *p)
{
    if (data == NULL || p == NULL || p->pkt == NULL)
    {
        return;
    }
    
    if (p->pkth->caplen > 0)
    {
        memset(data->encoded_buffer, '\0', MAX_QUERY_LENGTH);

        switch (data->encoding)
        {
            case ENCODING_HEX:
                if (fasthex_STATIC(p->pkt, p->pkth->caplen, data->encoded_buffer))
                {
                    return;
                }
                break;

            case ENCODING_BASE64:
                if (base64_STATIC(p->pkt, p->pkth->caplen, data->encoded_buffer))
                {
                    return;
                }
                break;

            case ENCODING_ASCII:
            default:
                if (ascii_STATIC(p->pkt, p->pkth->caplen, data->encoded_buffer))
                {
                    return;
                }
                break;
        }

        if (strlen(data->encoded_buffer))
        {
            TextLog_Print(data->log, " || %s", data->encoded_buffer);
        }
    }
}

static SpoLogFullData *ParseLogFullArgs (char *args)
{
    SpoLogFullData *data;
    char **toks;
    int num_toks;
    int i;
    char *filename = NULL;
    unsigned long limit;

    data = (SpoLogFullData *)SnortAlloc(sizeof(SpoLogFullData));

    // Set some defaults
    data->encoding = ENCODING_ASCII;
    limit = DEFAULT_LIMIT;

    toks = mSplit(args, ",", 0, &num_toks, '\\');

    for (i = 0; i < num_toks; i++)
    {
        char **stoks;
        int num_stoks;
        char *setting = toks[i];
        char *end;

        // Strip off leading spaces
        while (isspace((int) *setting))
        {
            ++setting;
        }

        // Save key [0] and value [1] tokens from setting
        stoks = mSplit(setting, " ", 2, &num_stoks, 0);

        if (!strcasecmp("filename", stoks[0]))
        {
            if (num_stoks > 1)
            {
                filename = SnortStrdup(stoks[1]);
            }
            else
            {
                filename = SnortStrdup(FULL_LOG_FILE);
            }
        }

        else if (!strcasecmp("limit", stoks[0]))
        {
            if (num_stoks > 1)
            {
                limit = strtol(stoks[1], &end, 10);

                if (stoks[1] == end)
                {
                    FatalError("log_full: Error in %s(%i): %s\n", file_name, file_line, stoks[1]);
                }
                if (end && toupper(*end) == 'G')
                {
                    limit <<= 30; /* GB */
                }
                else if ( end && toupper(*end) == 'M' )
                {
                    limit <<= 20; /* MB */
                }
                else if ( end && toupper(*end) == 'K' )
                {
                    limit <<= 10; /* KB */
                }
                break;
            }
            else
            {
                FatalError("log_full: Limit setting in config, but not specified\n");
            }
        }

        else if (!strcasecmp("encoding", stoks[0]))
        {
            if (num_stoks > 1)
            {
                if (strcasecmp("hex", stoks[1]) == 0)
                {
                    data->encoding = ENCODING_HEX;
                }
                else if (strcasecmp("ascii", stoks[1]) == 0)
                {
                    data->encoding = ENCODING_ASCII;
                }
                else if (strcasecmp("base64", stoks[1]) == 0)
                {
                    data->encoding = ENCODING_BASE64;
                }
                else
                {
                    FatalError("log_full: Encoding in config set to invalid setting (%s)\n", stoks[1]);
                }
            }
            else
            {
                FatalError("log_full: Encoding in config not defined\n");
            }
        }

        mSplitFree(&stoks, num_stoks);
    }

    mSplitFree(&toks, num_toks);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "log_full: log: %s; limit: %ld\n; encoding: %d", filename, limit, data->encoding););

    data->log = TextLog_Init(filename, LOG_BUFFER, limit);
    if (filename)
    {
        free(filename);
    }

    return data;
}

static void LogFullCleanup (int signal, void *arg, const char* msg)
{
    SpoLogFullData *data = (SpoLogFullData *)arg;

    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "%s\n", msg););

    /* free memory from SpoLogFullData */
    if (data->log)
        TextLog_Term(data->log);
    
    memset(data->encoded_buffer, '\0', MAX_QUERY_LENGTH);

    if (data)
        free(data);
    
    return;
}

static void LogFullCleanExit (int signal, void *arg)
{
    LogFullCleanup(signal, arg, "LogFullCleanExit");
}

static void LogFullRestart (int signal, void *arg)
{
    LogFullCleanup(signal, arg, "LogFullRestart");
}

