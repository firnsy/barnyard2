/*
** Copyright (C) 2002-2009 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 2001 Brian Caswell <bmc@mitre.org>
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

/* spo_csv
 *
 * Purpose:  output plugin for csv alerting
 *
 * Arguments:  alert file (eventually)
 *
 * Effect:
 *
 * Alerts are written to a file in the snort csv alert format
 *
 * Comments:   Allows use of csv alerts with other output plugin types
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* !WIN32 */

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "mstring.h"
#include "util.h"
#include "log.h"
#include "map.h"
#include "unified2.h"

#include "barnyard2.h"

#include "sfutil/sf_textlog.h"
#include "log_text.h"
#include "ipv6_port.h"

#define DEFAULT_CSV "timestamp,sig_generator,sig_id,sig_rev,msg,proto,src,srcport,dst,dstport,ethsrc,ethdst,ethlen,tcpflags,tcpseq,tcpack,tcpln,tcpwindow,ttl,tos,id,dgmlen,iplen,icmptype,icmpcode,icmpid,icmpseq"

#define DEFAULT_FILE  "alert.csv"
#define DEFAULT_LIMIT (128*M_BYTES)
#define LOG_BUFFER    (4*K_BYTES)

typedef struct _AlertCSVConfig
{
    char *type;
    struct _AlertCSVConfig *next;
} AlertCSVConfig;

typedef struct _AlertCSVData
{
    TextLog* log;
    char * csvargs;
    char ** args;
    int numargs;
    AlertCSVConfig *config;
} AlertCSVData;


/* list of function prototypes for this preprocessor */
static void AlertJSONInit(char *);
static AlertCSVData *AlertCSVParseArgs(char *);
static void AlertCSV(Packet *, void *, uint32_t, void *);
static void AlertCSVCleanExit(int, void *);
static void AlertCSVRestart(int, void *);
static void RealAlertCSV(
    Packet*, void*, uint32_t, char **args, int numargs, TextLog*
);

/*
 * Function: SetupJSON()
 *
 * Purpose: Registers the output plugin keyword and initialization
 *          function into the output plugin list.  This is the function that
 *          gets called from InitOutputPlugins() in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void AlertJSONSetup(void)
{
    /* link the preprocessor keyword to the init function in
       the preproc list */
    RegisterOutputPlugin("alert_json", OUTPUT_TYPE_FLAG__ALERT, AlertJSONInit);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output plugin: alert_json is setup...\n"););
}


/*
 * Function: JSONInit(char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
static void AlertJSONInit(char *args)
{
    AlertCSVData *data;
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output: CSV Initialized\n"););

    /* parse the argument list from the rules file */
    data = AlertCSVParseArgs(args);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Linking CSV functions to call lists...\n"););

    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(AlertCSV, OUTPUT_TYPE__ALERT, data);
    AddFuncToCleanExitList(AlertCSVCleanExit, data);
    AddFuncToRestartList(AlertCSVRestart, data);
}

/*
 * Function: ParseCSVArgs(char *)
 *
 * Purpose: Process positional args, if any.  Syntax is:
 * output alert_csv: [<logpath> ["default"|<list> [<limit>]]]
 * list ::= <field>(,<field>)*
 * field ::= "dst"|"src"|"ttl" ...
 * limit ::= <number>('G'|'M'|K')
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 */
static AlertCSVData *AlertCSVParseArgs(char *args)
{
    char **toks;
    int num_toks;
    AlertCSVData *data;
    char* filename = NULL;
    unsigned long limit = DEFAULT_LIMIT;
    int i;

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "ParseCSVArgs: %s\n", args););
    data = (AlertCSVData *)SnortAlloc(sizeof(AlertCSVData));

    if ( !data )
    {
        FatalError("alert_csv: unable to allocate memory!\n");
    }
    if ( !args ) args = "";
    toks = mSplit((char *)args, " \t", 4, &num_toks, '\\');

    for (i = 0; i < num_toks; i++)
    {
        const char* tok = toks[i];
        char *end;

        switch (i)
        {
            case 0:
                if ( !strcasecmp(tok, "stdout") )
                    filename = SnortStrdup(tok);

                else
                    filename = ProcessFileOption(barnyard2_conf_for_parsing, tok);
                break;

            case 1:
                if ( !strcasecmp("default", tok) )
                {
                data->csvargs = strdup(DEFAULT_CSV);
                }
                else
                {
                data->csvargs = strdup(toks[1]);
                }
                break;

            case 2:
                limit = strtol(tok, &end, 10);

                if ( tok == end )
                    FatalError("alert_csv error in %s(%i): %s\n",
                        file_name, file_line, tok);

                if ( end && toupper(*end) == 'G' )
                    limit <<= 30; /* GB */

                else if ( end && toupper(*end) == 'M' )
                    limit <<= 20; /* MB */

                else if ( end && toupper(*end) == 'K' )
                    limit <<= 10; /* KB */
                break;

            case 3:
                FatalError("alert_csv: error in %s(%i): %s\n",
                    file_name, file_line, tok);
                break;
        }
    }
    if ( !data->csvargs ) data->csvargs = strdup(DEFAULT_CSV);
    if ( !filename ) filename = ProcessFileOption(barnyard2_conf_for_parsing, DEFAULT_FILE);

    mSplitFree(&toks, num_toks);
    toks = mSplit(data->csvargs, ",", 128, &num_toks, 0);

    data->args = toks;
    data->numargs = num_toks;

    DEBUG_WRAP(DebugMessage(
        DEBUG_INIT, "alert_csv: '%s' '%s' %ld\n", filename, data->csvargs, limit
    ););
    data->log = TextLog_Init(filename, LOG_BUFFER, limit);
    if ( filename ) free(filename);

    return data;
}

static void AlertCSVCleanup(int signal, void *arg, const char* msg)
{
    AlertCSVData *data = (AlertCSVData *)arg;
    /* close alert file */
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"%s\n", msg););

    if(data)
    {
        mSplitFree(&data->args, data->numargs);
        if (data->log) TextLog_Term(data->log);
        free(data->csvargs);
        /* free memory from SpoCSVData */
        free(data);
    }
}

static void AlertCSVCleanExit(int signal, void *arg)
{
    AlertCSVCleanup(signal, arg, "AlertCSVCleanExit");
}

static void AlertCSVRestart(int signal, void *arg)
{
    AlertCSVCleanup(signal, arg, "AlertCSVRestart");
}


static void AlertCSV(Packet *p, void *event, uint32_t event_type, void *arg)
{
    AlertCSVData *data = (AlertCSVData *)arg;
    RealAlertCSV(p, event, event_type, data->args, data->numargs, data->log);
}

/*
 *
 * Function: RealAlertCSV(Packet *, char *, FILE *, char *, numargs const int)
 *
 * Purpose: Write a user defined CSV message
 *
 * Arguments:     p => packet. (could be NULL)
 *              msg => the message to send
 *             args => CSV output arguements
 *          numargs => number of arguements
 *             log => Log
 * Returns: void function
 *
 */
static void RealAlertCSV(Packet * p, void *event, uint32_t event_type,
        char **args, int numargs, TextLog* log)
{
    int num;
    SigNode             *sn;
    char *type;
    char tcpFlags[9];

    if(p == NULL)
        return;

    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Logging CSV Alert data\n"););

    for (num = 0; num < numargs; num++)
    {
        type = args[num];

        DEBUG_WRAP(DebugMessage(DEBUG_LOG, "CSV Got type %s %d\n", type, num););

        if(!strncasecmp("timestamp", type, 9))
        {
            LogTimeStamp(log, p);
        }
        else if(!strncasecmp("sig_generator",type,13))
        {
            if(event != NULL)
            {
                TextLog_Print(log, "%lu",
                    (unsigned long) ntohl(((Unified2EventCommon *)event)->generator_id));
            }
        }
        else if(!strncasecmp("sig_id",type,6))
        {
            if(event != NULL)
            {
                TextLog_Print(log, "%lu",
                    (unsigned long) ntohl(((Unified2EventCommon *)event)->signature_id));
            }
        }
        else if(!strncasecmp("sig_rev",type,7))
        {
            if(event != NULL)
            {
                TextLog_Print(log, "%lu",
                    (unsigned long) ntohl(((Unified2EventCommon *)event)->signature_revision));
            }
        }
        else if(!strncasecmp("msg", type, 3))
        {
            if ( event != NULL )
            {
                sn = GetSigByGidSid(ntohl(((Unified2EventCommon *)event)->generator_id),
				    ntohl(((Unified2EventCommon *)event)->signature_id),
				    ntohl(((Unified2EventCommon *)event)->signature_revision));

                if (sn != NULL)
                {
                    if ( !TextLog_Quote(log, sn->msg) )
                    {
                        FatalError("Not enough buffer space to escape msg string\n");
                    }
                }
            }
        }
        else if(!strncasecmp("proto", type, 5))
        {
            if(IPH_IS_VALID(p))
            {
                switch (GET_IPH_PROTO(p))
                {
                    case IPPROTO_UDP:
                        TextLog_Puts(log, "UDP");
                        break;
                    case IPPROTO_TCP:
                        TextLog_Puts(log, "TCP");
                        break;
                    case IPPROTO_ICMP:
                        TextLog_Puts(log, "ICMP");
                        break;
                }
            }
        }
        else if(!strncasecmp("ethsrc", type, 6))
        {
            if(p->eh)
            {
                TextLog_Print(log,  "%X:%X:%X:%X:%X:%X", p->eh->ether_src[0],
                    p->eh->ether_src[1], p->eh->ether_src[2], p->eh->ether_src[3],
                    p->eh->ether_src[4], p->eh->ether_src[5]);
            }
        }
        else if(!strncasecmp("ethdst", type, 6))
        {
            if(p->eh)
            {
                TextLog_Print(log,  "%X:%X:%X:%X:%X:%X", p->eh->ether_dst[0],
                p->eh->ether_dst[1], p->eh->ether_dst[2], p->eh->ether_dst[3],
                p->eh->ether_dst[4], p->eh->ether_dst[5]);
            }
        }
        else if(!strncasecmp("ethtype", type, 7))
        {
            if(p->eh)
            {
                TextLog_Print(log, "0x%X",ntohs(p->eh->ether_type));
            }
        }
        else if(!strncasecmp("udplength", type, 9))
        {
            if(p->udph)
                TextLog_Print(log, "%d",ntohs(p->udph->uh_len));
        }
        else if(!strncasecmp("ethlen", type, 6))
        {
            if(p->eh)
                TextLog_Print(log, "0x%X",p->pkth->len);
        }
#ifndef NO_NON_ETHER_DECODER
        else if(!strncasecmp("trheader", type, 8))
        {
            if(p->trh)
                LogTrHeader(log, p);
        }
#endif
        else if(!strncasecmp("srcport", type, 7))
        {
            if(IPH_IS_VALID(p))
            {
                switch(GET_IPH_PROTO(p))
                {
                    case IPPROTO_UDP:
                    case IPPROTO_TCP:
                        TextLog_Print(log,  "%d", p->sp);
                        break;
                }
            }
        }
        else if(!strncasecmp("dstport", type, 7))
        {
            if(IPH_IS_VALID(p))
            {
                switch(GET_IPH_PROTO(p))
                {
                    case IPPROTO_UDP:
                    case IPPROTO_TCP:
                        TextLog_Print(log,  "%d", p->dp);
                        break;
                }
            }
        }
        else if(!strncasecmp("src", type, 3))
        {
            if(IPH_IS_VALID(p))
                TextLog_Puts(log, inet_ntoa(GET_SRC_ADDR(p)));
        }
        else if(!strncasecmp("dst", type, 3))
        {
            if(IPH_IS_VALID(p))
                TextLog_Puts(log, inet_ntoa(GET_DST_ADDR(p)));
        }
        else if(!strncasecmp("icmptype",type,8))
        {
            if(p->icmph)
            {
            TextLog_Print(log, "%d",p->icmph->type);
            }
        }
        else if(!strncasecmp("icmpcode",type,8))
        {
            if(p->icmph)
            {
                TextLog_Print(log, "%d",p->icmph->code);
            }
        }
        else if(!strncasecmp("icmpid",type,6))
        {
            if(p->icmph)
                TextLog_Print(log, "%d",ntohs(p->icmph->s_icmp_id));
        }
        else if(!strncasecmp("icmpseq",type,7))
        {
            if(p->icmph)
                TextLog_Print(log, "%d",ntohs(p->icmph->s_icmp_seq));
        }
        else if(!strncasecmp("ttl",type,3))
        {
            if(IPH_IS_VALID(p))
            TextLog_Print(log, "%d",GET_IPH_TTL(p));
        }
        else if(!strncasecmp("tos",type,3))
        {
            if(IPH_IS_VALID(p))
            TextLog_Print(log, "%d",GET_IPH_TOS(p));
        }
        else if(!strncasecmp("id",type,2))
        {
            if(IPH_IS_VALID(p))
                TextLog_Print(log, "%u", IS_IP6(p) ? ntohl(GET_IPH_ID(p)) : ntohs((u_int16_t)GET_IPH_ID(p)));
        }
        else if(!strncasecmp("iplen",type,5))
        {
            if(IPH_IS_VALID(p))
            TextLog_Print(log, "%d",GET_IPH_LEN(p) << 2);
        }
        else if(!strncasecmp("dgmlen",type,6))
        {
            if(IPH_IS_VALID(p))
                // XXX might cause a bug when IPv6 is printed?
                TextLog_Print(log, "%d",ntohs(GET_IPH_LEN(p)));
        }
        else if(!strncasecmp("tcpseq",type,6))
        {
            if(p->tcph)
            TextLog_Print(log, "0x%lX",(u_long) ntohl(p->tcph->th_seq));
        }
        else if(!strncasecmp("tcpack",type,6))
            {
            if(p->tcph)
                TextLog_Print(log, "0x%lX",(u_long) ntohl(p->tcph->th_ack));
        }
        else if(!strncasecmp("tcplen",type,6))
        {
            if(p->tcph)
                TextLog_Print(log, "%d",TCP_OFFSET(p->tcph) << 2);
        }
        else if(!strncasecmp("tcpwindow",type,9))
        {
            if(p->tcph)
                TextLog_Print(log, "0x%X",ntohs(p->tcph->th_win));
        }
        else if(!strncasecmp("tcpflags",type,8))
        {
            if(p->tcph)
            {
                CreateTCPFlagString(p, tcpFlags);
                TextLog_Print(log, "%s", tcpFlags);
            }
        }

        DEBUG_WRAP(DebugMessage(DEBUG_LOG, "WOOT!\n"););

        if (num < numargs - 1)
            TextLog_Putc(log, ',');

    }
    TextLog_NewLine(log);
    TextLog_Flush(log);
}

