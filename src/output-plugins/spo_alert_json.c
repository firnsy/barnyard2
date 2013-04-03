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

/* spo_json
 *
 * Purpose:  output plugin for json alerting
 *
 * Arguments:  alert file (eventually)
 *
 * Effect:
 *
 * Alerts are written to a file in the snort json alert format
 *
 * Comments:   Allows use of json alerts with other output plugin types
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

#define DEFAULT_JSON "timestamp,sig_generator,sig_id,sig_rev,msg,proto,src,srcport,dst,dstport,ethsrc,ethdst,ethlen,tcpflags,tcpseq,tcpack,tcpln,tcpwindow,ttl,tos,id,dgmlen,iplen,icmptype,icmpcode,icmpid,icmpseq"

#define DEFAULT_FILE  "alert.json"
#define DEFAULT_LIMIT (128*M_BYTES)
#define LOG_BUFFER    (4*K_BYTES)

#define FIELD_NAME_VALUE_SEPARATOR ": "
#define JSON_FIELDS_SEPARATOR ","

#define JSON_TIMESTAMP_NAME "event_timestamp"
#define JSON_SIG_GENERATOR_NAME "sig_generator"
#define JSON_SIG_ID_NAME "sig_id"
#define JSON_SIG_REV_NAME "rev"
#define JSON_MSG_NAME "msg"
#define JSON_PROTO_NAME "proto"
#define JSON_ETHSRC_NAME "ethsrc"
#define JSON_ETHDST_NAME "ethdst"
#define JSON_ETHTYPE_NAME "ethtype"
#define JSON_UDPLENGTH_NAME "udplength"
#define JSON_ETHLENGTH_NAME "ethlength"
#define JSON_TRHEADER_NAME "trheader"
#define JSON_SRCPORT_NAME "secport"
#define JSON_DSTPORT_NAME "dstport"
#define JSON_SRC_NAME "src"
#define JSON_DST_NAME "dst"
#define JSON_ICMPTYPE_NAME "icmptype"
#define JSON_ICMPCODE_NAME "icmpcode"
#define JSON_ICMPID_NAME "icmpid"
#define JSON_ICMPSEQ_NAME "icmpseq"
#define JSON_TTL_NAME "ttl"
#define JSON_TOS_NAME "tos"
#define JSON_ID_NAME "id"
#define JSON_IPLEN_NAME "iplen"
#define JSON_DGMLEN_NAME "dgmlen"
#define JSON_TCPSEQ_NAME "tcpseq"
#define JSON_TCPACK_NAME "tcpack"
#define JSON_TCPLEN_NAME "tcplen"
#define JSON_TCPFLAGS_NAME "tcpflags"



typedef struct _AlertJSONConfig
{
    char *type;
    struct _AlertJSONConfig *next;
} AlertJSONConfig;

typedef struct _AlertJSONData
{
    TextLog* log;
    char * jsonargs;
    char ** args;
    int numargs;
    AlertJSONConfig *config;
} AlertJSONData;


/* list of function prototypes for this preprocessor */
static void AlertJSONInit(char *);
static AlertJSONData *AlertJSONParseArgs(char *);
static void AlertJSON(Packet *, void *, uint32_t, void *);
static void AlertJSONCleanExit(int, void *);
static void AlertRestart(int, void *);
static void RealAlertJSON(
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
    AlertJSONData *data;
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output: JSON Initialized\n"););

    /* parse the argument list from the rules file */
    data = AlertJSONParseArgs(args);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Linking JSON functions to call lists...\n"););

    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(AlertJSON, OUTPUT_TYPE__ALERT, data);
    AddFuncToCleanExitList(AlertJSONCleanExit, data);
    AddFuncToRestartList(AlertRestart, data);
}

/*
 * Function: ParseJSONArgs(char *)
 *
 * Purpose: Process positional args, if any.  Syntax is:
 * output alert_json: [<logpath> ["default"|<list> [<limit>]]]
 * list ::= <field>(,<field>)*
 * field ::= "dst"|"src"|"ttl" ...
 * limit ::= <number>('G'|'M'|K')
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 */
static AlertJSONData *AlertJSONParseArgs(char *args)
{
    char **toks;
    int num_toks;
    AlertJSONData *data;
    char* filename = NULL;
    unsigned long limit = DEFAULT_LIMIT;
    int i;

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "ParseJSONArgs: %s\n", args););
    data = (AlertJSONData *)SnortAlloc(sizeof(AlertJSONData));

    if ( !data )
    {
        FatalError("alert_json: unable to allocate memory!\n");
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
                data->jsonargs = strdup(DEFAULT_JSON);
                }
                else
                {
                data->jsonargs = strdup(toks[1]);
                }
                break;

            case 2:
                limit = strtol(tok, &end, 10);

                if ( tok == end )
                    FatalError("alert_json error in %s(%i): %s\n",
                        file_name, file_line, tok);

                if ( end && toupper(*end) == 'G' )
                    limit <<= 30; /* GB */

                else if ( end && toupper(*end) == 'M' )
                    limit <<= 20; /* MB */

                else if ( end && toupper(*end) == 'K' )
                    limit <<= 10; /* KB */
                break;

            case 3:
                FatalError("alert_json: error in %s(%i): %s\n",
                    file_name, file_line, tok);
                break;
        }
    }
    if ( !data->jsonargs ) data->jsonargs = strdup(DEFAULT_JSON);
    if ( !filename ) filename = ProcessFileOption(barnyard2_conf_for_parsing, DEFAULT_FILE);

    mSplitFree(&toks, num_toks);
    toks = mSplit(data->jsonargs, ",", 128, &num_toks, 0);

    data->args = toks;
    data->numargs = num_toks;

    DEBUG_WRAP(DebugMessage(
        DEBUG_INIT, "alert_json: '%s' '%s' %ld\n", filename, data->jsonargs, limit
    ););
    data->log = TextLog_Init(filename, LOG_BUFFER, limit);
    if ( filename ) free(filename);

    return data;
}

static void AlertJSONCleanup(int signal, void *arg, const char* msg)
{
    AlertJSONData *data = (AlertJSONData *)arg;
    /* close alert file */
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"%s\n", msg););

    if(data)
    {
        mSplitFree(&data->args, data->numargs);
        if (data->log) TextLog_Term(data->log);
        free(data->jsonargs);
        /* free memory from SpoJSONData */
        free(data);
    }
}

static void AlertJSONCleanExit(int signal, void *arg)
{
    AlertJSONCleanup(signal, arg, "AlertJSONCleanExit");
}

static void AlertRestart(int signal, void *arg)
{
    AlertJSONCleanup(signal, arg, "AlertRestart");
}


static void AlertJSON(Packet *p, void *event, uint32_t event_type, void *arg)
{
    AlertJSONData *data = (AlertJSONData *)arg;
    RealAlertJSON(p, event, event_type, data->args, data->numargs, data->log);
}

static bool PrintJSONFieldName(TextLog * log,const char *fieldName){
    bool aok = TextLog_Quote(log,fieldName);
    
    if(aok){
        TextLog_Puts(log,FIELD_NAME_VALUE_SEPARATOR);
    }
    return aok;
}

static bool LogJSON_i64(TextLog *log,const char *fieldName,uint64_t fieldValue){
    bool aok = PrintJSONFieldName(log,fieldName);
    if(aok)
        TextLog_Print(log,"%"PRIu64,fieldValue);
    return aok;
}

static bool LogJSON_a(TextLog *log,const char *fieldName,const char *fieldValue){
    return PrintJSONFieldName(log,fieldName) && TextLog_Quote(log,fieldValue);
}

/*
  * Function: RealAlertJSON(Packet *, char *, FILE *, char *, numargs const int)
 *
 * Purpose: Write a user defined JSON message
 *
 * Arguments:     p => packet. (could be NULL)
 *              msg => the message to send
 *             args => JSON output arguements
 *          numargs => number of arguements
 *             log => Log
 * Returns: void function
 *
 */
static void RealAlertJSON(Packet * p, void *event, uint32_t event_type,
        char **args, int numargs, TextLog* log)
{
    int num;
    SigNode             *sn;
    char *type;
    char tcpFlags[9];

    if(p == NULL)
        return;

    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Logging JSON Alert data\n"););

    TextLog_Putc(log,'{');
    for (num = 0; num < numargs; num++)
    {
        type = args[num];

        DEBUG_WRAP(DebugMessage(DEBUG_LOG, "JSON Got type %s %d\n", type, num););

        if(!strncasecmp("timestamp", type, 9))
        {
            //LogTimeStamp(log, p); // CVS log
            if(!LogJSON_i64(log,JSON_TIMESTAMP_NAME,p->pkth->ts.tv_sec*1000 + p->pkth->ts.tv_usec/1000))
                FatalError("Not enough buffer space to escape msg string\n");
            if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
        }
        else if(!strncasecmp("sig_generator ",type,13))
        {
            if(event != NULL)
            {
                //TextLog_Print(log, "%lu",
                //    (unsigned long) ntohl(((Unified2EventCommon *)event)->generator_id));
                if(!LogJSON_i64(log,JSON_SIG_GENERATOR_NAME,ntohl(((Unified2EventCommon *)event)->generator_id)))
                    FatalError("Not enough buffer space to escape msg string\n");
                if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
            }
        }
        else if(!strncasecmp("sig_id",type,6))
        {
            if(event != NULL)
            {
                //TextLog_Print(log, "%lu",
                //    (unsigned long) ntohl(((Unified2EventCommon *)event)->signature_id));
                if(!LogJSON_i64(log,JSON_SIG_ID_NAME,ntohl(((Unified2EventCommon *)event)->signature_id)))
                    FatalError("Not enough buffer space to escape msg string\n");
                if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
            }
        }
        else if(!strncasecmp("sig_rev",type,7))
        {
            if(event != NULL)
            {
                //TextLog_Print(log, "%lu",
                //    (unsigned long) ntohl(((Unified2EventCommon *)event)->signature_revision));
                if(!LogJSON_i64(log,JSON_SIG_REV_NAME,ntohl(((Unified2EventCommon *)event)->signature_revision)))
                    FatalError("Not enough buffer space to escape msg string\n");
                if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
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
                    if(!PrintJSONFieldName(log,JSON_MSG_NAME) && !TextLog_Quote(log, sn->msg) )
                    {
                        FatalError("Not enough buffer space to escape msg string\n");
                    }
                    if (num < numargs - 1)
                        TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
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
                        //TextLog_Puts(log, "UDP");
                        LogJSON_a(log,JSON_PROTO_NAME,"UDP");
                        break;
                    case IPPROTO_TCP:
                        //TextLog_Puts(log, "TCP");
                        LogJSON_a(log,JSON_PROTO_NAME,"TCP");
                        break;
                    case IPPROTO_ICMP:
                        //TextLog_Puts(log, "ICMP");
                        LogJSON_a(log,JSON_PROTO_NAME,"ICMP");
                        break;
                }
                if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
            }
        }
        else if(!strncasecmp("ethsrc", type, 6))
        {
            if(p->eh)
            {
                PrintJSONFieldName(log,JSON_ETHSRC_NAME);
                TextLog_Print(log,  "%X:%X:%X:%X:%X:%X", p->eh->ether_src[0],
                    p->eh->ether_src[1], p->eh->ether_src[2], p->eh->ether_src[3],
                    p->eh->ether_src[4], p->eh->ether_src[5]);
                if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
            }
        }
        else if(!strncasecmp("ethdst", type, 6))
        {
            if(p->eh)
            {
                PrintJSONFieldName(log,JSON_ETHDST_NAME);
                TextLog_Print(log,  "%X:%X:%X:%X:%X:%X", p->eh->ether_dst[0],
                p->eh->ether_dst[1], p->eh->ether_dst[2], p->eh->ether_dst[3],
                p->eh->ether_dst[4], p->eh->ether_dst[5]);
                if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
            }
        }
        else if(!strncasecmp("ethtype", type, 7))
        {
            if(p->eh)
            {
                PrintJSONFieldName(log,JSON_ETHTYPE_NAME);
                TextLog_Print(log, "0x%X",ntohs(p->eh->ether_type));
                if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
            }
        }
        else if(!strncasecmp("udplength", type, 9))
        {
            if(p->udph){
                PrintJSONFieldName(log,JSON_UDPLENGTH_NAME);
                TextLog_Print(log, "%d",ntohs(p->udph->uh_len));
                if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
            }
        }
        else if(!strncasecmp("ethlen", type, 6))
        {
            if(p->eh){
                PrintJSONFieldName(log,JSON_ETHLENGTH_NAME);
                TextLog_Print(log, "0x%X",p->pkth->len);
                if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
            }
        }
#ifndef NO_NON_ETHER_DECODER
        else if(!strncasecmp("trheader", type, 8))
        {
            if(p->trh){
                PrintJSONFieldName(log,JSON_TRHEADER_NAME);
                LogTrHeader(log, p);
                if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
            }
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
                        PrintJSONFieldName(log,JSON_SRCPORT_NAME);
                        TextLog_Print(log,  "%d", p->sp);
                        if (num < numargs - 1)
                            TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
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
                        PrintJSONFieldName(log,JSON_DSTPORT_NAME);
                        TextLog_Print(log,  "%d", p->dp);
                        if (num < numargs - 1)
                            TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
                        break;
                }
            }
        }
        else if(!strncasecmp("src", type, 3))
        {
            if(IPH_IS_VALID(p)){
                PrintJSONFieldName(log,JSON_SRC_NAME);
                TextLog_Puts(log, inet_ntoa(GET_SRC_ADDR(p)));
                if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
            }
        }
        else if(!strncasecmp("dst", type, 3))
        {
            if(IPH_IS_VALID(p)){
                PrintJSONFieldName(log,JSON_DST_NAME);
                TextLog_Puts(log, inet_ntoa(GET_DST_ADDR(p)));
                if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
            }
        }
        else if(!strncasecmp("icmptype",type,8))
        {
            if(p->icmph)
            {
                PrintJSONFieldName(log,JSON_ICMPTYPE_NAME);
                TextLog_Print(log, "%d",p->icmph->type);
                if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
            }
        }
        else if(!strncasecmp("icmpcode",type,8))
        {
            if(p->icmph)
            {
                PrintJSONFieldName(log,JSON_ICMPCODE_NAME);
                TextLog_Print(log, "%d",p->icmph->code);
                if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
            }
        }
        else if(!strncasecmp("icmpid",type,6))
        {
            if(p->icmph){
                PrintJSONFieldName(log,JSON_ICMPID_NAME);
                TextLog_Print(log, "%d",ntohs(p->icmph->s_icmp_id));
                if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
            }
        }
        else if(!strncasecmp("icmpseq",type,7))
        {
            if(p->icmph){
                PrintJSONFieldName(log,JSON_ICMPSEQ_NAME);
                TextLog_Print(log, "%d",ntohs(p->icmph->s_icmp_seq));
                if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
            }
        }
        else if(!strncasecmp("ttl",type,3))
        {
            if(IPH_IS_VALID(p)){
                PrintJSONFieldName(log,JSON_TTL_NAME);
                TextLog_Print(log, "%d",GET_IPH_TTL(p));
                if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
            }
        }
        else if(!strncasecmp("tos",type,3))
        {
            if(IPH_IS_VALID(p)){
                PrintJSONFieldName(log,JSON_TOS_NAME);
                TextLog_Print(log, "%d",GET_IPH_TOS(p));
                if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
            }
        }
        else if(!strncasecmp("id",type,2))
        {
            if(IPH_IS_VALID(p)){
                PrintJSONFieldName(log,JSON_ID_NAME);
                TextLog_Print(log, "%u", IS_IP6(p) ? ntohl(GET_IPH_ID(p)) : ntohs((u_int16_t)GET_IPH_ID(p)));
                if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
            }
        }
        else if(!strncasecmp("iplen",type,5))
        {
            if(IPH_IS_VALID(p)){
                PrintJSONFieldName(log,JSON_IPLEN_NAME);
                TextLog_Print(log, "%d",GET_IPH_LEN(p) << 2);
                if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
            }
        }
        else if(!strncasecmp("dgmlen",type,6))
        {
            if(IPH_IS_VALID(p)){
                PrintJSONFieldName(log,JSON_DGMLEN_NAME);
                // XXX might cause a bug when IPv6 is printed?
                TextLog_Print(log, "%d",ntohs(GET_IPH_LEN(p)));
                if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
            }
        }
        else if(!strncasecmp("tcpseq",type,6))
        {
            if(p->tcph){
                PrintJSONFieldName(log,JSON_TCPSEQ_NAME);
                TextLog_Print(log, "0x%lX",(u_long) ntohl(p->tcph->th_seq));
                if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
            }
        }
        else if(!strncasecmp("tcpack",type,6))
            {
            if(p->tcph){
                PrintJSONFieldName(log,JSON_TCPACK_NAME);
                TextLog_Print(log, "0x%lX",(u_long) ntohl(p->tcph->th_ack));
                if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
            }
        }
        else if(!strncasecmp("tcplen",type,6))
        {
            if(p->tcph){
                PrintJSONFieldName(log,JSON_TCPLEN_NAME);
                TextLog_Print(log, "%d",TCP_OFFSET(p->tcph) << 2);
                if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
            }
        }
        else if(!strncasecmp("tcpwindow",type,9))
        {
            if(p->tcph){
                PrintJSONFieldName(log,JSON_DST_NAME);
                TextLog_Print(log, "0x%X",ntohs(p->tcph->th_win));
                if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
            }
        }
        else if(!strncasecmp("tcpflags",type,8))
        {
            if(p->tcph)
            {
                CreateTCPFlagString(p, tcpFlags);
                PrintJSONFieldName(log,JSON_TCPFLAGS_NAME);
                TextLog_Print(log, "%s", tcpFlags);
                if (num < numargs - 1)
                    TextLog_Puts(log, JSON_FIELDS_SEPARATOR);
            }
        }

        DEBUG_WRAP(DebugMessage(DEBUG_LOG, "WOOT!\n"););

    }

    TextLog_Putc(log,'}');
    TextLog_NewLine(log); // Newline not needed.
    TextLog_Flush(log);
}

