/* 
** Copyright (C) 2008-2013 Ian Firns (SecurixLive) <dev@securixlive.com>
** Copyright (C) 2002-2005 Robert (Bamm) Visscher <bamm@sguil.net>
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
**
**
*/

/*
** Description:
**   A sguil output plugin. For further information regarding sguil see
** http://www.sguil.net
**
** TODO:
**   1. Test signal handling of sleep.
**   2. Convert noisy LogMessages to DEBUG_WRAP()
*/

/*
** INCLUDES
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>


#include "barnyard2.h"
#include "debug.h"
#include "decode.h"
#include "map.h"
#include "mstring.h"
#include "plugbase.h"
#include "strlcpyu.h"
#include "unified2.h"
#include "util.h"

/* Yeah TCL! */
#ifdef ENABLE_TCL
#include <tcl.h>
#endif

typedef struct _SpoSguilData
{
    char				*sensor_name;
    char				*tag_path;
    char				*passwd;
    u_int16_t			sensor_id;
    /** lowest event_id we submitted, but that wasn't confirmed yet,
     *  should only be lower than event_id_max on server timeouts. */
    u_int32_t			event_id_min;
    /** higest event_id sent to the server, normally we expect a confirm for
     *  this id. */
    u_int32_t			event_id_max;
    u_int16_t			agent_port;
    int					agent_sock;

	char				*args;
} SpoSguilData;

/* constants */
#define KEYWORD_AGENTPORT       "agent_port"
#define KEYWORD_SENSORNAME      "sensor_name"
#define KEYWORD_TAGPATH         "tag_path"
#define KEYWORD_PASSWORD        "passwd"

#define MAX_MSG_LEN             2048
#define TMP_BUFFER              128

/* output plug-in API functions */
void SguilInit(char *args);
void SguilInitFinalize(int unused, void *arg);

SpoSguilData *InitSguilData(char *);
void ParseSguilArgs(SpoSguilData *ssd_data);

void SguilCleanExitFunc(int, void *);
void SguilRestartFunc(int, void *);


/* internal sguil functions */
void Sguil(Packet *, void *, uint32_t, void *);

int SguilSensorAgentConnect(SpoSguilData *);
int SguilSensorAgentInit(SpoSguilData *);
int SguilRTEventMsg(SpoSguilData *, char *);
int SguilSendAgentMsg(SpoSguilData *, char *);
int SguilRecvAgentMsg(SpoSguilData *, char *);

char *SguilTimestamp(u_int32_t);

#ifdef ENABLE_TCL
int SguilAppendIPHdrDataEVT(Tcl_DString *, void *);
int SguilAppendIPHdrData(Tcl_DString *, Packet *);
int SguilAppendICMPData(Tcl_DString *, Packet *);
int SguilAppendTCPData(Tcl_DString *, Packet *);
int SguilAppendUDPData(Tcl_DString *, Packet *);
int SguilAppendPayloadData(Tcl_DString *, Packet *);
#endif

/* init routine makes this processor available for dataprocessor directives */
void SguilSetup()
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterOutputPlugin("sguil", OUTPUT_TYPE_FLAG__ALERT, SguilInit);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Output: Sguil is setup\n"););
}

void SguilInit(char *args)
{
	SpoSguilData		*ssd_data;

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Output: Sguil initialized\n"););

#ifndef ENABLE_TCL
    ErrorMessage("sguil: Tcl support is not compiled into this build of barnyard2\n\n");
    FatalError("If this build of barnyard was obtained as a binary distribution (e.g., rpm,\n"
               "or Windows), then check for alternate builds that contains the necessary Tcl\n"
               "support.\n\n"
               "If this build of barnyard was compiled by you, then re-run the ./configure\n"
               "script using the '--with-tcl' switch to specify the location of the\n"
			   "tclConfig.sh for your system.\n\n");
#endif

	/* parse the argument list from the rules file`*/
	ssd_data = InitSguilData(args);

	AddFuncToPostConfigList(SguilInitFinalize, ssd_data);
}

SpoSguilData *InitSguilData(char *args)
{
	SpoSguilData		*data;

	/* setup the internal structures and parse any arguments */
    data = (SpoSguilData *)SnortAlloc(sizeof(SpoSguilData));

	if (args == NULL)
	{
		ErrorMessage("sguil: you must supply arguments for sguil plugin\n");
		//PrintSguilUsage();
		FatalError("");
	}

	data->args = SnortStrdup(args);

	return data;
}

void SguilInitFinalize(int unused, void *arg)
{
	SpoSguilData		*ssd_data = (SpoSguilData *)arg;

	if (!ssd_data)
	{
		FatalError("sguil:  data uninitialized\n");
	}

	ParseSguilArgs(ssd_data);

    /* identify the sensor_name */
    if(ssd_data->sensor_name == NULL)
    {
		ssd_data->sensor_name = SnortStrdup(GetUniqueName(PRINT_INTERFACE(barnyard2_conf->interface)));
         if(ssd_data->sensor_name)
         {
            if( ssd_data->sensor_name[strlen(ssd_data->sensor_name)-1] == '\n' )
            {
                ssd_data->sensor_name[strlen(ssd_data->sensor_name)-1] = '\0';
            }
		 }
    }

	if (!BcLogQuiet())
    {
        LogMessage("sguil:  sensor name = %s\n", ssd_data->sensor_name);
        LogMessage("sguil:  agent port =  %u\n", ssd_data->agent_port);
    }

	/* connect to sensor_agent */
    SguilSensorAgentConnect(ssd_data);

    /* initialise the sensor agent - get sid and next cid */
    if(BcLogVerbose())
        LogMessage("sguil: Waiting for sid and cid from sensor_agent.\n");

    /* try to connect, if we are not getting retval 0 it timed out
     * so we try again, and again, and again... */
    do {
        if (SguilSensorAgentInit(ssd_data) == 0)
            break;
    } while (1);

    /* set the preprocessor function into the function list */
    AddFuncToOutputList(Sguil, OUTPUT_TYPE__ALERT, ssd_data);
    AddFuncToCleanExitList(SguilCleanExitFunc, ssd_data);
    AddFuncToRestartList(SguilRestartFunc, ssd_data);
}

void Sguil(Packet *p, void *event, uint32_t event_type, void *arg)
{
#ifdef ENABLE_TCL
    char				*timestamp_string;
    char				buffer[TMP_BUFFER];
	SpoSguilData		*data;
	SigNode				*sn = NULL;
    ClassType			*cn = NULL;
    Tcl_DString			list;

    memset(buffer, 0, TMP_BUFFER); /* bzero() deprecated, replaced by memset() */

	if ( event == NULL || arg == NULL )
	{
		return;
	}

    if(p != NULL)
    {
        if(p->ip6h != NULL)
        {
          LogMessage("[%s] Received a IPv6 Packets, ignoring \n",
                    __FUNCTION__);
          return;
        }
    }

    data = (SpoSguilData *)arg;

	/* grab the appropriate signature and classification information */
	sn = GetSigByGidSid(ntohl(((Unified2EventCommon *)event)->generator_id),
			    ntohl(((Unified2EventCommon *)event)->signature_id),
			    ntohl(((Unified2EventCommon *)event)->signature_revision));

	cn = ClassTypeLookupById(barnyard2_conf, ntohl(((Unified2EventCommon *)event)->classification_id));

    /* Here we build our RT event to send to sguild. The event is built with a
    ** proper tcl list format. 
    ** RT FORMAT:
    ** 
    **     0      1    2     3          4            5                  6                7
    ** {RTEVENT} {0} {sid} {cid} {sensor name} {snort event_id} {snort event_ref} {snort ref_time} 
    **
    **     8         9      10      11         12         13          14
    ** {sig_gen} {sig id} {rev} {message} {timestamp} {priority} {class_type} 
    **
    **      15            16           17           18           19       20        21
    ** {sip (dec)} {sip (string)} {dip (dec)} {dip (string)} {ip proto} {ip ver} {ip hlen}
    **
    **    22       23      24        25        26       27       28
    ** {ip tos} {ip len} {ip id} {ip flags} {ip off} {ip ttl} {ip csum}
    **
    **      29         30           31        32         33
    ** {icmp type} {icmp code} {icmp csum} {icmp id} {icmp seq}
    ** 
    **     34         35
    ** {src port} {dst port}
    **
    **     36        37        38        39        40         41        42          43
    ** {tcp seq} {tcp ack} {tcp off} {tcp res} {tcp flags} {tcp win} {tcp csum} {tcp urp}
    **
    **     44        45
    ** {udp len} {udp csum}
    **
    **      46
    ** {data payload}
    */

    Tcl_DStringInit(&list);

    /* RTEVENT */
    Tcl_DStringAppendElement(&list, "RTEVENT");

    /* Status - 0 */
    Tcl_DStringAppendElement(&list, "0");

    /* Sensor ID  (sid) */
    SnortSnprintf(buffer, TMP_BUFFER, "%u", data->sensor_id);
    Tcl_DStringAppendElement(&list, buffer);

    /* Event ID (cid) */
    SnortSnprintf(buffer, TMP_BUFFER, "%u", data->event_id_max);
    Tcl_DStringAppendElement(&list, buffer);

    /* Sensor Name */
    Tcl_DStringAppendElement(&list, data->sensor_name);

    /* Snort Event ID */
    SnortSnprintf(buffer, TMP_BUFFER, "%u",
			ntohl(((Unified2EventCommon *)event)->event_id));
    Tcl_DStringAppendElement(&list, buffer);

    /* Snort Event Ref */
    SnortSnprintf(buffer, TMP_BUFFER, "%u",
			ntohl(((Unified2EventCommon *)event)->event_id));
    Tcl_DStringAppendElement(&list, buffer);

    /* Snort Event Ref Time */
	timestamp_string = SguilTimestamp(ntohl(((Unified2EventCommon *)event)->event_second));

	if(ntohl(((Unified2EventCommon *)event)->event_second) == 0)
        Tcl_DStringAppendElement(&list, "");
    else
        Tcl_DStringAppendElement(&list, timestamp_string);

    /* Generator ID */
    SnortSnprintf(buffer, TMP_BUFFER, "%d",
			ntohl(((Unified2EventCommon *)event)->generator_id));
    Tcl_DStringAppendElement(&list, buffer);

    /* Signature ID */
    SnortSnprintf(buffer, TMP_BUFFER, "%d",
			ntohl(((Unified2EventCommon *)event)->signature_id));
    Tcl_DStringAppendElement(&list, buffer);

    /* Signature Revision */
    SnortSnprintf(buffer, TMP_BUFFER, "%d",
			ntohl(((Unified2EventCommon *)event)->signature_revision));
    Tcl_DStringAppendElement(&list, buffer);

    /* Signature Msg */
    Tcl_DStringAppendElement(&list, sn->msg);

    /* Packet Timestamp = Event Timestamp*/
    Tcl_DStringAppendElement(&list, timestamp_string);

    /* Alert Priority */
    SnortSnprintf(buffer, TMP_BUFFER, "%u",
			ntohl(((Unified2EventCommon *)event)->priority_id));
    Tcl_DStringAppendElement(&list, buffer);

    /* Alert Classification */
    if (cn == NULL)
        Tcl_DStringAppendElement(&list, "unknown");
    else
        Tcl_DStringAppendElement(&list, cn->type);

    /* Pull decoded info from the packet */
    if(p != NULL)
    {
        if(p->iph)
        {
            int i;

            /* add IP header */
            SguilAppendIPHdrData(&list, p);

            /* add ICMP || UDP || TCP data */
            if ( !(p->packet_flags & PKT_REBUILT_FRAG) )
            {
                switch(p->iph->ip_proto)
                {
                    case IPPROTO_ICMP:
                        SguilAppendICMPData(&list, p);
                        break;

                    case IPPROTO_TCP:
                        SguilAppendTCPData(&list, p);
                        break;

                    case IPPROTO_UDP:
                        SguilAppendUDPData(&list, p);
                        break;

                    default:
                        for(i = 0; i < 17; ++i)
                            Tcl_DStringAppendElement(&list, "");
                        break;
                }
            }
            else
            {
                /* null out TCP/UDP/ICMP fields */
                for(i = 0; i < 17; ++i)
                    Tcl_DStringAppendElement(&list, "");
            }
        }
        else
        {
            /* no IP Header. */
            int i;
            for(i = 0; i < 31; ++i)
                Tcl_DStringAppendElement(&list, "");
        }

        /* add payload data */
        SguilAppendPayloadData(&list, p);
    }
    else
    {
        /* ack! an event without a packet. Append IP data from event struct and append
        27 fillers */
        if ( (event_type == UNIFIED2_IDS_EVENT_VLAN)||
                (event_type == UNIFIED2_IDS_EVENT_MPLS) ||
                (event_type == UNIFIED2_IDS_EVENT_VLAN)){
            SguilAppendIPHdrDataEVT(&list, event);
            int i;
            for(i = 0; i < 27; ++i)
            Tcl_DStringAppendElement(&list, "");
        } else {
        /* ack! an event without a packet. and no IP Data in eventAppend 32 fillers */
            int i;
            for(i = 0; i < 32; ++i)
            Tcl_DStringAppendElement(&list, "");
        }

    }

    /* send msg to sensor_agent */
    if (SguilRTEventMsg(data, Tcl_DStringValue(&list)))
        FatalError("Unable to send RT Events to sensor agent.\n");

    /* free the mallocs! */
    Tcl_DStringFree(&list);
	free(timestamp_string);

    /* bump the event id */
    data->event_id_max++;
#endif
}

static unsigned int sguil_agent_setup_timeouts = 0;

int SguilRTEventMsg(SpoSguilData *data, char *msg)
{

    char tmpRecvMsg[MAX_MSG_LEN];

    /* Send Msg */
    SguilSendAgentMsg(data, msg);

    /* Get confirmation */
    memset(tmpRecvMsg, 0x0, MAX_MSG_LEN);
    if (SguilRecvAgentMsg(data, tmpRecvMsg) == 1)
    {
        if (BcLogVerbose())
            LogMessage("sguil: Retrying\n");

        SguilRTEventMsg(data, msg);
    }
    else
    {
        char **toks;
        int num_toks;

        if (BcLogVerbose())
            LogMessage("sguil: Received: %s", tmpRecvMsg);

        /* Parse the response */
        toks = mSplit(tmpRecvMsg, " ", 2, &num_toks, 0);

        /* if the agent registration timed out once or several times we can
         * receive unexpected SidCidResponse messages. */
        if (sguil_agent_setup_timeouts > 0 && strcasecmp("SidCidResponse", toks[0]) == 0)
        {
            sguil_agent_setup_timeouts--;

	    if (BcLogVerbose())
		    LogMessage("sguil: Ignored: %s", tmpRecvMsg);
        }
        else
        {
            int event_id = atoi(toks[1]);
            if (event_id < 0)
            {
                FatalError("sguil: Malformed response, expected \"Confirm %u\", got: %s\n",
                        data->event_id_max, tmpRecvMsg);
            }

            if(strcasecmp("Confirm", toks[0]) != 0) {

                if ((uint)event_id != data->event_id_max) {
                    if ((uint)event_id == data->event_id_min) {
                        if (BcLogVerbose())
                            LogMessage("sguil: processed delayed Confirm: %s", tmpRecvMsg);
                    }
                    else
                    {
                        FatalError("sguil: Expected Confirm %u and got: %s\n", data->event_id_max, tmpRecvMsg);
                    }
                }

                /* either we are in sync or the confirm we got confirmed
                 * event_id_min. Either way, we can increment it */
                data->event_id_min++;
            }
        }

        mSplitFree(&toks, num_toks);
    }

    return 0;
}

/*
 * Function: ParseSguilArgs(char *)
 *
 * Purpose: Process the preprocessor arguements from the rules file and 
 *          initialize the preprocessor's data struct.  This function doesn't
 *          have to exist if it makes sense to parse the args in the init 
 *          function.
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 *
 */
void ParseSguilArgs(SpoSguilData *ssd_data)
{
    char **toks;
    int num_toks;
    int i;

    if(ssd_data->args == NULL)
    {
		ErrorMessage("sguil: you must supply arguments for sguil plugin\n");
		//PrintSguilUsage();
		FatalError("");
	}

	/* initialise appropariate values to 0 */
	ssd_data->agent_port = 0;

    /* parse out your args */
    toks = mSplit(ssd_data->args, ", ", 31, &num_toks, '\\');

    for(i = 0; i < num_toks; ++i)
    {
        char **stoks;
        int num_stoks;
        char *index = toks[i];
        while(isspace((int)*index))
            ++index;

        stoks = mSplit(index, "=", 2, &num_stoks, 0);

        if ( !strncasecmp(stoks[0], KEYWORD_AGENTPORT, strlen(KEYWORD_AGENTPORT)) )
        {
            if(num_stoks > 1)
                ssd_data->agent_port = atoi(stoks[1]);
            else
                LogMessage("sguil: agent_port error\n");
        }
        else if ( !strncasecmp(stoks[0], KEYWORD_TAGPATH, strlen(KEYWORD_TAGPATH)) )
        {
            if(num_stoks > 1 && ssd_data->tag_path == NULL)
                ssd_data->tag_path = SnortStrdup(stoks[1]);
            else
                LogMessage("sguil: tag_path error\n");
        }
        else if ( !strncasecmp(stoks[0], KEYWORD_SENSORNAME, strlen(KEYWORD_SENSORNAME)) )
        {
            if(num_stoks > 1 && ssd_data->sensor_name == NULL)
                ssd_data->sensor_name = SnortStrdup(stoks[1]);
            else
                LogMessage("sguil: sensor_name error\n");
		}
        else if ( !strncasecmp(stoks[0], KEYWORD_PASSWORD, strlen(KEYWORD_PASSWORD)) )
        {
            if(num_stoks > 1 && ssd_data->passwd == NULL)
                ssd_data->passwd = SnortStrdup(stoks[1]);
            else
                LogMessage("sguil: passwd error\n");
        }
        else
        {
			LogMessage("sguil: unrecognised argument = %s\n", index);
		}

		/* free your mSplit tokens */
        mSplitFree(&stoks, num_stoks);
    }

    /* free your mSplit tokens */
    mSplitFree(&toks, num_toks);

	/* identify the agent_port */
	if (ssd_data->agent_port == 0)
		ssd_data->agent_port = 7735;
}

#ifdef ENABLE_TCL
int SguilAppendIPHdrDataEVT(Tcl_DString *list, void *event)
{
    char buffer[TMP_BUFFER];

    memset(buffer, 0, TMP_BUFFER); /* bzero() deprecated, replaced by memset() */

    SnortSnprintf(buffer, TMP_BUFFER, "%u", ntohl(((Unified2IDSEvent *)event)->ip_source));
    Tcl_DStringAppendElement(list, buffer);
#if defined(WORDS_BIGENDIAN)
    SnortSnprintf(buffer, TMP_BUFFER, "%u.%u.%u.%u",
           (((Unified2IDSEvent *)event)->ip_source & 0xff000000) >> 24,
           (((Unified2IDSEvent *)event)->ip_source & 0x00ff0000) >> 16,
           (((Unified2IDSEvent *)event)->ip_source & 0x0000ff00) >> 8,
           (((Unified2IDSEvent *)event)->ip_source & 0x000000ff));
#else
    SnortSnprintf(buffer, TMP_BUFFER, "%u.%u.%u.%u",
           (((Unified2IDSEvent *)event)->ip_source & 0x000000ff),
           (((Unified2IDSEvent *)event)->ip_source & 0x0000ff00) >> 8,
           (((Unified2IDSEvent *)event)->ip_source & 0x00ff0000) >> 16,
           (((Unified2IDSEvent *)event)->ip_source & 0xff000000) >> 24);
#endif
    Tcl_DStringAppendElement(list, buffer);
    SnortSnprintf(buffer, TMP_BUFFER, "%u", ntohl(((Unified2IDSEvent *)event)->ip_destination));
    Tcl_DStringAppendElement(list, buffer);
#if defined(WORDS_BIGENDIAN)
    SnortSnprintf(buffer, TMP_BUFFER, "%u.%u.%u.%u",
           (((Unified2IDSEvent *)event)->ip_destination & 0xff000000) >> 24,
           (((Unified2IDSEvent *)event)->ip_destination & 0x00ff0000) >> 16,
           (((Unified2IDSEvent *)event)->ip_destination & 0x0000ff00) >> 8,
           (((Unified2IDSEvent *)event)->ip_destination & 0x000000ff));
#else
    SnortSnprintf(buffer, TMP_BUFFER, "%u.%u.%u.%u",
           (((Unified2IDSEvent *)event)->ip_destination & 0x000000ff),
           (((Unified2IDSEvent *)event)->ip_destination & 0x0000ff00) >> 8,
           (((Unified2IDSEvent *)event)->ip_destination & 0x00ff0000) >> 16,
           (((Unified2IDSEvent *)event)->ip_destination & 0xff000000) >> 24);
#endif
    Tcl_DStringAppendElement(list, buffer);
    SnortSnprintf(buffer, TMP_BUFFER, "%u", ((Unified2IDSEvent *)event)->protocol);
    Tcl_DStringAppendElement(list, buffer);

    return 0;
}
#endif

#ifdef ENABLE_TCL
int SguilAppendIPHdrData(Tcl_DString *list, Packet *p)
{
    char buffer[TMP_BUFFER];

    memset(buffer, 0, TMP_BUFFER); /* bzero() deprecated, replaced by memset() */

    SnortSnprintf(buffer, TMP_BUFFER, "%u", ntohl(p->iph->ip_src.s_addr));
    Tcl_DStringAppendElement(list, buffer);
#if defined(WORDS_BIGENDIAN)
    SnortSnprintf(buffer, TMP_BUFFER, "%u.%u.%u.%u",
           (p->iph->ip_src.s_addr & 0xff000000) >> 24,
           (p->iph->ip_src.s_addr & 0x00ff0000) >> 16,
           (p->iph->ip_src.s_addr & 0x0000ff00) >> 8,
           (p->iph->ip_src.s_addr & 0x000000ff));
#else
    SnortSnprintf(buffer, TMP_BUFFER, "%u.%u.%u.%u",
           (p->iph->ip_src.s_addr & 0x000000ff),
           (p->iph->ip_src.s_addr & 0x0000ff00) >> 8,
           (p->iph->ip_src.s_addr & 0x00ff0000) >> 16,
           (p->iph->ip_src.s_addr & 0xff000000) >> 24);
#endif
    Tcl_DStringAppendElement(list, buffer);
    SnortSnprintf(buffer, TMP_BUFFER, "%u", ntohl(p->iph->ip_dst.s_addr));
    Tcl_DStringAppendElement(list, buffer);
#if defined(WORDS_BIGENDIAN)
    SnortSnprintf(buffer, TMP_BUFFER, "%u.%u.%u.%u",
           (p->iph->ip_dst.s_addr & 0xff000000) >> 24,
           (p->iph->ip_dst.s_addr & 0x00ff0000) >> 16,
           (p->iph->ip_dst.s_addr & 0x0000ff00) >> 8,
           (p->iph->ip_dst.s_addr & 0x000000ff));
#else
    SnortSnprintf(buffer, TMP_BUFFER, "%u.%u.%u.%u",
           (p->iph->ip_dst.s_addr & 0x000000ff),
           (p->iph->ip_dst.s_addr & 0x0000ff00) >> 8,
           (p->iph->ip_dst.s_addr & 0x00ff0000) >> 16,
           (p->iph->ip_dst.s_addr & 0xff000000) >> 24);
#endif
    Tcl_DStringAppendElement(list, buffer);
    SnortSnprintf(buffer, TMP_BUFFER, "%u", p->iph->ip_proto);
    Tcl_DStringAppendElement(list, buffer);
    SnortSnprintf(buffer, TMP_BUFFER, "%u", IP_VER(p->iph));
    Tcl_DStringAppendElement(list, buffer);
    SnortSnprintf(buffer, TMP_BUFFER, "%u", IP_HLEN(p->iph));
    Tcl_DStringAppendElement(list, buffer);
    SnortSnprintf(buffer, TMP_BUFFER, "%u", p->iph->ip_tos);
    Tcl_DStringAppendElement(list, buffer);
    SnortSnprintf(buffer, TMP_BUFFER, "%u", ntohs(p->iph->ip_len));
    Tcl_DStringAppendElement(list, buffer);
    SnortSnprintf(buffer, TMP_BUFFER, "%u", ntohs(p->iph->ip_id));
    Tcl_DStringAppendElement(list, buffer);

#if defined(WORDS_BIGENDIAN)
    SnortSnprintf(buffer, TMP_BUFFER, "%u", ((p->iph->ip_off & 0xE000) >> 13));
    Tcl_DStringAppendElement(list, buffer);
    SnortSnprintf(buffer, TMP_BUFFER, "%u", htons(p->iph->ip_off & 0x1FFF));
    Tcl_DStringAppendElement(list, buffer);
#else
    SnortSnprintf(buffer, TMP_BUFFER, "%u", ((p->iph->ip_off & 0x00E0) >> 5));
    Tcl_DStringAppendElement(list, buffer);
    SnortSnprintf(buffer, TMP_BUFFER, "%u", htons(p->iph->ip_off & 0xFF1F));
    Tcl_DStringAppendElement(list, buffer);
#endif

    SnortSnprintf(buffer, TMP_BUFFER, "%u", p->iph->ip_ttl);
    Tcl_DStringAppendElement(list, buffer);
    SnortSnprintf(buffer, TMP_BUFFER, "%u", htons(p->iph->ip_csum));
    Tcl_DStringAppendElement(list, buffer);

    return 0;
}
#endif

#ifdef ENABLE_TCL
int SguilAppendICMPData(Tcl_DString *list, Packet *p)
{

    int i;
    char buffer[TMP_BUFFER];

    memset(buffer, 0, TMP_BUFFER); /* bzero() deprecated, replaced by memset() */

    if (!p->icmph)
    {

        /* Null out ICMP fields */
        for(i=0; i < 5; i++)
            Tcl_DStringAppendElement(list, "");

    }
    else
    {

        /* ICMP type */
        SnortSnprintf(buffer, TMP_BUFFER, "%u", p->icmph->type);
        Tcl_DStringAppendElement(list, buffer);

        /* ICMP code */
        SnortSnprintf(buffer, TMP_BUFFER, "%u", p->icmph->code);
        Tcl_DStringAppendElement(list, buffer);

        /* ICMP CSUM */
        SnortSnprintf(buffer, TMP_BUFFER, "%u", ntohs(p->icmph->csum));
        Tcl_DStringAppendElement(list, buffer);

        /* Append other ICMP data if we have it */
        if (p->icmph->type == ICMP_ECHOREPLY ||
                p->icmph->type == ICMP_ECHO ||
                p->icmph->type == ICMP_TIMESTAMP ||
                p->icmph->type == ICMP_TIMESTAMPREPLY ||
                p->icmph->type == ICMP_INFO_REQUEST ||
                p->icmph->type == ICMP_INFO_REPLY)
        {

            /* ICMP ID */
            SnortSnprintf(buffer, TMP_BUFFER, "%u", htons(p->icmph->icmp_hun.idseq.id));
            Tcl_DStringAppendElement(list, buffer);

            /* ICMP Seq */
            SnortSnprintf(buffer, TMP_BUFFER, "%u", htons(p->icmph->icmp_hun.idseq.seq));
            Tcl_DStringAppendElement(list, buffer);

        }
        else
        {

            /* Add two empty elements */
            for(i=0; i < 2; i++)
                Tcl_DStringAppendElement(list, "");

        }

    }

    /* blank out 12 elements */
    for(i = 0; i < 12; i++)
        Tcl_DStringAppendElement(list, "");

    return 0;

}
#endif

#ifdef ENABLE_TCL
int SguilAppendTCPData(Tcl_DString *list, Packet *p)
{
    /*
    **     33        34        35        36        37         38        39          40
    ** {tcp seq} {tcp ack} {tcp off} {tcp res} {tcp flags} {tcp win} {tcp csum} {tcp urp}
    **
    */

    int i;
    char buffer[TMP_BUFFER];

    memset(buffer, 0, TMP_BUFFER); /* bzero() deprecated, replaced by memset() */

    /* empty elements for icmp data */
    for(i=0; i < 5; i++)
        Tcl_DStringAppendElement(list, "");

    if (!p->tcph)
    {
        /* Null out TCP fields */
        for(i=0; i < 10; i++)
            Tcl_DStringAppendElement(list, "");
    }
    else
    {
        SnortSnprintf(buffer, TMP_BUFFER, "%u", p->sp);
        Tcl_DStringAppendElement(list, buffer);

        SnortSnprintf(buffer, TMP_BUFFER, "%u", p->dp);
        Tcl_DStringAppendElement(list, buffer);

        SnortSnprintf(buffer, TMP_BUFFER, "%u", ntohl(p->tcph->th_seq));
        Tcl_DStringAppendElement(list, buffer);

        SnortSnprintf(buffer, TMP_BUFFER, "%u", ntohl(p->tcph->th_ack));
        Tcl_DStringAppendElement(list, buffer);

        SnortSnprintf(buffer, TMP_BUFFER, "%u", TCP_OFFSET(p->tcph));
        Tcl_DStringAppendElement(list, buffer);

        SnortSnprintf(buffer, TMP_BUFFER, "%u", TCP_X2(p->tcph));
        Tcl_DStringAppendElement(list, buffer);

        SnortSnprintf(buffer, TMP_BUFFER, "%u", p->tcph->th_flags);
        Tcl_DStringAppendElement(list, buffer);

        SnortSnprintf(buffer, TMP_BUFFER, "%u", ntohs(p->tcph->th_win));
        Tcl_DStringAppendElement(list, buffer);

        SnortSnprintf(buffer, TMP_BUFFER, "%u", ntohs(p->tcph->th_sum));
        Tcl_DStringAppendElement(list, buffer);

        SnortSnprintf(buffer, TMP_BUFFER, "%u", ntohs(p->tcph->th_urp));
        Tcl_DStringAppendElement(list, buffer);

    }

    /* empty elements for UDP data */
    for(i=0; i < 2; i++)
        Tcl_DStringAppendElement(list, "");

    return 0;

}
#endif

#ifdef ENABLE_TCL
int SguilAppendUDPData(Tcl_DString *list, Packet *p)
{

    int i;
    char buffer[TMP_BUFFER];

    memset(buffer, 0, TMP_BUFFER); /* bzero() deprecated, replaced by memset() */

    /* empty elements for ICMP data */
    for(i=0; i < 5; i++)
        Tcl_DStringAppendElement(list, "");

    if (!p->udph)
    {
        /* null out port info */
        for(i=0; i < 2; i++)
            Tcl_DStringAppendElement(list, "");
    }
    else
    {
        /* source and dst port */
        SnortSnprintf(buffer, TMP_BUFFER, "%u", p->sp);
        Tcl_DStringAppendElement(list, buffer);

        SnortSnprintf(buffer, TMP_BUFFER, "%u", p->dp);
        Tcl_DStringAppendElement(list, buffer);

    }

    /* empty elements for TCP data */
    for(i=0; i < 8; i++)
        Tcl_DStringAppendElement(list, "");

    if (!p->udph)
    {
        /* null out UDP info */
        for(i=0; i < 2; i++)
            Tcl_DStringAppendElement(list, "");
    }
    else
    {
        SnortSnprintf(buffer, TMP_BUFFER, "%u", ntohs(p->udph->uh_len));
        Tcl_DStringAppendElement(list, buffer);

        SnortSnprintf(buffer, TMP_BUFFER, "%u", ntohs(p->udph->uh_chk));
        Tcl_DStringAppendElement(list, buffer);
    }

    return 0;

}
#endif

#ifdef ENABLE_TCL
int SguilAppendPayloadData(Tcl_DString *list, Packet *p)
{
    char *hex_payload;

    if (p->dsize)
    {
        hex_payload = fasthex(p->data, p->dsize);
        Tcl_DStringAppendElement(list, hex_payload);
        free(hex_payload);
    } else {
        Tcl_DStringAppendElement(list, "");
    }

    return 0;
}
#endif

int SguilSensorAgentConnect(SpoSguilData *ssd_data)
{
    int					sockfd;
    struct sockaddr_in	my_addr;
	u_int8_t			tries = 4;

    /* loop listening for external signals */
	while (exit_signal == 0)
    {

        if ( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
        {
            FatalError("sguil:  Can't open a local socket.\n");
            return 1;
        }

        my_addr.sin_family = AF_INET;
        my_addr.sin_port = htons(ssd_data->agent_port);
        my_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        memset(&(my_addr.sin_zero), '\0', 8);

        if (connect(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) < 0)
        {
            LogMessage("sguil:  Can't connect to localhost on TCP port %u.\n",
                        ssd_data->agent_port);
            close(sockfd);

			/* only perform 4 tries when testing the configuration */
			if ((BcTestMode()) && (tries-- == 0))
			{
				FatalError("sguil:  Unable to connect after 4 attempts\n");
	        }

			LogMessage("sguil:  Waiting 15 secs to try again.\n");

			/* TODO: test inherent signal handling */
		    if (sleep(15))
			{
//			    LogMessage("sguil:  Received Kill Signal...\n");
//				CleanExit(0);
	        }
        }
        else
        {
            ssd_data->agent_sock = sockfd;
            LogMessage("sguil:  Connected to localhost on %u.\n",
                        ssd_data->agent_port);
            return 0;
        }
    }

	return 1;
}

/* Request sensor ID (sid) and next cid from sensor_agent
 * return 0 on success
 * return 1 on timeout
 */
int SguilSensorAgentInit(SpoSguilData *ssd_data)
{
    char tmpSendMsg[MAX_MSG_LEN];
    char tmpRecvMsg[MAX_MSG_LEN];

    /* Send our Request */
    snprintf(tmpSendMsg, MAX_MSG_LEN, "SidCidRequest %s", ssd_data->sensor_name);
    SguilSendAgentMsg(ssd_data, tmpSendMsg);

    /* Get the Results */
    memset(tmpRecvMsg,0x0,MAX_MSG_LEN);

    if ( SguilRecvAgentMsg(ssd_data, tmpRecvMsg) == 1 )
    {
        if (BcLogVerbose())
	        LogMessage("sguil: Agent registration timed out, retrying\n");

        sguil_agent_setup_timeouts++;

        /* timeout, resend */
        return 1;
    }
    else
    {
        char **toks;
        int num_toks;

        DEBUG_WRAP(DebugMessage(DEBUG_LOG, "sguil: received \"%s\"", tmpRecvMsg););

        /* parse the response */
        toks = mSplit(tmpRecvMsg, " ", 3, &num_toks, 0);

        if ( strcasecmp("SidCidResponse", toks[0]) == 0 )
        {
            ssd_data->sensor_id = atoi(toks[1]);
            ssd_data->event_id_min = ssd_data->event_id_max = atoi(toks[2]);
        }
        else
        {
            FatalError("sguil: Expected SidCidResponse and got '%s'\n", tmpRecvMsg);
        }

        mSplitFree(&toks, num_toks);

        if (BcLogVerbose())
	        LogMessage("sguil: sensor ID = %u\nsguil: last cid = %u\n",
					ssd_data->sensor_id, ssd_data->event_id_max);

        /* use the next event_id */
        ssd_data->event_id_min++;
        ssd_data->event_id_max++;
    }

    return 0;
}

int SguilSendAgentMsg(SpoSguilData *data, char *msg)
{
    int					schars;
    size_t				len;
    char				*tmpMsg;

    len = strlen(msg)+2;
    tmpMsg = SnortAlloc(len);
    snprintf(tmpMsg, len, "%s\n", msg);

    if ( (schars = send(data->agent_sock, tmpMsg, sizeof(char)*strlen(tmpMsg), 0)) < 0 )
    {
        if(BcLogVerbose())
		    LogMessage("sguil: Lost connection to sensor_agent.\n");

        /* resend our message */
        SguilSendAgentMsg(data, msg);
    }

    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "sguil: sending \"%s\"", tmpMsg););

    free(tmpMsg);

    return 0;
}

/**
 *  \brief Receive a message from the Sguil server
 *  \retval 1 on timeout
 */

/* I love google. http://pont.net/socket/prog/tcpServer.c */
int SguilRecvAgentMsg(SpoSguilData *ssd_data, char *line_to_return)
{
	static int			rcv_ptr = 0;
	static char			rcv_msg[MAX_MSG_LEN];
	static int			n;
	struct timeval		tv;
	fd_set				read_fds;
	int					offset;

	offset=0;

	/* wait up to 15 secs for our response */
	tv.tv_sec = 15;
	tv.tv_usec = 0;

	FD_ZERO(&read_fds);
	FD_SET(ssd_data->agent_sock, &read_fds);

    /* loop listening for external signals */
	while (exit_signal == 0)
	{

		/* wait for response from sguild */
		select(ssd_data->agent_sock+1, &read_fds, NULL, NULL, &tv);

		if ( !(FD_ISSET(ssd_data->agent_sock, &read_fds)) )
		{
			/* timed out */
			if (BcLogVerbose())
				LogMessage("sguil: Timed out waiting for response.\n");

			return 1;
		}
		else
		{
			if (rcv_ptr == 0)
			{
				memset(rcv_msg,0x0,MAX_MSG_LEN);
				n = recv(ssd_data->agent_sock, rcv_msg, MAX_MSG_LEN, 0);
				if (n < 0)
				{
					LogMessage("ERROR: Unable to read data.\n");

					/* reconnect to sensor_agent */
					SguilSensorAgentConnect(ssd_data);
				}
				else if (n == 0)
				{
					LogMessage("ERROR: Connecton closed by client\n");
					close(ssd_data->agent_sock);

					/* reconnect to sensor_agent */
					SguilSensorAgentConnect(ssd_data);
				}
			}

			/* if new data read on socket */
			/* OR */
			/* if another line is still in buffer */

			/* copy line into 'line_to_return' */
			while (*(rcv_msg+rcv_ptr) != 0x0A && rcv_ptr < n )
			{
				memcpy(line_to_return+offset,rcv_msg+rcv_ptr,1);
				offset++;
				rcv_ptr++;
			}

			/* end of line + end of buffer => return line */
			if (rcv_ptr == (n - 1))
			{
				/* set last byte to END_LINE */
				*(line_to_return + offset) = 0x0A;
				rcv_ptr = 0;

				return ++offset;
			}

			/* end of line but still some data in buffer => return line */
			if (rcv_ptr < (n - 1))
			{
				/* set last byte to END_LINE */
		        *(line_to_return+offset) = 0x0A;
			    rcv_ptr++;

				return ++offset;
			}

			/* end of buffer but line is not ended => */
			/*  wait for more data to arrive on socket */
			if (rcv_ptr == n)
			{
				rcv_ptr = 0;
			}
		}
	}

	return 0;
}

char *SguilTimestamp(u_int32_t sec)
{
    struct tm           *lt;  /* localtime */
    char                *buf;
    time_t              Time = sec;

    buf = (char *)SnortAlloc(TMP_BUFFER * sizeof(char));

	if (BcOutputUseUtc())
		lt = gmtime(&Time);
	else
		lt = localtime(&Time);

    SnortSnprintf(buf, TMP_BUFFER, "%04i-%02i-%02i %02i:%02i:%02i",
					1900 + lt->tm_year, lt->tm_mon + 1, lt->tm_mday,
					lt->tm_hour, lt->tm_min, lt->tm_sec);
  return buf;
}

void SguilCleanExitFunc(int signal, void *arg)
{
    SpoSguilData *ssd_data = (SpoSguilData *)arg;

    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"SguilCleanExitFunc\n"););

    /* free allocated memory from SpoSguilData */
	if (ssd_data)
	{

	    if(ssd_data->agent_sock > 0)
	    {
		close(ssd_data->agent_sock);
		ssd_data->agent_sock = -1;
	    }
	    
	    
	    if (ssd_data->sensor_name)
		free(ssd_data->sensor_name);
	    
	    if (ssd_data->tag_path)
		free(ssd_data->tag_path);
	    
	    if (ssd_data->passwd)
		free(ssd_data->passwd);
	    
	    if (ssd_data->args)
		free(ssd_data->args);
	    
	    free(ssd_data);
	}

}

void SguilRestartFunc(int signal, void *arg)
{
    SpoSguilData *ssd_data = (SpoSguilData *)arg;

    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"SguilCleanExitFunc\n"););

    /* free allocated memory from SpoSguilData */
	if (ssd_data)
	{

	    if(ssd_data->agent_sock > 0)
	    {
		close(ssd_data->agent_sock);
		ssd_data->agent_sock = -1;
	    }
	    
	    if (ssd_data->sensor_name)
		free(ssd_data->sensor_name);
	    
	    if (ssd_data->tag_path)
		free(ssd_data->tag_path);
	    
	    if (ssd_data->passwd)
		free(ssd_data->passwd);
	    
	    if (ssd_data->args)
		free(ssd_data->args);
	    
	    free(ssd_data);
	}
}


