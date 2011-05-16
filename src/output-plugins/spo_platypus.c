/*
** Copyright (C) 2008-2011 Ian Firns (SecurixLive) <dev@securixlive.com>
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

typedef struct _SpoPlatypusData
{
    char				*agent_name;
    u_int16_t			sensor_id;
    u_int16_t			agent_port;
    int					agent_sock;

    u_int32_t			event_id;

	char				*args;
} SpoPlatypusData;

/* constants */
#define KEYWORD_AGENTPORT 		"agent_port"
#define KEYWORD_AGENTNAME		"agent_name"

#define DEFAULT_AGENTPORT       7060

#define MAX_MSG_LEN				2048
#define TMP_BUFFER				128

/* output plug-in API functions */
void PlatypusInit(char *args);
void PlatypusInitFinalize(int unused, void *arg);

SpoPlatypusData *InitPlatypusData(char *);
void ParsePlatypusArgs(SpoPlatypusData *spd_data);

void PlatypusCleanExitFunc(int, void *);
void PlatypusRestartFunc(int, void *);


/* internal platypus functions */
void Platypus(Packet *, void *, u_int32_t, void *);

int PlatypusAgentConnect(SpoPlatypusData *);
int PlatypusAgentInit(SpoPlatypusData *);
int PlatypusAgentEventSend(SpoPlatypusData *, char *);
int PlatypusAgentSend(SpoPlatypusData *, char *);
int PlatypusAgentReceive();

char *PlatypusTimestamp(u_int32_t, u_int32_t);

int PlatypusEventIPHeaderDataAppend(char *, Packet *);
int PlatypusEventICMPDataAppend(char *, Packet *);
int PlatypusEventTCPDataAppend(char *, Packet *);
int PlatypusEventUDPDataAppend(char *, Packet *);

/* init routine makes this processor available for dataprocessor directives */
void PlatypusSetup()
{
    /* link the preprocessor keyword to the init function in
       the preproc list */
    RegisterOutputPlugin("platypus", OUTPUT_TYPE_FLAG__ALERT, PlatypusInit);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Output: Platypus is setup\n"););
}

void PlatypusInit(char *args)
{
	SpoPlatypusData		*spd_data;

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Output: Platypus initialized\n"););

	/* parse the argument list from the rules file`*/
	spd_data = InitPlatypusData(args);

	AddFuncToPostConfigList(PlatypusInitFinalize, spd_data);
}

SpoPlatypusData *InitPlatypusData(char *args)
{
	SpoPlatypusData		*data;

	/* setup the internal structures and parse any arguments */
    data = (SpoPlatypusData *)SnortAlloc(sizeof(SpoPlatypusData));

    /* store args for later parsing */
    if ( args != NULL )
    {
    	data->args = SnortStrdup(args);
    }
	
	return data;
}

void PlatypusInitFinalize(int unused, void *arg)
{
	SpoPlatypusData		*spd_data = (SpoPlatypusData *)arg;

	if (spd_data == NULL)
	{
		FatalError("platypus: data uninitialized\n");
	}

	ParsePlatypusArgs(spd_data);

    /* identify the agent_name */
    if(spd_data->agent_name == NULL)
    {
		spd_data->agent_name = SnortStrdup(GetUniqueName(PRINT_INTERFACE(barnyard2_conf->interface)));
    }

	if (!BcLogQuiet())
    {
        LogMessage("platypus: agent port = %u\n", spd_data->agent_port);
    }

	/* connect to the sensor agent (SnortAgent) */
    if (PlatypusAgentConnect(spd_data) == 0)
    {
        /* initialise the sensor agent - get sid/eid */
        if(BcLogVerbose())
            LogMessage("platypus: waiting for sid/eid from SnortAgent.\n");

        PlatypusAgentInit(spd_data);
    }
    else
    {
		FatalError("platypus: unable to connect to agent\n");
    }

    /* set the preprocessor function into the function list */
    AddFuncToOutputList(Platypus, OUTPUT_TYPE__ALERT, spd_data);
    AddFuncToCleanExitList(PlatypusCleanExitFunc, spd_data);
    AddFuncToRestartList(PlatypusRestartFunc, spd_data);
}

void Platypus(Packet *p, void *event, u_int32_t event_type, void *arg)
{
    char                *evt_msg;
    char                *data_msg;

    char                sip4[INET_ADDRSTRLEN];
    char                dip4[INET_ADDRSTRLEN];
    char                sip6[INET6_ADDRSTRLEN];
    char                dip6[INET6_ADDRSTRLEN];

	SpoPlatypusData		*data;
	SigNode				*sn = NULL;
    ClassType			*cn = NULL;

	if ( event == NULL || arg == NULL )
	{
		return;
	}

    if ( p != NULL && p->dsize > 0 )
    {
        evt_msg = SnortAlloc(sizeof(char) * ((p->dsize>>2)+MAX_MSG_LEN));
    }
    else
    {
        evt_msg = SnortAlloc(sizeof(char) * MAX_MSG_LEN);
    }

    data = (SpoPlatypusData *)arg;

	/* grab the appropriate signature and classification information */
	sn = GetSigByGidSid(ntohl(((Unified2EventCommon *)event)->generator_id),
						ntohl(((Unified2EventCommon *)event)->signature_id));
	cn = ClassTypeLookupById(barnyard2_conf, ntohl(((Unified2EventCommon *)event)->classification_id));

    /*
    ** 0       1   2   3         4         5       6      7       8        (9)
    ** BY2_EVT|SID|EID|SNORT EID|TIMESTAMP|SIG_GEN|SIG_ID|SIG_REV|SIG_MSG|
    **
    ** 9        10         11     12  13          14  15          16        (8)
    ** PRIORITY|CLASS TYPE|IP_VER|SIP|SPORT_ICODE|DIP|DPORT_ICODE|IP_PROTO|
    **
    ** 17     18      19     20     21    22       23     24     25       (9)
    ** IP_VER|IP_HLEN|IP_TOS|IP_LEN|IP_ID|IP_FLAGS|IP_OFF|IP_TTL|IP_CSUM|
    **
    ** 26        27      28        (3)
    ** ICMP_CSUM|ICMP_ID|ICMP_SEQ|
    **
    ** 29      30      31      32      33        34      35       36      (8)
    ** TCP_SEQ|TCP_ACK|TCP_OFF|TCP_RES|TCP_FLAGS|TCP_WIN|TCP_CSUM|TCP_URP
    **
    ** 37      38        (2)
    ** UDP_LEN|UDP_CSUM|
    **
    ** 39   (1)
    ** DATA
    */

    /* initialise the string */
    SnortSnprintf(evt_msg, MAX_MSG_LEN, "BY2_EVT|");

    /* sensor ID  (sid) */
    SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|", data->sensor_id);

    /* event ID (eid) */
    SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|", data->event_id);

    /* snort event ID */
    SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|",
            ntohl(((Unified2EventCommon *)event)->event_id));

    /* snort event reference time */
    SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%s|",
        PlatypusTimestamp(
            ntohl(((Unified2EventCommon *)event)->event_second),
            ntohl(((Unified2EventCommon *)event)->event_microsecond)
        )
    );

    /* generator ID */
    SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%d|",
			ntohl(((Unified2EventCommon *)event)->generator_id));

    /* signature ID */
    SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%d|",
			ntohl(((Unified2EventCommon *)event)->signature_id));

    /* signature revision */
    SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%d|",
			ntohl(((Unified2EventCommon *)event)->signature_revision));

    /* signature message */
    SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%s|", sn->msg);

    /* alert priority */
    SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|",
			ntohl(((Unified2EventCommon *)event)->priority_id));

    /* alert classification */
    SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%s|", cn != NULL ? cn->type : "unknown");

    /* IP version, addresses, ports and protocol */
    switch(event_type)
    {
        case UNIFIED2_IDS_EVENT:
        case UNIFIED2_IDS_EVENT_MPLS:
        case UNIFIED2_IDS_EVENT_VLAN:
            inet_ntop(AF_INET, &((Unified2IDSEvent*)event)->ip_source, sip4, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &((Unified2IDSEvent*)event)->ip_destination, dip4, INET_ADDRSTRLEN);

            SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "4|%s|%u|%s|%u|%u|",
                sip4,
                ntohs(((Unified2IDSEvent *)event)->sport_itype),
                dip4,
                ntohs(((Unified2IDSEvent *)event)->dport_icode),
                ((Unified2IDSEvent *)event)->protocol);
            break;
        case UNIFIED2_IDS_EVENT_IPV6:
        case UNIFIED2_IDS_EVENT_IPV6_MPLS:
        case UNIFIED2_IDS_EVENT_IPV6_VLAN:
            inet_ntop(AF_INET6, &((Unified2IDSEventIPv6 *)event)->ip_source, sip6, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &((Unified2IDSEventIPv6 *)event)->ip_destination, dip6, INET6_ADDRSTRLEN);

            SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "6|%s|%u|%s|%u|%u|",
                sip6,
                ntohs(((Unified2IDSEventIPv6 *)event)->sport_itype),
                dip6,
                ntohs(((Unified2IDSEventIPv6 *)event)->dport_icode),
                ((Unified2IDSEventIPv6 *)event)->protocol);
            break;
        default:
            printf("Type: %d\n", event_type);
            SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "0||||||");
            break;
    }

    /* pull decoded info from the packet */
    if (p != NULL)
    {
        if (p->iph)
        {
            /* IP version and protocol */
            SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|", IP_VER(p->iph));

            /* add IP header */
            PlatypusEventIPHeaderDataAppend(evt_msg, p);

            /* add ICMP || UDP || TCP data */
            if ( !(p->packet_flags & PKT_REBUILT_FRAG) )
            {
                switch(p->iph->ip_proto)
                {
                    case IPPROTO_ICMP:
                        PlatypusEventICMPDataAppend(evt_msg, p);
                        break;

                    case IPPROTO_TCP:
                        PlatypusEventTCPDataAppend(evt_msg, p);
                        break;

                    case IPPROTO_UDP:
                        PlatypusEventUDPDataAppend(evt_msg, p);
                        break;

                    default:
                        /* append 13 fillers */
                        SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "|||||||||||||");
                        break;
                }
            }
            else
            {
                /* null out TCP/UDP/ICMP fields */
                SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "|||||||||||||");
            }
        }
        else
        {
            /* no IP Header. */
            SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "||||||||||||||||||||||");
        }

        /* add payload data */
        if (p->dsize)
        {
            data_msg = fasthex(p->data, p->dsize);
            SnortSnprintfAppend(evt_msg, (p->dsize>>2)+MAX_MSG_LEN, "%s", data_msg);
            free(data_msg);
        }
    }
    else
    {
        /* ack! an event without a packet. Append 23 fillers */
        SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "||||||||||||||||||||||");
    }

    /* send msg to sensor_agent */
    if (PlatypusAgentEventSend(data, evt_msg))
        FatalError("platypus: unable to send real-time events to SnortAgent!\n");

    /* free the mallocs! */
    free(evt_msg);
}

int PlatypusAgentEventSend(SpoPlatypusData *data, char *msg)
{
    char rcv_msg[MAX_MSG_LEN];

    /* send the real-time event message */
    PlatypusAgentSend(data, msg);

    /* get the reply */
    memset(rcv_msg, 0x0, MAX_MSG_LEN);
    if(PlatypusAgentReceive(data, rcv_msg) == 1)
    {
        if(BcLogVerbose())
            LogMessage("platypus: retrying...\n");

        PlatypusAgentEventSend(data, msg);
    }
    else
    {
        char **toks;
        int num_toks;

        DEBUG_WRAP(DebugMessage(DEBUG_LOG,"platypus: received \"%s\"", rcv_msg););

        /* parse the reply */
        toks = mSplit(rcv_msg, "|", 2, &num_toks, 0);
        if( strncasecmp(toks[0], "BY2_EVT_CFM", 11) != 0 )
        {
            FatalError("platypus: expected BY2_EVT_CFM|%u and got: \"%s\"\n", data->event_id, rcv_msg);
        }
        else
        {
            if ( (num_toks == 2) && (atoi(toks[1]) != data->event_id) )
            {
                FatalError("platypus: expected BY2_EVT_CFM|%u and got: \"%s\" (%u)\n", data->event_id, rcv_msg, atoi(toks[1]));
            }
        }

        mSplitFree(&toks, num_toks);

        /* bump the event id on confirmation only */
        data->event_id++;
    }

    return 0;
}

int PlatypusEventIPHeaderDataAppend(char *evt_msg, Packet *p)
{
    SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|", IP_HLEN(p->iph));
    SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|", p->iph->ip_tos);
    SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|", ntohs(p->iph->ip_len));
    SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|", ntohs(p->iph->ip_id));

#if defined(WORDS_BIGENDIAN)
    SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|", ((p->iph->ip_off & 0xe000) >> 13));
    SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|", htons(p->iph->ip_off & 0x1fff));
#else
    SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|", ((p->iph->ip_off & 0x00e0) >> 5));
    SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|", htons(p->iph->ip_off & 0xff1f));
#endif

    SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|", p->iph->ip_ttl);
    SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|", htons(p->iph->ip_csum));

    return 0;
}

int PlatypusEventICMPDataAppend(char *evt_msg, Packet *p)
{
    if (!p->icmph)
    {
        /* null out ICMP fields */
        SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "|||");
    }
    else
    {
        /* ICMP checksum */
        SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|", ntohs(p->icmph->csum));

        /* Append other ICMP data if we have it */
        if ( p->icmph->type == ICMP_ECHOREPLY || p->icmph->type == ICMP_ECHO ||
             p->icmph->type == ICMP_TIMESTAMP || p->icmph->type == ICMP_TIMESTAMPREPLY ||
             p->icmph->type == ICMP_INFO_REQUEST || p->icmph->type == ICMP_INFO_REPLY )
        {
            /* ICMP ID */
            SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|", htonl(p->icmph->icmp_hun.idseq.id));

            /* ICMP sequence */
            SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|", htonl(p->icmph->icmp_hun.idseq.seq));
        }
        else
        {
            /* add two empty elements */
            SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "||");
        }
    }

    /* blank out TCP / UDP elements */
    SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "||||||||||");

    return 0;
}

int PlatypusEventTCPDataAppend(char *evt_msg, Packet *p)
{
    /* empty elements for icmp data */
    SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "|||");

    if (!p->tcph)
    {
        /* null out TCP fields */
        SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "||||||||");
    }
    else
    {
        SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|", ntohl(p->tcph->th_seq));
        SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|", ntohl(p->tcph->th_ack));
        SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|", TCP_OFFSET(p->tcph));
        SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|", TCP_X2(p->tcph));
        SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|", p->tcph->th_flags);
        SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|", ntohl(p->tcph->th_win));
        SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|", ntohl(p->tcph->th_sum));
        SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|", ntohl(p->tcph->th_urp));
    }

    /* empty elements for UDP data */
    SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "||");

    return 0;
}

int PlatypusEventUDPDataAppend(char *evt_msg, Packet *p)
{
    /* empty elements for ICMP data */
    SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "|||");

    /* empty elements for TCP data */
    SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "||||||||");

    if (!p->udph)
    {
        /* null out UDP info */
        SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "||");
    }
    else
    {
        SnortSnprintfAppend(evt_msg, MAX_MSG_LEN, "%u|%u|",
            ntohs(p->udph->uh_len),
            ntohs(p->udph->uh_chk));
    }

    return 0;
}

int PlatypusAgentConnect(SpoPlatypusData *spd_data)
{
    int					srv_sock;
    struct sockaddr_in	srv_saddr;
	u_int8_t			tries = 5;

    /* loop listening for external signals */
	while (exit_signal == 0)
    {

        if ( (srv_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
        {
            FatalError("platypus:  Can't open a local socket.\n");
            return 1;
        }

        srv_saddr.sin_family = AF_INET;
        srv_saddr.sin_port = htons(spd_data->agent_port);
        srv_saddr.sin_addr.s_addr = inet_addr("127.0.0.1");
        memset(&(srv_saddr.sin_zero), '\0', 8);

        if (connect(srv_sock, (struct sockaddr *)&srv_saddr, sizeof(struct sockaddr)) < 0)
        {
            LogMessage("platypus: can't connect to localhost:%u.\n",
                        spd_data->agent_port);
            close(srv_sock);

			/* only perform 4 tries when testing the configuration */
			if ((BcTestMode()) && (tries-- == 0))
			{
				FatalError("platypus: unable to connect after 5 attempts\n");
	        }

			LogMessage("platypus: will try again in 15 seconds.\n");

			/* sleep for allocated time before retrying */
		   sleep(15);
        }
        else
        {
            spd_data->agent_sock = srv_sock;
            LogMessage("platypus: connected to localhost:%u.\n",
                        spd_data->agent_port);
            return 0;
        }
    }

	return 1;
}

/* request sensor ID (sid) and last event ID (eid) from the server, via the SnortAgent */
int PlatypusAgentInit(SpoPlatypusData *spd_data)
{
    char snd_msg[MAX_MSG_LEN];
    char rcv_msg[MAX_MSG_LEN];

    /* send our request */
    SnortSnprintf(snd_msg, MAX_MSG_LEN, "BY2_SEID_REQ|%s", spd_data->agent_name);
    PlatypusAgentSend(spd_data, snd_msg);

    /* get the reply */
    memset(rcv_msg, 0x0, MAX_MSG_LEN);
    if ( PlatypusAgentReceive(spd_data, rcv_msg) == 1 )
    {
        PlatypusAgentInit(spd_data);
    }
    else
    {
        char			**toks;
        int				num_toks;

        DEBUG_WRAP(DebugMessage(DEBUG_LOG,"platypus: received \"%s\" (%d)\n", rcv_msg, strlen(rcv_msg)););

        /* check we actually received something */
        if ( strlen(rcv_msg) == 0 )
        {
            FatalError("platypus: expected BY2_SEID_RSP but got \"%s\"\n", rcv_msg);
        }

        /* parse the response */
        toks = mSplit(rcv_msg, "|", 3, &num_toks, 0);

        if ( strncasecmp("BY2_SEID_RSP", toks[0], 11) == 0 )
        {
            spd_data->sensor_id = atoi(toks[1]);
            spd_data->event_id = atoi(toks[2]);
        }
        else
        {
            FatalError("platypus: expected BY2_SEID_RSP but got \"%s\"\n", rcv_msg);
        }

        mSplitFree(&toks, num_toks);

        if (BcLogVerbose())
        {
	        LogMessage("platypus: sensor ID = %u\n", spd_data->sensor_id);
	        LogMessage("platypus: event ID  = %u\n", spd_data->event_id);
        }

        /* increment event ID */
        spd_data->event_id++;
    }

    return 0;
}

int PlatypusAgentSend(SpoPlatypusData *data, char *out)
{
    char				*snd_msg;
    size_t				snd_len;

    /* calculate length + 2 (ie. account for terminated \n and \0 */
    snd_len = strlen(out)+2;
    snd_msg = SnortAlloc(snd_len);
    SnortSnprintf(snd_msg, snd_len, "%s\n", out);

    if ( send(data->agent_sock, snd_msg, sizeof(char)*snd_len, 0) == -1 )
    {
        if(BcLogVerbose())
		    LogMessage("platypus: lost connection to SnortAgent.\n");

        /* free the buffer allocation */
        free(snd_msg);

        /* resend our message */
        PlatypusAgentSend(data, out);
    }

    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"platypus: sent \"%s\"\n", out););

    /* free the buffer allocation */
    free(snd_msg);

    return 0;
}

/* I love google. http://pont.net/socket/prog/tcpServer.c */
int PlatypusAgentReceive(SpoPlatypusData *spd_data, char *in)
{
	static int			rcv_idx = 0;	
	static char			rcv_msg[MAX_MSG_LEN];
	static int		    rcv_len;
	struct timeval		rcv_tv;
	fd_set				rcv_fds;
	int					in_off;

	in_off = 0;

	/* wait up to 15 secs for our response */
	rcv_tv.tv_sec = 15;
	rcv_tv.tv_usec = 0;

	FD_ZERO(&rcv_fds);
	FD_SET(spd_data->agent_sock, &rcv_fds);

    /* loop listening for external signals */
	while (exit_signal == 0)
	{
		/* wait for response from SnortAgent */
		select(spd_data->agent_sock+1, &rcv_fds, NULL, NULL, &rcv_tv);

		if ( !(FD_ISSET(spd_data->agent_sock, &rcv_fds)) )
		{
			/* timed out */
			if(BcLogVerbose())
				LogMessage("platypus: timed out waiting for response.\n");

			return 1;
		}
		else
		{
			if (rcv_idx == 0)
			{
				memset(rcv_msg, 0x0, MAX_MSG_LEN);
			    rcv_len = recv(spd_data->agent_sock, rcv_msg, MAX_MSG_LEN, 0);

				if (rcv_len < 0)
				{
					LogMessage("platypus: unable to read data!\n");

					/* reconnect to sensor_agent */
					PlatypusAgentConnect(spd_data);
				}
				else if (rcv_len == 0)
				{
					LogMessage("platypus: connecton closed by client!\n");
					close(spd_data->agent_sock);
			
					/* reconnect to sensor_agent */
					PlatypusAgentConnect(spd_data);
				}
			}

			/* copy line into 'in' */
			while( *(rcv_msg+rcv_idx) != 0x0a && rcv_idx < rcv_len )
			{
				memcpy(in+in_off, rcv_msg+rcv_idx, 1);
				in_off++;
				rcv_idx++;
			}

			/* we have reached the end of the line and the end of buffer, */
            /* return the line and reset the buffer index pointer */
			if (rcv_idx == rcv_len-1)
			{
				/* set last byte to END_LINE */
				*(in+in_off) = 0x0a;
				rcv_idx = 0;
			
				return ++in_off;
			}

			/* we have reached the end of line but still have some data in */
            /* buffer, return the line and increment the buffer index pointer */
			if (rcv_idx < rcv_len-1)
			{
				/* set last byte to END_LINE */
		        *(in+in_off) = 0x0a;
			    rcv_idx++;
	
				return ++in_off;
			}
	
			/* we have reached the end of buffer but the line has not ended, */
			/* wait for more data to arrive on socket */
			if (rcv_idx == rcv_len)
			{
				rcv_idx = 0;
			}
		}
	}

	return 0;
}

/*
 * Function: ParsePlatypusArgs(char *)
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
void ParsePlatypusArgs(SpoPlatypusData *spd_data)
{
    char **toks;
    int num_toks;
    int i;

	/* initialise appropariate values to defaults */
	spd_data->agent_port = DEFAULT_AGENTPORT;

    if(spd_data->args == NULL)
    {
		//FatalError("platypus: you must supply arguments for platypus plugin.\n");
        return;
	}

    /* parse out the args */
    toks = mSplit(spd_data->args, ", ", 31, &num_toks, '\\');

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
                spd_data->agent_port = atoi(stoks[1]);
            else
                LogMessage("platypus: agent_port error\n");
        }
        else if ( !strncasecmp(stoks[0], KEYWORD_AGENTNAME, strlen(KEYWORD_AGENTNAME)) )
        {
            if(num_stoks > 1 && spd_data->agent_name == NULL)
                spd_data->agent_name = SnortStrdup(stoks[1]);
            else
                LogMessage("platypus: agent_name error\n");
		}
        else
        {
			FatalError("platypus: unrecognised plugin argument \"%s\"!\n", index);
		}

		/* free your mSplit tokens */
        mSplitFree(&stoks, num_stoks);
    }

    /* free your mSplit tokens */
    mSplitFree(&toks, num_toks);
}

char *PlatypusTimestamp(u_int32_t sec, u_int32_t usec)
{
    struct tm           *lt;  /* localtime */
    char                *buf;
    time_t              Time = sec;

    buf = (char *)SnortAlloc(TMP_BUFFER * sizeof(char));

	if (BcOutputUseUtc())
		lt = gmtime(&Time);
	else
		lt = localtime(&Time);

    SnortSnprintf(buf, TMP_BUFFER, "%04i-%02i-%02i %02i:%02i:%02i.%06i",
					1900 + lt->tm_year, lt->tm_mon + 1, lt->tm_mday,
					lt->tm_hour, lt->tm_min, lt->tm_sec, usec);

    return buf;
}

void PlatypusClose(void *arg)
{
    SpoPlatypusData *spd_data = (SpoPlatypusData *)arg;

    /* free allocated memory from SpoPlatypusData */
	if (spd_data)
	{
		if (spd_data->agent_name)
			free(spd_data->agent_name);

		if (spd_data->args)
			free(spd_data->args);

		free(spd_data);
	}
}

void PlatypusCleanExitFunc(int signal, void *arg)
{
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"platypus: exiting...\n"););

    PlatypusClose(arg);
}

void PlatypusRestartFunc(int signal, void *arg)
{
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"platypus: restarting...\n"););

    PlatypusClose(arg);
}


