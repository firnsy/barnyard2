/*
** Copyright (C) 2011 Tim Shelton
** Copyright (C) 2011 HAWK Network Defense, Inc. hawkdefense.com
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
** # syslog_full
** #-------------------------------
** # Available as both a log and alert output plugin.  Used to output data via TCP/UDP
** # HAWK Network Defense, Inc.
** # Arguments:
** #      sensor_name $sensor_name         - unique sensor name
** #      server $server                   - server the device will report to
** #      protocol $protocol               - protocol device will report over (tcp/udp)
** #      port $port                       - destination port device will report to (default: 514)
** #      detail $detail_threshold         - specify full/complete log reporting or only summaries.
** # output alert_syslog_full: sensor_name snortIds1-eth2, server dev.hawkdefense.com, protocol udp, port 514, detail full
** # output log_syslog_full: sensor_name snortIds1-eth2, server dev.hawkdefense.com, protocol udp, port 514, detail full
**
** #output alert_syslog_full: sensor_name snortIds1-eth2, server dev.hawkdefense.com, protocol udp,
** port 514, detail full
** output log_syslog_full: sensor_name snortIds1-eth2, server dev.hawkdefense.com, protocol udp, port 514, detail full
**
*/



/*  I N C L U D E S  *****************************************************/


#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "ConfigFile.h"
#include "mstring.h"
#include "sid.h"
#include "classification.h"
#include "util.h"
#include "input-plugins/dp_alert.h"
#include "input-plugins/dp_log.h"
#include "op_plugbase.h"
#include "op_decode.h"
#include "event.h"

#include <ctype.h>

typedef struct _OpSyslog_Data 
{
    char *server;
    char *sensor_name;
    struct sockaddr_in sockaddr;
    u_int32_t port;
    u_int16_t detail;
    u_int16_t proto;
    int socket;
    u_int32_t payload_length;
    char *payload;
} OpSyslog_Data;

#define MAX_QUERY_SIZE 4096

char *db_proto[] = {"udp", "tcp", NULL};

/* Output plugin API functions */
int OpSyslog_Setup(OutputPlugin *, char *args);
int OpSyslog(OutputPlugin *);
int OpSyslog_Start(OutputPlugin *, void *);
int OpSyslog_Stop(OutputPlugin *);
int OpSyslog_Log(void *, void *);
int OpSyslog_Alert(void *, void *);
int OpSyslog_Exit(OutputPlugin *outputPlugin);
int OpSyslog_LogConfig(OutputPlugin *outputPlugin);

/* Internal functions */
OpSyslog_Data *OpSyslog_ParseArgs(char *);
int NetClose(OpSyslog_Data *data);
int NetSend(OpSyslog_Data *data);
int NetConnect(OpSyslog_Data *data);

static int Syslog_FormatReference(OpSyslog_Data *data, ReferenceData *refer);
/* init routine makes this processor available for dataprocessor directives */
void OpSyslog_Init()
{
    OutputPlugin *outputPlugin;

    outputPlugin = RegisterOutputPlugin("alert_syslog_full", "alert");
    outputPlugin->setupFunc = OpSyslog_Setup;
    outputPlugin->exitFunc = OpSyslog_Exit;
    outputPlugin->startFunc = OpSyslog_Start;
    outputPlugin->stopFunc = OpSyslog_Stop;
    outputPlugin->outputFunc = OpSyslog_Alert;
    outputPlugin->logConfigFunc = OpSyslog_LogConfig;
    
    outputPlugin = RegisterOutputPlugin("log_syslog_full", "log");
    outputPlugin->setupFunc = OpSyslog_Setup;
    outputPlugin->exitFunc = OpSyslog_Exit;
    outputPlugin->startFunc = OpSyslog_Start;
    outputPlugin->stopFunc = OpSyslog_Stop;
    outputPlugin->outputFunc = OpSyslog_Log;
    outputPlugin->logConfigFunc = OpSyslog_LogConfig;
    
}


/* Setup the output plugin, process any arguments, link the functions to
 * the output functional node
 */
int OpSyslog_Setup(OutputPlugin *outputPlugin, char *args)
{
    /* setup the run time context for this output plugin */
    outputPlugin->data = OpSyslog_ParseArgs(args);

    return 0;
}

/* Inverse of the setup function, free memory allocated in Setup 
 * can't free the outputPlugin since it is also the list node itself
 */
int OpSyslog_Exit(OutputPlugin *outputPlugin)
{
    return 0;
}

int OpSyslog_LogConfig(OutputPlugin *outputPlugin)
{
    OpSyslog_Data *data = NULL;

    if(!outputPlugin || !outputPlugin->data)
        return -1;

    data = (OpSyslog_Data *)outputPlugin->data;

    LogMessage("OpSyslogFull configured\n");
    LogMessage("  Detail Level: %s\n", data->detail == 1 ? "Full" : "Fast");
    LogMessage("  Syslog Server: %s:%u\n", data->server, data->port);
    LogMessage("  Reporting Protocol: %s\n", db_proto[data->proto]);
    return 0;
}

/* 
 * this function gets called at start time, you should open any output files
 * or establish DB connections, etc, here
 */
int OpSyslog_Start(OutputPlugin *outputPlugin, void *spool_header)
{
    OpSyslog_Data *data = (OpSyslog_Data *)outputPlugin->data;

    if(data == NULL)
        FatalError("ERROR: Unable to find context for SyslogFull startup!\n");
    
    if(pv.verbose)
    {
        OpSyslog_LogConfig(outputPlugin);
    }
    
    
    if(NetConnect(data)) {
        LogMessage("OpSyslogFull: Failed to connect to host: [%s] %s:%u\n",
                db_proto[data->proto], data->server, data->port);
    	return 1;
    } 

    return 0;
}

int OpSyslog_Stop(OutputPlugin *outputPlugin)
{
    OpSyslog_Data *data = (OpSyslog_Data *)outputPlugin->data;

    if(data == NULL)
        FatalError("ERROR: Unable to find context for SyslogFull startup!\n");

    NetClose(data);
    free(data->server);
    free(data->sensor_name);
    
    return 0;
}


static int Syslog_FormatTriggerAlert(OpSyslog_Data *data, UnifiedAlertRecord *record) {

    char timestamp[TIMEBUF_SIZE];
    Sid *sid = NULL;
    ClassType *class_type = NULL;

    char pBuf[2050];
    char *sensor_name = "SNORTIDS";
    if(data->sensor_name) sensor_name = data->sensor_name;
    snprintf(pBuf,2048,"SNORTIDS[ALERT]: %s|", sensor_name);
    strncat(data->payload, pBuf,data->payload_length);

    ////////////////////////////////////////////////////////
    RenderTimestamp(record->ts.tv_sec, timestamp, TIMEBUF_SIZE);
    sid = GetSid(record->event.sig_generator, record->event.sig_id);
    if(sid == NULL)
        sid = FakeSid(record->event.sig_generator, record->event.sig_id);
    
    sid->rev = record->event.sig_rev;
    
    if(!(class_type = GetClassType(record->event.classification)) 
            && record->event.classification != 0)
    {
        LogMessage("WARNING: No ClassType found for classification '%i'\n",
                record->event.classification);
	return 1;
    }

 
    snprintf(pBuf,2048,"%s %u %s", timestamp, record->event.priority, sid != NULL ? sid->msg : "ALERT");
    strncat(data->payload, pBuf, data->payload_length);
    snprintf(pBuf,2048,"|%s|", class_type != NULL ? class_type->name : "Suspicious Activity");
    strncat(data->payload, pBuf, data->payload_length);
    Syslog_FormatReference(data, sid->ref);

    return 0;
}


static int Syslog_FormatTriggerLog(OpSyslog_Data *data, UnifiedLogRecord *record) {

    char timestamp[TIMEBUF_SIZE];
    Sid *sid = NULL;
    ClassType *class_type = NULL;

    char pBuf[2048];
    char *sensor_name = "SNORTIDS";
    if(data->sensor_name) sensor_name = data->sensor_name;
    snprintf(pBuf,2048,"SNORTIDS[LOG]: %s|", sensor_name);
    strncat(data->payload, pBuf,data->payload_length);

    RenderTimestamp(record->log.pkth.ts.tv_sec, timestamp, TIMEBUF_SIZE);
    sid = GetSid(record->log.event.sig_generator, record->log.event.sig_id);
    if(sid == NULL)
        sid = FakeSid(record->log.event.sig_generator, record->log.event.sig_id);
    
    sid->rev = record->log.event.sig_rev;
    
    if(!(class_type = GetClassType(record->log.event.classification)) 
            && record->log.event.classification != 0)
    {
        LogMessage("WARNING: No ClassType found for classification '%i'\n",
                record->log.event.classification);
	return 1;
    }

		    
    snprintf(pBuf,2048,"%s %u %s|%s|", timestamp, record->log.event.priority, sid != NULL ? sid->msg : "ALERT", class_type != NULL ? class_type->name : "Suspicious Activity");

    strncat(data->payload, pBuf, data->payload_length);

    Syslog_FormatReference(data, sid->ref);

    return 0;
}

static int Syslog_FormatReference(OpSyslog_Data *data, ReferenceData *refer) {

	ReferenceData *ref;

	ref = refer;

	/*
	while(ref) {

		fprintf(stderr,"System: %s ID:%s URL:%s\n", ref->system, ref->id, ref->url);
		ref = ref->next;
	}
	*/
    	//data->payload_length = strlen(data->payload) +strlen(hex_payload);
    	//data->payload = realloc(data->payload,data->payload_length+10);
    	//strncat(data->payload,hex_payload,data->payload_length);
	//
	
	return 0;

}

// this should be different for Alert messages
// than it is for Info/Log messages
static int Syslog_FormatIPHeaderAlert(OpSyslog_Data *data, UnifiedAlertRecord *record) {
    char pBuf[513];

    snprintf(pBuf,512,"%u,%u,%u|", record->sip, record->dip, record->protocol);
    strncat(data->payload, pBuf,data->payload_length);

    return 0;
}

static int Syslog_FormatIPHeaderLog(OpSyslog_Data *data, Packet *p) {

    char pBuf[1025];
    unsigned int s, d, proto, ver, hlen, tos, len, id, off, ttl, csum;

    s=d=proto=ver=hlen=tos=len=id=off=ttl=csum=0;

    if(p->iph) {
		if(p->iph->ip_src.s_addr)
			s = ntohl( p->iph->ip_src.s_addr);
		if(p->iph->ip_dst.s_addr)
			d = ntohl( p->iph->ip_dst.s_addr);
		if(p->iph->ip_proto)
			proto = p->iph->ip_proto;
		if(IP_VER(p->iph))
			ver = IP_VER(p->iph);
		if(IP_HLEN(p->iph))
			ver = IP_HLEN(p->iph);
		if(p->iph->ip_tos)
			tos = p->iph->ip_tos;
		if(p->iph->ip_len)
			len = ntohs(p->iph->ip_len);
		if(p->iph->ip_id)
			id = ntohs(p->iph->ip_id);
		if(p->iph->ip_off)
			off = (p->iph->ip_off);
		if(p->iph->ip_ttl)
			ttl = (p->iph->ip_ttl);
		if(p->iph->ip_csum)
			ttl = htons(p->iph->ip_csum);
    }

    snprintf(pBuf,1024,"%u, %u, %u, %u, %u, %u, %u, %u, %u, %u, "
                    "%u, %u|",
		    s, d, proto, ver, hlen, tos, len, id, 
#if defined(WORDS_BIGENDIAN)
                    ((off & 0xE000) >> 13),
                    htons(off & 0x1FFF),
#else
                    ((off & 0x00E0) >> 5),
                    htons(off & 0xFF1F), 
#endif
                   ttl,
                   csum);

    strncat(data->payload, pBuf, data->payload_length);

    return 0;
}

// need one for each ? alert : log
static int Syslog_FormatTCPHeaderAlert(OpSyslog_Data *data, UnifiedAlertRecord *record) {
    char pBuf[256];
    snprintf(pBuf,255,"%u,%u|", record->sp, record->dp);
    strncat(data->payload, pBuf,data->payload_length);

    return 0;
}

static int Syslog_FormatTCPHeaderLog(OpSyslog_Data *data, Packet *p) {
    char pBuf[1025];

	unsigned int th_win, th_sum, th_flags, th_ack, th_seq, th_urp, th_off, th_x2;

	th_win=th_sum=th_flags=th_ack=th_seq=th_urp=th_off=th_x2=0;

	if(p->tcph) {
		if(p->tcph->th_seq)
		th_seq = ntohl(p->tcph->th_seq);
		if(p->tcph->th_ack)
		th_ack = ntohl(p->tcph->th_ack);
		if(TCP_OFFSET(p->tcph))
		th_off = TCP_OFFSET(p->tcph);
		if(TCP_X2(p->tcph))
		th_x2 = TCP_X2(p->tcph);
		if(p->tcph->th_flags)
		th_flags = p->tcph->th_flags;
		if(p->tcph->th_win)
		th_win = ntohs(p->tcph->th_win);
		if(p->tcph->th_sum)
		th_sum =  ntohs(p->tcph->th_sum);
		if(p->tcph->th_urp)
		th_urp = ntohs(p->tcph->th_urp);
	}

    snprintf(pBuf,1024,"%u, %u, %u, %u, %u, %u, %u, %u, %u, %u|", p->sp, 
	p->dp, th_seq, th_ack, th_off, th_x2, th_flags, th_win, th_sum, th_urp);

    strncat(data->payload, pBuf,data->payload_length);

    return 0;
}

static int Syslog_FormatUDPHeaderAlert(OpSyslog_Data *data, UnifiedAlertRecord *record) {
    char pBuf[256];
    snprintf(pBuf,255,"%u,%u|", record->sp, record->dp);
    strncat(data->payload, pBuf,data->payload_length);

    return 0;
}

static int Syslog_FormatUDPHeaderLog(OpSyslog_Data *data, Packet *p) {
    char pBuf[1025];
    unsigned int uh_len=0, uh_chk=0;
    if(p->udph) {
	if(p->udph->uh_len)
		uh_len =  ntohs(p->udph->uh_len);
	if(p->udph->uh_chk)
		uh_chk =  ntohs(p->udph->uh_chk);
    }
    snprintf(pBuf,1024,
		    "%u, %u, %u, %u|",
		    p->sp, p->dp, uh_len, uh_chk);

    strncat(data->payload, pBuf,data->payload_length);

    return 0;
}

static int Syslog_FormatICMPHeaderAlert(OpSyslog_Data *data, UnifiedAlertRecord *record) {
    char pBuf[1025];
    snprintf(pBuf,1024,"%u,%u|", record->sp, record->dp);
    strncat(data->payload, pBuf,data->payload_length);

    return 0;
}

static int Syslog_FormatICMPHeaderLog(OpSyslog_Data *data, Packet *p) {
    char pBuf[1025];

    unsigned int type, code, csum, id, seq;
    type=code=csum=id=seq=0;

    if(p->icmph) {
	if(p->icmph->icmp_type)
		type = p->icmph->icmp_type;
    if(type == 0 || type == 8 ||
	type == 13 || type == 14 ||
	type == 15 || type == 16)
	{
		if(p->icmph->icmp_code)
			code = p->icmph->icmp_code;
		if(p->icmph->icmp_csum)
			csum = ntohs(p->icmph->icmp_csum);

		id =  htons(p->icmph->icmp_hun.ih_idseq.icd_id);
		seq = htons(p->icmph->icmp_hun.ih_idseq.icd_seq);

		snprintf(pBuf, 1024,"%u, %u, %u, %u, %u|",  type,
			code, csum,
			id, seq);
	} else {
		if(p->icmph->icmp_code)
			code = p->icmph->icmp_code;
		if(p->icmph->icmp_csum)
			csum = ntohs(p->icmph->icmp_csum);

		snprintf(pBuf, 1024,"%u, %u, %u|",  type, code, csum);
	}

    strncat(data->payload, pBuf,data->payload_length);

    }

    return 0;
}

static int Syslog_FormatPayload(OpSyslog_Data *data, Packet *p) {
    char *hex_payload;
    if(p->dsize > 0) {
	hex_payload = fasthex(p->data, p->dsize);
	// lets re-negotiate the size of our payload
    	data->payload_length = strlen(data->payload) +strlen(hex_payload);
    	data->payload = realloc(data->payload,data->payload_length+10);
    	strncat(data->payload,hex_payload,data->payload_length);
    }


    return 0;
}

//  We only report the data associated with an "Alert"
// 
// we plan to do the following: 
// 	connect to our remote host, exit on failure
// 	create our Syslog Alert message (format):
// 		SNORTIDS:#sensor_name#	#timestamp#	#signature#	#Class_Type#	#!!ip header!!#	#!!/tcp/udp/icmp header!!#	#payload#
// 	send our string over our socket using NetSocket
// 	close our socket and continue


int OpSyslog_Alert(void *context, void *data)
{
    UnifiedAlertRecord *record = (UnifiedAlertRecord *)data; 
    OpSyslog_Data *op_data = (OpSyslog_Data *)context;

    if(op_data->socket == -1) {
    if(NetConnect(op_data)) {
	    LogMessage("WARNING: Unable to connect to our syslog host: '%s:%u'\n", op_data->server, op_data->port);
	    return 1;
    }
    }
    
    // lets put together our payload query
    //
    op_data->payload = malloc(MAX_QUERY_SIZE+10);
    if(!op_data->payload)
	    return 1;

    op_data->payload_length = MAX_QUERY_SIZE;

    // lets start to build  our string
    if(Syslog_FormatTriggerAlert(op_data, record) ) {
	    LogMessage("WARNING: Unable to append Trigger header.\n");
	    free(op_data->payload);
	    return 1;
    }
    
    //
    if(Syslog_FormatIPHeaderAlert(op_data, record) ) {
	    LogMessage("WARNING: Unable to append Trigger header.\n");
	    free(op_data->payload);
	    return 1;
    }


    /* build the protocol specific header information */
    switch(record->protocol)
    {
        case IPPROTO_TCP:
		Syslog_FormatTCPHeaderAlert(data, record);
            break;
        case IPPROTO_UDP:
		Syslog_FormatUDPHeaderAlert(data, record);
            break;
        case IPPROTO_ICMP:
		Syslog_FormatICMPHeaderAlert(data, record);
            break;
    }


    // by here our msg is completed so lets debug/test its formatting
    // and lets send it to via our socket
    //
    
    strncat(op_data->payload, "\n",op_data->payload_length);

    if(NetSend(op_data)) {
            	LogMessage("WARNING: Unable to connect to our syslog host: '%s:%u'\n", op_data->server, op_data->port);
	        free(op_data->payload);
    		NetClose(op_data);
	        return 1;
    }

    free(op_data->payload);

    NetClose(data);

    return 0;
}

int OpSyslog_Log(void *context, void *data)
{
    UnifiedLogRecord *record = (UnifiedLogRecord *)data; 
    OpSyslog_Data *op_data = (OpSyslog_Data *)context;
    Packet p;


    if(op_data->socket == -1) {
    if(NetConnect(op_data)) {
	    LogMessage("WARNING: Unable to connect to our syslog host: '%s:%u'\n", op_data->server, op_data->port);
	    return 1;
    }
    }
    
    // lets put together our payload query
    //
    op_data->payload = malloc(MAX_QUERY_SIZE+10);
    if(!op_data->payload)
	    return 1;

    memset(op_data->payload,0x00, MAX_QUERY_SIZE+10); // null out our buffer

    op_data->payload_length = MAX_QUERY_SIZE;

    // lets start to build  our string
    if(Syslog_FormatTriggerLog(op_data, record) ) {
	    LogMessage("WARNING: Unable to append Trigger header.\n");
	    free(op_data->payload);
	    return 1;
    }
    
    /* decode the packet */
    if(DecodePacket(&p, &record->log.pkth, record->pkt + 2) == 0)
    {
        if(p.iph)
        {
    
	Syslog_FormatIPHeaderLog(op_data, &p);
	    // append ip data to our payload string

            //if(!(p.pkt_flags & PKT_FRAG_FLAG))
            {
		    
                switch(p.iph->ip_proto)
                {
                    case IPPROTO_ICMP:
                        Syslog_FormatICMPHeaderLog(op_data, &p);
                        break;
                    case IPPROTO_TCP:
                        Syslog_FormatTCPHeaderLog(op_data, &p);
                        break;
                    case IPPROTO_UDP:
                        Syslog_FormatUDPHeaderLog(op_data, &p);
                        break;
                }
		
            }

                Syslog_FormatPayload(op_data, &p);
        }
    }

    strncat(op_data->payload,"\n",op_data->payload_length);

    if(NetSend(op_data)) {
                LogMessage("WARNING: Unable to connect to our syslog host: '%s:%u'\n", op_data->server, op_data->port);
    		NetClose(op_data);
                free(op_data->payload);
                return 1;
    }

    free(op_data->payload);

    NetClose(op_data);

    return 0;
}


OpSyslog_Data *OpSyslog_ParseArgs(char *args)
{
    OpSyslog_Data *op_data;

    op_data = (OpSyslog_Data *)SafeAlloc(sizeof(OpSyslog_Data));

    // default syslog port
    op_data->port = 514;

    if(args != NULL)
    {
        char **toks;
        int num_toks;
        int i;
        /* parse out your args */
        toks = mSplit(args, ",", 31, &num_toks, '\\');
        for(i = 0; i < num_toks; ++i)
        {
            char **stoks;
            int num_stoks;
            char *index = toks[i];
            while(isspace((int)*index))
                ++index;
            stoks = mSplit(index, " ", 2, &num_stoks, 0);
            if(strcasecmp("port", stoks[0]) == 0)
            {
                if(num_stoks > 1 )
                    op_data->port = strtoul(stoks[1], NULL, 0);
                else
                    LogMessage("Argument Error in %s(%i): %s\n", file_name, 
                            file_line, index);
            }
            else if(strcasecmp("server", stoks[0]) == 0)
            {
                if(num_stoks > 1 && !op_data->server )
                    op_data->server = strdup(stoks[1]);
                else
                    LogMessage("Argument Error in %s(%i): %s\n", file_name, 
                            file_line, index);
            }
            else if(strcasecmp("sensor_name", stoks[0]) == 0)
	    {
		if(num_stoks > 1 && !op_data->sensor_name )
			op_data->sensor_name = strdup(stoks[1]);
		else
			LogMessage("Argument Error in %s(%i): %s\n", file_name,
				file_line, index);
	    }

            else if(strcasecmp("protocol", stoks[0]) == 0)
            {
                if(num_stoks > 1)
                {
                    if(strcasecmp("udp", stoks[1]) == 0)
                        op_data->proto = 0;
		    else
			op_data->proto = 1;
                }
                else 
                    LogMessage("Argument Error in %s(%i): %s\n", file_name, 
                            file_line, index);
            }
            else if(strcasecmp("detail", stoks[0]) == 0)
            {
                if(num_stoks > 1)
                {
                    if(strcasecmp("full", stoks[1]) == 0)
                        op_data->detail = 1;
                }
                else 
                    LogMessage("Argument Error in %s(%i): %s\n", file_name, 
                            file_line, index);
            }
            else
            {
                fprintf(stderr, "WARNING %s (%d) => Unrecognized argument for "
                        "SyslogFull plugin: %s\n", file_name, file_line, index);
            }
            FreeToks(stoks, num_stoks);
        }
        /* free your mSplit tokens */
        FreeToks(toks, num_toks);
    }

    /*
    if(!op_data->sensor_name)
	    FatalError("You must specify a sensor name\n");
    */

    return op_data;
}


int UDPConnect(OpSyslog_Data *op_data) {
	// IPPROTO_UDP , SOCK_DGRAM
	struct hostent *hostPtr;
	op_data->socket = socket(AF_INET, SOCK_DGRAM, 0);
	if(op_data->socket == -1) {
		LogMessage("Failed to create our socket");
		return 1;
	}
		

	if(!op_data->server)
		op_data->server = strdup("127.0.0.1");

	if (inet_aton(op_data->server,&op_data->sockaddr.sin_addr) != 1) {
		if ((hostPtr = gethostbyname(op_data->server)) == NULL) {
			LogMessage("could not resolve address[%s]",op_data->server);
			return 1;
		}

		memcpy(&op_data->sockaddr.sin_addr,hostPtr->h_addr,sizeof(op_data->sockaddr.sin_addr));
	}

	op_data->sockaddr.sin_port = htons(op_data->port);
	op_data->sockaddr.sin_family = AF_INET;

	if(connect(op_data->socket,  (struct sockaddr*)&op_data->sockaddr, sizeof(struct sockaddr)) == -1)  {
		// failed to connect to host
		close(op_data->socket);
		return 1;
	}


	return 0;

}

int TCPConnect(OpSyslog_Data *op_data) {
	// IPPROTO_TCP , SOCK_STREAM
	//
        struct hostent *hostPtr;
	int option=1;
	op_data->socket = socket(AF_INET, SOCK_STREAM, 0);
	if(op_data->socket == -1) {
		LogMessage("Failed to create our socket");
		return 1;
	}

	if(!op_data->server)
		op_data->server = strdup("127.0.0.1");

	if (inet_aton(op_data->server,&op_data->sockaddr.sin_addr) != 1) {
		if ((hostPtr = gethostbyname(op_data->server)) == NULL) {
			LogMessage("could not resolve address[%s]",op_data->server);
			return 1;
		}

		memcpy(&op_data->sockaddr.sin_addr,hostPtr->h_addr,sizeof(op_data->sockaddr.sin_addr));
	}

	op_data->sockaddr.sin_port = htons(op_data->port);
	op_data->sockaddr.sin_family = AF_INET;

	if(op_data->proto == 1) { // tcp!!
		setsockopt(op_data->socket,IPPROTO_TCP,TCP_NODELAY,  (char *)&option, sizeof(option));  // error checking
	}

	if(connect(op_data->socket,  (struct sockaddr*)&op_data->sockaddr, sizeof(struct sockaddr)) != 0)  {
	// failed to connect to host
		close(op_data->socket);
		return 1;
	}
	

	return 0;

}

int NetConnect(OpSyslog_Data *op_data)
{
    switch(op_data->proto)
    {
        case 0:
            return UDPConnect(op_data);
        case 1:
            return TCPConnect(op_data);
        default:
            FatalError("Protocol not supported\n");
            return 1;
    }
//    return 1;
}

int NetClose(OpSyslog_Data *op_data)
{

    int rval = close(op_data->socket);
    op_data->socket = -1;
    return rval;
}


int NetSend(OpSyslog_Data *data) {
// if failure lets try and auto-renegotiate teh connection
	switch(data->proto) {
		case 0: // UDP!!
			if(sendto(data->socket,data->payload, strlen(data->payload), 0 , (struct sockaddr *)&data->sockaddr, sizeof(struct sockaddr)) <= 0) {
				//perror("sendto");
				return 1;
			}
			break;

		case 1: // TCP!!
			if( send(data->socket, data->payload, strlen(data->payload), 0) <= 0) {
				//perror("send");
				return 1;
			}
			break;
	}
	return 0;
}

