/*
** 2011 Modified and enchanced for barnyard2 by the Barnyard2 Team.
**
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
# syslog_full
#-------------------------------
# Available as both a log and alert output plugin.  Used to output data via TCP/UDP
# Arguments:
#      sensor_name $sensor_name         - unique sensor name
#      server $server                   - server the device will report to
#      protocol $protocol               - protocol device will report over (tcp/udp)
#      port $port                       - destination port device will report to (default: 514)
#      delimiters                       - define a character that will delimit message sections ex:  "|", will use | as message section delimiters. (default: |)
#      separators                       - define field separator included in each message ex: " " ,  will use space as field separator.             (default: [:space:])
# output alert_syslog_full: sensor_name snortIds1-eth2, server xxx.xxx.xxx.xxx, protocol udp, port 514
# output log_syslog_full: sensor_name snortIds1-eth2, server xxx.xxx.xxx.xxx, protocol udp, port 514
# output alert_syslog_full: sensor_name snortIds1-eth2, server xxx.xxx.xxx.xxx, protocol udp, port 514
# output log_syslog_full: sensor_name snortIds1-eth2, server xxx.xxx.xxx.xxx, protocol udp, port 514
*/

#include "output-plugins/spo_syslog_full.h"

/* Output plugin API functions */
static void OpSyslog_Exit(int signal,void *outputPlugin);
static void OpSyslog_Alert(Packet *, void *, uint32_t, void *);
static void OpSyslog_Log(Packet *, void *, uint32_t, void *);
static int OpSyslog_LogConfig(void *outputPlugin);
static void OpSyslog_InitLog(char *args);
static void OpSyslog_InitAlert(char *args);
static OpSyslog_Data *OpSyslog_ParseArgs(char *);

static int NetClose(OpSyslog_Data *data);
static int NetSend(OpSyslog_Data *data);
static int NetConnect(OpSyslog_Data *data);
static int NetTestSocket(OpSyslog_Data *op_data);

//CHECKME: -elz Need to investigate
//static int Syslog_FormatReference(OpSyslog_Data *data, ReferenceNode *refer);

extern Barnyard2Config *barnyard2_conf;

int SyslogLogContext;
char *db_proto[] = {"udp", "tcp", NULL};


/* Setup routine makes this processor available for dataprocessor directives */
void OpSyslog_Setup(void)
{
    RegisterOutputPlugin("alert_syslog_full", OUTPUT_TYPE_FLAG__ALERT, OpSyslog_InitAlert);
    RegisterOutputPlugin("log_syslog_full",  OUTPUT_TYPE_FLAG__LOG, OpSyslog_InitLog);
    return;
}

/* Log Init Context wrapping function */
void OpSyslog_InitLog(char *args)
{
    SyslogLogContext = OUTPUT_TYPE_FLAG__LOG;
    OpSyslog_Init(args);
    return;
}

/* Alert Init Context wrapping function */
void OpSyslog_InitAlert(char *args)
{
    SyslogLogContext = OUTPUT_TYPE_FLAG__ALERT;
    OpSyslog_Init(args);
    return;
}

/* 
 * init the output plugin, process any arguments, link the functions to
 * the output functional node
 */
void OpSyslog_Init(char *args)
{
    OpSyslog_Data *syslogContext;
    
    if( args == NULL)
    {
	/* For later use...
	   ErrorMessage("OpSyslog_Init(): Invoked with NULL arguments....\n");
	   return 1;
	*/
	
	FatalError("OpSyslog_Init(): Invoked with NULL arguments....\n");
    }
    
    if( (syslogContext = OpSyslog_ParseArgs(args)) == NULL)
    {
	FatalError("OpSyslog_Init(): Error parsing output plugin arguments, bailing.\n");
    }
    
    AddFuncToCleanExitList(OpSyslog_Exit,(void *)syslogContext);
    AddFuncToShutdownList(OpSyslog_Exit,(void *)syslogContext);
    
    switch(SyslogLogContext)
    {
	
    case OUTPUT_TYPE_FLAG__LOG:
	AddFuncToOutputList(OpSyslog_Log, OUTPUT_TYPE__LOG, (void *)syslogContext);
	break;
	
    case OUTPUT_TYPE_FLAG__ALERT:
	AddFuncToOutputList(OpSyslog_Alert, OUTPUT_TYPE__ALERT, (void *)syslogContext);
	break;
	
    default:
	FatalError("OpSyslog_Init(): Unknown operation mode...\n");
	break;
    }
    
    /* Since we are in init phase */
    syslogContext->socket = -1;
    
    if(NetConnect(syslogContext)) 
    {
        FatalError("OpSyslog_Init(): Failed to connect to host: [%s] %s:%u\n",
		   db_proto[syslogContext->proto], 
		   syslogContext->server, 
		   syslogContext->port);
        return;
    }
    
    if( (syslogContext->payload = malloc(SYSLOG_MAX_QUERY_SIZE)) == NULL)
    {
	FatalError("OpSyslog_Init(): Can't allocate payload memory, bailling \n");
    }
    
    memset(syslogContext->payload,'\0',(SYSLOG_MAX_QUERY_SIZE));
    
    
    if( (syslogContext->formatBuffer = malloc(SYSLOG_MAX_QUERY_SIZE)) == NULL)
    {
	FatalError("OpSyslog_Init(): Can't allocate payload memory, bailling \n");
    }
    
    memset(syslogContext->formatBuffer,'\0',(SYSLOG_MAX_QUERY_SIZE));
    
    OpSyslog_LogConfig(syslogContext);    
    
    return;
}


/* Inverse of the setup function, free memory allocated in Setup 
 * can't free the outputPlugin since it is also the list node itself
 */
void OpSyslog_Exit(int signal,void *pSyslogContext)
{
    OpSyslog_Data *iSyslogContext = NULL;
    
    if( pSyslogContext == NULL)
    {
	FatalError("OpSyslog_Exit(): Called with a NULL argument .... bailing \n");
    }

    iSyslogContext =(OpSyslog_Data *)pSyslogContext;
    
    if(iSyslogContext->payload)
    {
	free(iSyslogContext->payload);
	iSyslogContext->payload = NULL;
    }
    
    if(iSyslogContext->formatBuffer)
    {
	free(iSyslogContext->formatBuffer);
	iSyslogContext->formatBuffer = NULL;
    }
    
    if(iSyslogContext->server)
    {
	free(iSyslogContext->server);
	iSyslogContext->server = NULL;
    }
    
    if(iSyslogContext->sensor_name)
    {
	free(iSyslogContext->sensor_name);
	iSyslogContext->sensor_name = NULL;
    }
    
    NetClose(iSyslogContext);
    
    return;
}


/* Used to concat current format to current the syslog payload message */
int OpSyslog_Concat(OpSyslog_Data *syslogContext)
{
    
    if( (syslogContext == NULL) ||
	(syslogContext->payload == NULL) ||
	(syslogContext->formatBuffer == NULL))
    {
	/* XXX */
	return 1;
    }
    
    if( (syslogContext->payload_current_pos + syslogContext->format_current_pos) >= SYSLOG_MAX_QUERY_SIZE)
    {
	/* XXX */
	return 1;
    }
    
    if( (syslogContext->payload_current_pos += snprintf((syslogContext->payload+syslogContext->payload_current_pos),
							(SYSLOG_MAX_QUERY_SIZE - syslogContext->payload_current_pos),
							"%c %s %c",
							syslogContext->delim,
							syslogContext->formatBuffer,
							syslogContext->delim))  >= SYSLOG_MAX_QUERY_SIZE)
    {
	/* XXX */
	return 1;
    }
    
    memset(syslogContext->formatBuffer,'\0',SYSLOG_MAX_QUERY_SIZE);
    syslogContext->format_current_pos = 0;
    
    return 0;
}

int OpSyslog_LogConfig(void *pSyslogContext)
{
    OpSyslog_Data *iSyslogContext = NULL;
    
    if( pSyslogContext == NULL) 
    {
        return -1;
    }
    
    iSyslogContext =(OpSyslog_Data *)pSyslogContext;
    
    LogMessage("spo_syslog_full config:\n");
    LogMessage("\tDetail Level: %s\n",
	       iSyslogContext->detail == 1 ? "Full" : "Fast");
    LogMessage("\tSyslog Server: %s:%u\n",
	       iSyslogContext->server, 
	       iSyslogContext->port);
    LogMessage("\tReporting Protocol: %s\n", 
	       db_proto[iSyslogContext->proto]);
    return 0;
}



/* CHECKME: -elz seem to have been incomplete @ creation time ...investigate after port */
/*int Syslog_FormatReference(OpSyslog_Data *data, ReferenceNode *refer) 
{
ReferenceNode *cRef = NULL;

if( (data == NULL) ||
(refer == NULL))
{

return 1;
}

cRef = refer;

while(cRef) 
{
LogMessage("System: %s ID:[%s] URL:%s\n", cRef->system->name,cRef->id, cRef->system->url);
cRef = cRef->next;
}
return 0;

}*/


static int Syslog_FormatTrigger(OpSyslog_Data *syslogData, Unified2EventCommon *pEvent,int opType) 
{
    
    char tSigBuf[256] = {0};
    char *timestamp_string = NULL;
    
    SigNode             *sn = NULL;
    ClassType           *cn = NULL;
    //ReferenceNode       *rn = NULL;
    
    if( (syslogData == NULL) ||
	(pEvent == NULL))
    {
	/* XXX */
	return 1;
    }
    
    switch(opType)
    {
	
    case 0:
	/* Alert */
	if( (syslogData->format_current_pos += snprintf(syslogData->formatBuffer,SYSLOG_MAX_QUERY_SIZE,"[SNORTIDS[ALERT]: [%s] }", syslogData->sensor_name)) >=  SYSLOG_MAX_QUERY_SIZE)
	{
	    /* XXX */
	    return 1;
	}
	break;
    case 1:
	if( (syslogData->format_current_pos += snprintf(syslogData->formatBuffer,SYSLOG_MAX_QUERY_SIZE,"[SNORTIDS[LOG]: [%s] ]", syslogData->sensor_name)) >=  SYSLOG_MAX_QUERY_SIZE)
	{
	    /* XXX */
	    return 1;
	}
	/* Log */
	break;
	
    default:
	/* XXX */
	LogMessage("Syslog_FormatTrigger(): Unknown [%d] operation mode \n",opType);
	return 1;
	break;
    }
    
    
    if( OpSyslog_Concat(syslogData))
    {
	/* XXX */
	FatalError("OpSyslog_Concat(): Failed \n");
    }

    
    if( (timestamp_string = GetTimestampByComponent(
	     ntohl(pEvent->event_second),
	     ntohl(pEvent->event_microsecond),
	     GetLocalTimezone())) == NULL)
    {
	/* XXX */
	/* Something went wrong ...we create a little string? */
	if( (timestamp_string = malloc(256)) == NULL)
	{
	    /* XXX */
	    return 1;
	}
	
	memset(timestamp_string,'\0',256);
	snprintf(timestamp_string,256,"sec:[%u] msec:[%u] Second away from UTC:[%u] ",
		 ntohl(pEvent->event_second),
		 ntohl(pEvent->event_microsecond),
		 GetLocalTimezone());
    }
    
    
    snprintf(tSigBuf,256,"Snort Alert [%u:%u:%u]",
	     ntohl(pEvent->generator_id),
	     ntohl(pEvent->signature_id),
	     ntohl(pEvent->signature_revision));
    
    sn = GetSigByGidSid(ntohl(pEvent->generator_id),
			ntohl(pEvent->signature_id));
    
    cn = ClassTypeLookupById(barnyard2_conf, 
			     ntohl(pEvent->classification_id));
    
    if( (syslogData->format_current_pos += snprintf(syslogData->formatBuffer,SYSLOG_MAX_QUERY_SIZE,"%s%c%u%c%s", 
						    timestamp_string,syslogData->field_separators,
						    ntohl(pEvent->priority_id),syslogData->field_separators,
						    sn != NULL ? sn->msg : tSigBuf)) >=  SYSLOG_MAX_QUERY_SIZE)
    {
	/* XXX */
	free(timestamp_string);
	return 1;
    }
    

    if( OpSyslog_Concat(syslogData))
    {
	/* XXX */
	FatalError("OpSyslog_Concat(): Failed \n");
    }
    
    if(cn)
    {
	if( (syslogData->format_current_pos += snprintf(syslogData->formatBuffer,SYSLOG_MAX_QUERY_SIZE,"%s", 
							cn->type)) >= SYSLOG_MAX_QUERY_SIZE)
	{
	    /* XXX */
	    free(timestamp_string);
	    return 1;
	}
    }
    else
    {
	if( ( syslogData->format_current_pos += snprintf(syslogData->formatBuffer,SYSLOG_MAX_QUERY_SIZE,"%s", 
							 "[Unknown Classification]") >= SYSLOG_MAX_QUERY_SIZE))
	{
	    /* XXX */
	    free(timestamp_string);
	    return 1;
	}
    }
    
    if( OpSyslog_Concat(syslogData))
    {
	/* XXX */
	FatalError("OpSyslog_Concat(): Failed \n");
    }
    
    /*CHECKME: -elz  Need to investigate */
    //Syslog_FormatReference(syslogData, sn->refs);
    
    free(timestamp_string);
    
    return 0;
}



static int Syslog_FormatIPHeaderAlert(OpSyslog_Data *data, Packet *p) 
{
    int inner_ip = 0;
    
    char *p_ip = NULL;
    char s_ip[16] ={0};
    char d_ip[16] ={0};
    

    if(data == NULL ||
       p == NULL)
    {
	/* XXX */
	return 1;
    }
    
    
    /* This might not be fixed but meanwhile its a fix */
    if( (p->iph == NULL) &&
	(p->inner_iph))
    {
	p->iph = p->inner_iph;
	inner_ip =1;
    }
    
    if(p->iph)
    {
        p_ip = inet_ntoa(p->iph->ip_src);
	memcpy(s_ip,p_ip,strlen(p_ip));
	
	p_ip = inet_ntoa(p->iph->ip_dst);
	memcpy(d_ip,p_ip,strlen(p_ip));
	
	if( (data->format_current_pos += snprintf(data->formatBuffer,SYSLOG_MAX_QUERY_SIZE,"%lu%c%s%c%s",   
						  (u_long)p->iph->ip_proto,data->field_separators, 
						  s_ip,data->field_separators,
						  d_ip)) >= SYSLOG_MAX_QUERY_SIZE)
	{
	    /* XXX */
	    if(inner_ip)
	    {
		p->iph = NULL;
	    }
	    return 1;
	}
    }
    
    if(inner_ip)
    {
	p->iph = NULL;
    }
    
    return OpSyslog_Concat(data);
}

static int Syslog_FormatIPHeaderLog(OpSyslog_Data *data, Packet *p) {

    int inner_ip = 0;

    unsigned int s, d, proto, ver, hlen, tos, len, id, off, ttl, csum;
    s=d=proto=ver=hlen=tos=len=id=off=ttl=csum=0;

    if( (p->iph == NULL) &&
        (p->inner_iph))
    {
        p->iph = p->inner_iph;
        inner_ip =1;
    }

    if(p->iph) 
    {
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
    
    if( (data->format_current_pos += snprintf(data->formatBuffer,SYSLOG_MAX_QUERY_SIZE,
					      "%u%c%u%c%u%c%u%c%u%c%u%c%u%c%u%c%u%c%u%c%u%c%u",
					      proto,data->field_separators, 
					      s, data->field_separators, 
					      d, data->field_separators, 
					      ver, data->field_separators, 
					      hlen, data->field_separators, 
					      tos, data->field_separators, 
					      len, data->field_separators, 
					      id, data->field_separators, 
#if defined(WORDS_BIGENDIAN)
					      ((off & 0xE000) >> 13),data->field_separators, 
					      htons(off & 0x1FFF),data->field_separators, 
#else
					      ((off & 0x00E0) >> 5),data->field_separators, 
					      htons(off & 0xFF1F), data->field_separators, 
#endif	     
					      ttl,data->field_separators, 
					      csum)) >= SYSLOG_MAX_QUERY_SIZE)
    {
	/* XXX */
	if(inner_ip)
	{
	    p->iph = NULL;
	}
	
	return 1;
    }

    if(inner_ip)
    {
	p->iph = NULL;
    }
    
    
    return OpSyslog_Concat(data);
}


static int Syslog_FormatTCPHeaderAlert(OpSyslog_Data *data, Packet *p) 
{
    if( (data == NULL) ||
	(p == NULL) || 
	(p->tcph == NULL))
    {
	/* XXX */
	return 1;
    }
    
    if( (data->format_current_pos += snprintf(data->formatBuffer,SYSLOG_MAX_QUERY_SIZE,"%u%c%u", 
					      ntohs(p->tcph->th_sport),data->field_separators,
					      ntohs(p->tcph->th_dport))) > SYSLOG_MAX_QUERY_SIZE)
    {
	/* XXX */
	return 1;
    }
    
    return OpSyslog_Concat(data);
}

static int Syslog_FormatTCPHeaderLog(OpSyslog_Data *data, Packet *p) 
{
    
    unsigned int th_win, th_sum, th_flags, th_ack, th_seq, th_urp, th_off, th_x2;
    
    th_win=th_sum=th_flags=th_ack=th_seq=th_urp=th_off=th_x2=0;
    
    if( (data == NULL) ||
	(p == NULL) || 
	(p->tcph == NULL))
    {
	/* XXX */
	return 1;
    }
    
    if(p->tcph) 
    {
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
    
    if( (data->format_current_pos += snprintf(data->formatBuffer,SYSLOG_MAX_QUERY_SIZE,
					       "%u%c%u%c%u%c%u%c%u%c%u%c%u%c%u%c%u%c%u", 
					       p->sp,data->field_separators,  
					       p->dp, data->field_separators, 
					       th_seq, data->field_separators, 
					       th_ack, data->field_separators, 
					       th_off, data->field_separators, 
					       th_x2, data->field_separators, 
					       th_flags, data->field_separators, 
					       th_win, data->field_separators, 
					       th_sum, data->field_separators, 
					       th_urp)) > SYSLOG_MAX_QUERY_SIZE)
    {
	/* XXX */
	return 1;
    }
    
    return OpSyslog_Concat(data);
}


static int Syslog_FormatUDPHeaderAlert(OpSyslog_Data *data, Packet *p) 
{
    
    if( (data == NULL) ||
	(p == NULL) || 
	(p->udph == NULL))
    {
	/* XXX */
	return 1;
    }
    
    
    if( (data->format_current_pos += snprintf(data->formatBuffer,SYSLOG_MAX_QUERY_SIZE,
					      "%u%c%u", 
					      ntohs(p->udph->uh_sport),data->field_separators,  
					      ntohs(p->udph->uh_dport)) >= SYSLOG_MAX_QUERY_SIZE))
    {
	/* XXX */
	return 1;
    }
    
    return OpSyslog_Concat(data);;
}

static int Syslog_FormatUDPHeaderLog(OpSyslog_Data *data, Packet *p) 
{
    unsigned int uh_len=0, uh_chk=0;

    if( (data == NULL) ||
        (p == NULL) ||
        (p->udph == NULL))
    {
        /* XXX */
        return 1;
    }

    if(p->udph) 
    {
	if(p->udph->uh_len)
	    uh_len =  ntohs(p->udph->uh_len);
	if(p->udph->uh_chk)
	    uh_chk =  ntohs(p->udph->uh_chk);
    }
    
    if( (data->format_current_pos +=  snprintf(data->formatBuffer,SYSLOG_MAX_QUERY_SIZE,
					       "%u%c%u%c%u%c%u",
					       ntohs(p->udph->uh_sport),data->field_separators, 
					       ntohs(p->udph->uh_dport),data->field_separators, 
					       uh_len, data->field_separators, 
					       uh_chk)) >= SYSLOG_MAX_QUERY_SIZE)
    {
	/* XXX */
	return 1;
    }
    
    return OpSyslog_Concat(data);
}

/* Not Complete */
static int Syslog_FormatICMPHeaderAlert(OpSyslog_Data *data, Packet *p) 
{
    if( (data == NULL) ||
        (p == NULL) ||
        (p->icmph == NULL))
    {
        /* XXX */
        return 1;
    }
    
    if( (data->format_current_pos +=  snprintf(data->formatBuffer,SYSLOG_MAX_QUERY_SIZE,
					       "%u%c%u",
					       p->icmph->type,data->field_separators, 
					       p->icmph->code)) >= SYSLOG_MAX_QUERY_SIZE)
    {
	/* XXX */
	return 1;
    }
    
    return OpSyslog_Concat(data);
}

static int Syslog_FormatICMPHeaderLog(OpSyslog_Data *data, Packet *p) 
{
    
    unsigned int type, code, csum, id, seq;
    type=code=csum=id=seq=0;
    
    if( (data == NULL) ||
        (p == NULL) ||
        (p->icmph == NULL))
    {
        /* XXX */
        return 1;
    }
    
    type = p->icmph->type;
    code = p->icmph->code;    
    csum = ntohs(p->icmph->csum);
	    
    if(type == 0 || type == 8 ||
       type == 13 || type == 14 ||
       type == 15 || type == 16)
    {
	
	id =  htons(p->icmph->icmp_hun.idseq.id);
	seq = htons(p->icmph->icmp_hun.idseq.seq);
	
	
    } 
    
    if( (data->format_current_pos +=  snprintf(data->formatBuffer, SYSLOG_MAX_QUERY_SIZE,
					       "%u%c%u%c%u%c%u%c%u",  
					       type,data->field_separators, 
					       code,data->field_separators, 
					       csum,data->field_separators, 
					       id,data->field_separators, 
					       seq)) >= SYSLOG_MAX_QUERY_SIZE)
    {
	/* XXX */
	return 1;
    }
    
    return OpSyslog_Concat(data);
}

int Syslog_FormatPayload(OpSyslog_Data *data, Packet *p) {
    
    char *hex_payload = NULL;
    
    if( (data == NULL) ||
        (p == NULL) ||
	(p->pkt == NULL))
	
    {
        /* XXX */
        return 1;
    }
    
    if(p->pkth->len > 0) 
    {
	if( (hex_payload = fasthex(p->pkt, p->pkth->len)) ==  NULL)
	{
	    /* XXX */
	    return 1;
	}
	if( (data->format_current_pos +=  snprintf(data->formatBuffer, SYSLOG_MAX_QUERY_SIZE,
						   "%u%c%s",
						   p->pkth->len,data->field_separators, 
						   hex_payload)) >= SYSLOG_MAX_QUERY_SIZE)
	{
	    /* XXX */
	    free(hex_payload);
	    return 1;
	}
	
	free(hex_payload);	
    }
    
    return OpSyslog_Concat(data);
}


void  OpSyslog_Alert(Packet *p, void *event, uint32_t event_type, void *arg)
{
    OpSyslog_Data *syslogContext = NULL;    
    Unified2EventCommon *iEvent = NULL;
    
    if( (p == NULL) ||
	(event == NULL) ||
	(arg == NULL))
    {
	LogMessage("OpSyslog_Alert(): Invoked with Packet[0x%x] Event[0x%x] Event Type [%u] Context pointer[0x%x]\n",
		   p,
		   event,
		   event_type,
		   arg);
	return;
    }
    
    
    if(event_type != UNIFIED2_IDS_EVENT)
    {
        LogMessage("OpSyslog_Alert(): Is currently unable to handle Event Type [%u] \n",
                   event_type);
    }

    
    syslogContext = (OpSyslog_Data *)arg;
    iEvent = event;
    
    memset(syslogContext->payload,'\0',(SYSLOG_MAX_QUERY_SIZE));
    memset(syslogContext->formatBuffer,'\0',(SYSLOG_MAX_QUERY_SIZE));
    syslogContext->payload_current_pos = 0;
    syslogContext->format_current_pos = 0;
    
    if(Syslog_FormatTrigger(syslogContext, iEvent,0) ) 
    {
	LogMessage("WARNING: Unable to append Trigger header.\n");
	return;
    }
    
    /* Support for portscan ip */
    if(p->iph ||
       p->inner_iph)
    {
	if(Syslog_FormatIPHeaderAlert(syslogContext, p) ) 
	{
	    LogMessage("WARNING: Unable to append Trigger header.\n");
	    return;
	}
    }	
	
    if(p->iph)
    {
        /* build the protocol specific header information */
	switch(p->iph->ip_proto)
	{
	case IPPROTO_TCP:
	    Syslog_FormatTCPHeaderAlert(syslogContext, p);
	    break;
	case IPPROTO_UDP:
	    Syslog_FormatUDPHeaderAlert(syslogContext, p);
	    break;
	case IPPROTO_ICMP:
	    Syslog_FormatICMPHeaderAlert(syslogContext, p);
	    break;
	}
    }
    

    /* CHECKME: -elz will update formating later on .. */
    if( (syslogContext->format_current_pos += snprintf(syslogContext->formatBuffer,SYSLOG_MAX_QUERY_SIZE,
						       "\n")) >= SYSLOG_MAX_QUERY_SIZE)
    {
	/* XXX */
        FatalError("Couldn't finalize payload string ....\n");
    }
    
    if( OpSyslog_Concat(syslogContext))
    {
        /* XXX */
        FatalError("OpSyslog_Concat(): Failed \n");
    }
    
    if(NetSend(syslogContext)) 
    {
	NetClose(syslogContext);
	FatalError("NetSend(): call failed for host:port '%s:%u' bailing...\n", syslogContext->server, syslogContext->port);
	return;
    }

    
    return;
}

void OpSyslog_Log(Packet *p, void *event, uint32_t event_type, void *arg)
{
    
    OpSyslog_Data *syslogContext = NULL;
    Unified2EventCommon *iEvent = NULL;
    
    if( (p == NULL) ||
        (event == NULL) ||
        (arg == NULL))
    {
        LogMessage("OpSyslog_Log(): Invoked with Packet[0x%x] Event[0x%x] Event Type [%u] Context pointer[0x%x]\n",
                   p,
                   event,
		   event_type,
                   arg);
        return;
    }
    
    if(event_type != UNIFIED2_IDS_EVENT)
    {
	LogMessage("OpSyslog_Log(): Is currently unable to handle Event Type [%u] \n",
		   event_type);
    }

    syslogContext = (OpSyslog_Data *)arg;
    iEvent = event;
    
    memset(syslogContext->payload,'\0',(SYSLOG_MAX_QUERY_SIZE));
    memset(syslogContext->formatBuffer,'\0',(SYSLOG_MAX_QUERY_SIZE));
    syslogContext->payload_current_pos = 0;
    syslogContext->format_current_pos = 0;
    
    if(Syslog_FormatTrigger(syslogContext, iEvent,1) ) 
    {
	FatalError("WARNING: Unable to append Trigger header.\n");
    }
    
    if(p->iph || p->inner_iph)
    {
	Syslog_FormatIPHeaderLog(syslogContext, p);
    }
    
    if(p->iph)
    {
	switch(p->iph->ip_proto)
	{
	case IPPROTO_ICMP:
	    Syslog_FormatICMPHeaderLog(syslogContext, p);
	    break;
	case IPPROTO_TCP:
	    Syslog_FormatTCPHeaderLog(syslogContext, p);
		break;
	case IPPROTO_UDP:
	    Syslog_FormatUDPHeaderLog(syslogContext, p);
	    break;
	}
    }
    
    Syslog_FormatPayload(syslogContext, p);    
    
    /* CHECKME: -elz will update formating later on .. */
    if( (syslogContext->format_current_pos += snprintf(syslogContext->formatBuffer,SYSLOG_MAX_QUERY_SIZE,
                                                       "\n")) >= SYSLOG_MAX_QUERY_SIZE)
    {
        /* XXX */
        FatalError("Couldn't finalize payload string ....\n");
    }
    
    if( OpSyslog_Concat(syslogContext))
    {
        /* XXX */
        FatalError("OpSyslog_Concat(): Failed \n");
    }
    
    if(NetSend(syslogContext)) 
    {
	NetClose(syslogContext);
	//Reliability...
	FatalError("WARNING: Unable to connect to our syslog host: '%s:%u'\n", syslogContext->server, syslogContext->port);
	
	return;
    }
    
    return;
}


OpSyslog_Data *OpSyslog_ParseArgs(char *args)
{
    OpSyslog_Data *op_data = NULL;
    
    op_data = (OpSyslog_Data *)SnortAlloc(sizeof(OpSyslog_Data));

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
	    else if(strcasecmp("delimiters", stoks[0]) == 0)
            {
		if(num_stoks >= 1)
                {
		    if( (strlen(stoks[1]) > 3) || 
			(strlen(stoks[1]) < 3))
		    {
			LogMessage("Invalid delimiters configured [%s], default will be used \n",stoks[1]);
		    }
		    else
		    {
			if(stoks[1][0] == '"' && 
			   stoks[1][2] == '"')
			{
			    op_data->delim = stoks[1][1];
			}
			else
			{
			    LogMessage("Invalid delimiters configured [%s], default will be used \n",stoks[1]);
			}
		    }
		}
		
	    }
	    else if(strcasecmp("separators", stoks[0]) == 0)
	    {
		if(num_stoks >= 1)
		{
		    if( (strlen(stoks[1]) > 3) ||
			(strlen(stoks[1]) < 3))
		    {
			
			LogMessage("Invalid field separator configured [%s], default will be used \n",stoks[1]);
		    }
		    else
		    {
			if(stoks[1][0] == '"' && 
			   stoks[1][2] == '"')
			{
			    op_data->field_separators = stoks[1][1];
			}
			else
			{
			    LogMessage("Invalid field separator configured [%s], default will be used. \n",stoks[1]);
			}
		    }		   
		}
	    }    
	    else
            {
                fprintf(stderr, "WARNING %s (%d) => Unrecognized argument for "
                        "SyslogFull plugin: %s\n", file_name, file_line, index);
            }
	    mSplitFree(&stoks, num_stoks);
        }
        /* free your mSplit tokens */
        mSplitFree(&toks, num_toks);
    }
    
    /* Default */    
    if(op_data->delim == 0)
    {
	LogMessage("Using default delimiters for syslog messages \"|\"\n");
	op_data->delim = '|';
    }
    else
    {
	LogMessage("Using \"%c\" as delimiters for syslog messages \n",op_data->delim);
    }
    
    if(op_data->field_separators == 0)
    {
	LogMessage("Using default field separators for syslog messages \" \"\n");
	op_data->field_separators= ' ';
    }
    else
    {
	LogMessage("Using \"%c\" as field separators for syslog messages \n",op_data->field_separators);
    }

    if(op_data->port == 0)
    {
	LogMessage("Using default Syslog port [%u] \n",op_data->port);
	op_data->port = 514;
    }
    
    
    if(op_data->sensor_name == NULL)
    {
	FatalError("You must specify a sensor name\n");
    }

    if(op_data->server == NULL)
    {
	
	FatalError("You must specify a valid server \n");
    }
    
    
    return op_data;
}


int UDPConnect(OpSyslog_Data *op_data) 
{
    
    if( (op_data == NULL))
    {
	/* XXX */
	return 1;
    }
    
    if(op_data->socket != -1 )
    {
	return 0;
    }
    
    if( (op_data->socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
	perror("Socket()");
	return 1;
    }
    
    return 0;
}


int TCPConnect(OpSyslog_Data *op_data) 
{
    int option=1;
    
    if(op_data == NULL)
    {
	/* XXX */
	return 1;
    }


    if( (op_data->socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
	LogMessage("Failed to create our socket");
	return 1;
    }
    
    /* CHECKME: -elz Really needed....? */
    if( (setsockopt(op_data->socket,IPPROTO_TCP,TCP_NODELAY,  (char *)&option, sizeof(option))) < 0 )
    {
	perror("setsockopt():");
	close(op_data->socket);
	op_data->socket = -1;
	return 1;
    }
    
    if( connect(op_data->socket,(struct sockaddr *)&op_data->sockaddr, sizeof(op_data->sockaddr)) != 0 )
    {
	perror("connect()");
	close(op_data->socket);
	op_data->socket = -1;
	return 1;
    }

    
    return 0;
}

int NetConnect(OpSyslog_Data *op_data)
{
    if(op_data == NULL)
    {
	/* XXX */
	return 1;
    }
    
    if(op_data->socket > 0)
    {
	if(NetTestSocket(op_data))
	{
	    op_data->socket = -1;
	    /* Test reconnection */
	}
    }

    
    /* Set socket information */
    
    if (inet_aton(op_data->server,&op_data->sockaddr.sin_addr) != 1) 
    {
	if ((op_data->hostPtr = gethostbyname(op_data->server)) == NULL) 
	{
	    FatalError("could not resolve address[%s]",op_data->server);
	}
	
	memcpy(&op_data->sockaddr.sin_addr,op_data->hostPtr->h_addr,sizeof(op_data->sockaddr.sin_addr));
    }
    

    op_data->sockaddr.sin_port = htons(op_data->port);
    op_data->sockaddr.sin_family = AF_INET;


    
    switch(op_data->proto)
    {
    case 0:
	return UDPConnect(op_data);
	break;
    case 1:
	return TCPConnect(op_data);
	break;
    default:
	FatalError("Protocol not supported\n");
	return 1;
	break;
    }
    
    /* XXX */
    /* Should never be reached */
    return 1;
}


int NetClose(OpSyslog_Data *op_data)
{
    int rval = 0;
    
    if(op_data ==NULL)
    {
	/* XXX */
	return -1;
    }
    
    if(op_data->socket)
    {
	rval = close(op_data->socket);
	op_data->socket = -1;
    }
    
    return rval;
}


int NetTestSocket(OpSyslog_Data *op_data)
{
    struct sockaddr addr = {0};
    socklen_t socklen = {0};

    if (op_data == NULL)
    {
	/* XXX */
	return 1;
    }
    
    if( getsockname(op_data->socket,&addr,&socklen) != 0)
    {
	/* XXX */
	perror("NetTestSocket():");
	return 1;
    }
    
    return 0;
}

int NetSend(OpSyslog_Data *op_data) 
{

    int sendSize = 0;
    int sendRetVal = 0;

    if(op_data == NULL)
    {
	/* XXX */
	return 1;
    }
    
    if(NetTestSocket(op_data))
    {
	if( NetConnect(op_data))
	{
	    FatalError("NetSend(): Failed to connect to host: [%s] %s:%u\n",
		       db_proto[op_data->proto],
		       op_data->server,
		       op_data->port);
	}
    }
    
    sendSize=strlen(op_data->payload);

    switch(op_data->proto) 
    {
	
    case 0: 
	/* UDP */
	if(sendto(op_data->socket,op_data->payload, strlen(op_data->payload), 0 , (struct sockaddr *)&op_data->sockaddr, sizeof(struct sockaddr)) <= 0) 
	{
	    /* XXX */
	    close(op_data->socket);
	    op_data->socket = -1;
	    return 1;
	}
	break;
	
    case 1: 
	/* TCP */ 
	
	sendRetVal = send(op_data->socket, op_data->payload, strlen(op_data->payload),0);
	
	if((sendRetVal < sendSize) ||
	   (sendRetVal < 0) )
	{
	    /* XXX */
	    perror("send():");
	    close(op_data->socket);
	    op_data->socket = -1;
	    return 1;
	}
	break;
	
    default:
	/* XXX */
	return 1;
	break;
    }
    
    return 0;
}

