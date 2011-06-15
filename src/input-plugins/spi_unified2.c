/* 
**
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

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef __USE_GNU
#define __USE_GNU 1
#endif
#include <string.h>
#ifdef SOLARIS
    #include <strings.h>
#endif
#include <errno.h>
#include <unistd.h>

#include <netinet/in.h>
#include <arpa/inet.h>


#include "barnyard2.h"
#include "debug.h"
#include "mstring.h"
#include "plugbase.h"
#include "spi_unified2.h"
#include "spooler.h"
#include "strlcpyu.h"
#include "util.h"


/* 
 * Define in which context we run (For spooler)
 */
static u_int32_t spiOpCtx = 0;


/*
 * Function: UnifiedLogSetup()
 *
 * Purpose: Registers the input plugin keyword and initialization function 
 *          into the input plugin list.  This is the function that gets called
 *          InitInputPlugins() in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void Unified2Setup(void)
{
    /* link the input keyword to the init function in the input list */
    RegisterInputPlugin("unified2", Unified2Init);
    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Input plugin: Unified2 is setup...\n"););
}


/* In the future this could get per-input processor thread specific with thread key for example. */
/** 
 *  Return Input plugin Unified2 Operation Context
 * 
 * 
 * @return spiOpCtx 
 */
int spiUnified2GetOperationMode(void)
{
    return spiOpCtx;
}

/** 
 * Parse unified2 input pluggin configuration.
 * 
 * @param iArgs 
 * 
 * @return Success [0] Failure [1]
 */
int parseUnified2InputArgs(char *iArgs)
{
    char **toks = NULL;
    int num_toks = 0;
    int i = 0;
    char *op_mode = NULL;
    
    if(iArgs == NULL)
    {
	/* XXX */
	return 1;
    }
    
    toks = mSplit((char *)iArgs, ",", 31, &num_toks, '\\');
    for(i = 0; i < num_toks; ++i)
    {
	char **stoks = NULL;
	int num_stoks = 0;
	char *index = toks[i];
	while(isspace((int)*index))
	    ++index;
	
	stoks = mSplit(index, " ", 2, &num_stoks, 0);
	
	if(strcasecmp("input_mode", stoks[0]) == 0)
	{
	    if(num_stoks >= 1)
	    {
		op_mode = strndup(stoks[1],64);
		
		if(strcasecmp("unified2",op_mode) == 0)
		{
		    spiOpCtx = LOGCTXUNIFIED2;
		}
		else if(strcasecmp("alert_unified2",op_mode) == 0)
		{
		    spiOpCtx= LOGCTXALERTUNIFIED2;
		}
		else if(strcasecmp("log_unified2",op_mode) == 0)
		{
		    spiOpCtx = LOGCTXLOGUNIFIED2;
		}    
		else
		{
		    if(op_mode != NULL)
		    {
			free(op_mode);
		    }
		    
		    /* XXX */
		    LogMessage("parseUnified2InputArgs(): Unknown mode [%s] specified to input_mode directive.\n"
			       "\t\t\t  Unified2 Input processor accecpt one of the following mode: (unified2|alert_unified2|log_unified2) \n",stoks[1]);
		    return 1;
		}
	    }
	    else
	    {
		if(op_mode != NULL)
		{
		    free(op_mode);
		}
		
		/* XXX */
		LogMessage("parseUnified2InputArgs(): Need argument to input_mode directive: (unified2|alert_unified2|log_unified2) \n");
		return 1;
	    }
	}
	else
	{
	    /* XXX */
	    LogMessage("parseUnified2InputArgs(): unsupported option [%s]\n",stoks[0]);
	    return 1;
	}
    }
    return 0;
}


/** 
 *  Initialize Unified2 Input Plugin.
 * 
 * @param args 
 */
void Unified2Init(char *args)
{
    if(args == NULL)
    {
	/* XXX*/
	FatalError("Unified2Init(): Can't start with NULL arguments \n");
    }

    if(parseUnified2InputArgs(args))
    {
	/* XXX */
       	FatalError("Unified2Init(): Can't parse unified2 arguments [%s] \n",args);
    }
    
    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Linking UnifiedLog functions to call lists...\n"););
    
    /* Link the input processor read/process functions to the function list */
    AddReadRecordHeaderFuncToInputList("unified2", Unified2ReadRecordHeader);
    AddReadRecordFuncToInputList("unified2", Unified2ReadRecord);
    
    /* Link the input processor exit/restart functions into the function list */
    AddFuncToCleanExitList(Unified2CleanExitFunc, NULL);
    AddFuncToRestartList(Unified2RestartFunc, NULL);
}

/* Partial reads should rarely, if ever, happen.  Thus we should not actually
   call lseek very often 
*/
int Unified2ReadRecordHeader(void *sph)
{
  ssize_t             bytes_read;
  Spooler             *spooler = (Spooler *)sph;
  
  // Depricated.
  //if( NULL == spooler->record.header )
  // {
  // SnortAlloc will FatalError if memory can't be assigned.
  //  spooler->record.header = SnortAlloc(sizeof(Unified2RecordHeader));
  // }
  
  memset(spooler->record.header,'\0',sizeof(Unified2RecordHeader));
  
  
  /* read the first portion of the unified log reader */
#if DEBUG
  int position = lseek(spooler->fd, 0, SEEK_CUR);
  DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Header: Reading at byte position %u\n", position););
#endif
  
  bytes_read = read( spooler->fd, spooler->record.header + spooler->offset, sizeof(Unified2RecordHeader) - spooler->offset);
  
  if (bytes_read == -1)
    {
      LogMessage("ERROR: Read error: %s\n", strerror(errno));
      return BARNYARD2_FILE_ERROR;
    }
  
  if (bytes_read + spooler->offset != sizeof(Unified2RecordHeader))
    {
      if(bytes_read + spooler->offset == 0)
	{
	  return BARNYARD2_READ_EOF;
        }
      
      spooler->offset += bytes_read;
      return BARNYARD2_READ_PARTIAL;
    }
  
  
  DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Header: Type=%u (%u bytes)\n",
			  ntohl(((Unified2RecordHeader *)spooler->record.header)->type),
			  ntohl(((Unified2RecordHeader *)spooler->record.header)->length)););
  
  spooler->offset = 0;
  return 0;
}

int Unified2ReadRecord(void *sph)
{
  ssize_t             bytes_read;
  uint32_t            record_type;
  uint32_t            record_length;
  Spooler             *spooler = (Spooler *)sph;
  
  /* convert once */
  record_type = ntohl(((Unified2RecordHeader *)spooler->record.header)->type);
  record_length = ntohl(((Unified2RecordHeader *)spooler->record.header)->length);
  
  DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Reading record type=%u (%u bytes)\n", 
			  record_type, record_length););
  
  /* Depricated */
  //if(!spooler->record.data)
  //  {
  //    /* SnortAlloc will FatalError if memory can't be assigned */
  //    spooler->record.data = SnortAlloc(record_length);
  //  }
  
  /* We might have to adjust size to be the maximum possible size for an event (gziped and extra data) */
  /* But the static model should stands */
  memset(spooler->record.data,'\0',MAX_UNIFIED2_EVENT_SIZE);
  
  if (spooler->offset < record_length)
    {
#if DEBUG
      int position = lseek(spooler->fd, 0, SEEK_CUR);
      DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Record: Reading at byte position %u\n", position););
#endif
      /* in case we don't have it already */
      
        bytes_read = read(spooler->fd, spooler->record.data + spooler->offset,
			  record_length - spooler->offset);
	
        if (bytes_read == -1)
	  {
	    LogMessage("ERROR: read error: %s\n", strerror(errno));
            return BARNYARD2_FILE_ERROR;
	  }
	
        if (bytes_read + spooler->offset != record_length)
	  {
	    spooler->offset += bytes_read;
	    return BARNYARD2_READ_PARTIAL;
	  }
	
#ifdef DEBUG
        switch (record_type)
	  {
	  case UNIFIED2_IDS_EVENT:
	    Unified2PrintEventRecord((Unified2IDSEvent_legacy *)spooler->record.data);
	    break;
	  case UNIFIED2_IDS_EVENT_IPV6:
	    Unified2PrintEvent6Record((Unified2IDSEventIPv6_legacy *)spooler->record.data);
	    break;
	  case UNIFIED2_PACKET:
	    Unified2PrintPacketRecord((Unified2Packet *)spooler->record.data);
	    break;
	  case UNIFIED2_IDS_EVENT_MPLS:
	  case UNIFIED2_IDS_EVENT_IPV6_MPLS:
	  case UNIFIED2_IDS_EVENT_VLAN:
	  case UNIFIED2_IDS_EVENT_IPV6_VLAN:
	  default:
	    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"No debug available for record type: %u\n", record_type););
	    break;
	  }
#endif
	
        spooler->offset = 0;
	
        return 0;
    }
  
  return -1;
}

void Unified2CleanExitFunc(int signal, void *arg)
{
  DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Unified2CleanExitFunc\n"););
}

void Unified2RestartFunc(int signal, void *arg)
{
  DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Unified2RestartFunc\n"););
}


#ifdef DEBUG
void Unified2PrintEventCommonRecord(Unified2EventCommon *evt)
{
  if(evt == NULL)
    return;
  
  DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			  "Type: Event -------------------------------------------\n"););
  DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			  "  sensor_id          = %d\n", ntohl(evt->sensor_id)););
  DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			  "  event_id           = %d\n", ntohl(evt->event_id)););
  DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			  "  event_second       = %lu\n", ntohl(evt->event_second)););
  DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			  "  event_microsecond  = %lu\n", ntohl(evt->event_microsecond)););
  DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			  "  generator_id       = %d\n", ntohl(evt->generator_id)););
  DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			  "  signature_id       = %d\n", ntohl(evt->signature_id)););
  DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			  "  signature_revision = %d\n", ntohl(evt->signature_revision)););
  DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			  "  classification_id  = %d\n", ntohl(evt->classification_id)););
  DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			  "  priority_id        = %d\n", ntohl(evt->priority_id)););
}

void Unified2PrintEventRecord(Unified2IDSEvent_legacy *evt)
{
  char                sip4[INET_ADDRSTRLEN];
  char                dip4[INET_ADDRSTRLEN];
  
  if(evt == NULL)
    return;
  
  Unified2PrintEventCommonRecord((Unified2EventCommon *)evt);
  
    inet_ntop(AF_INET, &(evt->ip_source), sip4, INET_ADDRSTRLEN);
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			    "  ip_source          = %s\n", sip4););
    
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			    "  sport_itype        = %d\n", ntohs(evt->sport_itype)););
    inet_ntop(AF_INET, &(evt->ip_destination), dip4, INET_ADDRSTRLEN);
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			    "  ip_destination     = %s\n", dip4););
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			    "  dport_icode        = %d\n", ntohs(evt->dport_icode)););

    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			    "  ip_protocol        = %d\n", evt->protocol););
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			    "  impact             = %d\n", evt->impact_flag););
}

void Unified2PrintEvent6Record(Unified2IDSEventIPv6_legacy *evt)
{
  char                sip6[INET6_ADDRSTRLEN];
  char                dip6[INET6_ADDRSTRLEN];
  
  if(evt == NULL)
    return;
  
  Unified2PrintEventCommonRecord((Unified2EventCommon *)evt);
  
  inet_ntop(AF_INET6, &(evt->ip_source), sip6, INET6_ADDRSTRLEN);
  DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			  "  ip_source          = %s\n", sip6););
  
  DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			  "  sport_itype        = %d\n", ntohs(evt->sport_itype)););
    inet_ntop(AF_INET6, &(evt->ip_destination), dip6, INET6_ADDRSTRLEN);
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			    "  ip_destination     = %s\n", dip6););
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			    "  dport_icode        = %d\n", ntohs(evt->dport_icode)););
    
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			    "  ip_protocol        = %d\n", evt->protocol););
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			    "  impact             = %d\n", evt->impact_flag););
}

void Unified2PrintPacketRecord(Unified2Packet *pkt)
{
  if(pkt == NULL)
    return;

  DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			  "Type: Packet ------------------------------------------\n"););
  DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			  "  sensor_id          = %d\n", ntohl(pkt->sensor_id)););
  DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			  "  event_id           = %d\n", ntohl(pkt->event_id)););
  DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			  "  event_second       = %lu\n", ntohl(pkt->event_second)););
  DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			  "  linktype           = %d\n", ntohl(pkt->linktype)););
  DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			  "  packet_second      = %lu\n", ntohl(pkt->packet_second)););
  DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			  "  packet_microsecond = %lu\n", ntohl(pkt->packet_microsecond)););
  DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			  "  packet_length      = %d\n", ntohl(pkt->packet_length)););
  DEBUG_WRAP(DebugMessage(DEBUG_LOG,
			  "  packet             = %02x %02x %02x %02x\n",pkt->packet_data[1],
			  pkt->packet_data[2],
			  pkt->packet_data[3],
			  pkt->packet_data[4]););
  
}
#endif

