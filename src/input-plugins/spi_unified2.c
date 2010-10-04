/* 
**
** Copyright (C) 2008-2010 SecurixLive   <dev@securixlive.com>
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
#include "plugbase.h"
#include "spi_unified2.h"
#include "spooler.h"
#include "strlcpyu.h"
#include "util.h"
#include "unified2.h"

/*
** PROTOTYPES
*/
void Unified2Init(char *);

/* processing functions  */
int Unified2ReadRecordHeader(void *);
int Unified2ReadRecord(void *);

int Unified2ReadEventRecord(void *);
int Unified2ReadEvent6Record(void *);
int Unified2ReadPacketRecord(void *);

void Unified2PrintCommonRecord(Unified2EventCommon *evt);
void Unified2PrintEventRecord(Unified2Event *);
void Unified2PrintEvent6Record(Unified2Event6 *evt);
void Unified2PrintPacketRecord(Unified2Packet *);

/* restart/shutdown functions */
void Unified2CleanExitFunc(int, void *);
void Unified2RestartFunc(int, void *);

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

void Unified2Init(char *args)
{
    /* parse the argument list from the rules file */
    //data = ParseAlertTestArgs(args);

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


/* TODO: remove static component since we can carry the header in spooler->record->header */
static Unified2RecordHeader u2hdr;

int Unified2ReadRecordHeader(void *sph)
{
    ssize_t             bytes_read;
    Spooler             *spooler = (Spooler *)sph;

    if( !spooler->record.header )
    {
        // SnortAlloc will FatalError if memory can't be assigned.
        spooler->record.header = SnortAlloc(sizeof(Unified2RecordHeader));
    }

    /* read the first portion of the unified log reader */
#if DEBUG
    int position = lseek(spooler->fd, 0, SEEK_CUR);
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Header: Reading at byte position %u\n", position););
#endif

    bytes_read = read( spooler->fd, &u2hdr + spooler->offset, sizeof(Unified2RecordHeader) - spooler->offset);
    
    if(bytes_read == -1)
    {
        LogMessage("ERROR: Read error: %s\n", strerror(errno));
        return BARNYARD2_FILE_ERROR;
    }

    if(bytes_read + spooler->offset != sizeof(Unified2RecordHeader))
    {
        if(bytes_read + spooler->offset == 0)
        {
            return BARNYARD2_READ_EOF;
        }

        spooler->offset += bytes_read;
        return BARNYARD2_READ_PARTIAL;
    }

    memcpy(spooler->record.header, &u2hdr, sizeof(Unified2RecordHeader));
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Header: Type=%u (%u bytes)\n", ntohl(u2hdr.type), ntohl(u2hdr.length)););

    spooler->offset = 0;
    return 0;
}

int Unified2ReadRecord(void *sph)
{
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Reading record type=%u (%u bytes)\n", ntohl(u2hdr.type), ntohl(u2hdr.length)););

    switch (ntohl(u2hdr.type))
    {
        case UNIFIED2_IDS_EVENT:
            return Unified2ReadEventRecord(sph);
            break;
        case UNIFIED2_IDS_EVENT_IPV6:
            return Unified2ReadEvent6Record(sph);
            break;
        case UNIFIED2_PACKET:
            return Unified2ReadPacketRecord(sph);
            break;
        default:
            FatalError("Unknown record type read: %u\n", ntohl(u2hdr.type));
            break;
    }

    return -1;
}

int Unified2ReadEventRecord(void *sph)
{
    ssize_t             bytes_read;
    int                 record_size;
    Spooler             *spooler = (Spooler *)sph;

    record_size = sizeof(Unified2Event);

    if(!spooler->record.data)
    {
        // SnortAlloc will FatalError if memory can't be assigned.
        spooler->record.data=SnortAlloc(record_size);
    }

    if (spooler->offset < record_size) 
    {
#if DEBUG
        int position = lseek(spooler->fd, 0, SEEK_CUR);
        DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Record: Reading at byte position %u\n", position););
#endif
        /* in case we don't have it already */

        bytes_read = read(spooler->fd, spooler->record.data + spooler->offset, 
                    record_size - spooler->offset);

        if(bytes_read == -1)
        {
            LogMessage("ERROR: read error: %s\n", strerror(errno));
            return BARNYARD2_FILE_ERROR;
        }
            
        if(bytes_read + spooler->offset != record_size)
        {
            spooler->offset += bytes_read;
            return BARNYARD2_READ_PARTIAL;
        }

#ifdef DEBUG
        Unified2PrintEventRecord((Unified2Event *)spooler->record.data);
#endif

        spooler->offset = 0;

        return 0;
    }

    return -1;
}

int Unified2ReadEvent6Record(void *sph)
{
    ssize_t             bytes_read;
    int                 record_size;
    Spooler             *spooler = (Spooler *)sph;

    record_size = sizeof(Unified2Event6);

    if(!spooler->record.data)
    {
        /* SnortAlloc will FatalError if memory can't be assigned */
        spooler->record.data=SnortAlloc(record_size);
    }

    if (spooler->offset < record_size) 
    {
#if DEBUG
        int position = lseek(spooler->fd, 0, SEEK_CUR);
        DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Record: Reading at byte position %u\n", position););
#endif
        /* in case we don't have it already */
        bytes_read = read(spooler->fd, spooler->record.data + spooler->offset, 
                    record_size - spooler->offset);

        if(bytes_read == -1)
        {
            LogMessage("ERROR: read error: %s\n", strerror(errno));
            return BARNYARD2_FILE_ERROR;
        }

        if(bytes_read + spooler->offset != record_size)
        {
            spooler->offset += bytes_read;
            return BARNYARD2_READ_PARTIAL;
        }

#ifdef DEBUG
        Unified2PrintEvent6Record((Unified2Event6 *)spooler->record.data);
#endif

        spooler->offset = 0;

        return 0;
    }

    return -1;
}

int Unified2ReadPacketRecord(void *sph)
{
    ssize_t             bytes_read;
    uint32_t            len;
    Spooler             *spooler = (Spooler *)sph;

    /* convert once */
    len = ntohl(u2hdr.length);

    if(!spooler->record.data)
    {
        // SnortAlloc will FatalError if memory can't be assigned.
        spooler->record.data=SnortAlloc(len);
    }

    if (spooler->offset < len)
    {
#if DEBUG
        int position = lseek(spooler->fd, 0, SEEK_CUR);
        DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Record: Reading at byte position %u\n", position););
#endif

        /* In case we don't have it already */
        bytes_read = read(spooler->fd, spooler->record.data + spooler->offset, 
                    ntohl(u2hdr.length) - spooler->offset);

        if(bytes_read == -1)
        {
            LogMessage("ERROR: read error: %s\n", strerror(errno));
            return BARNYARD2_FILE_ERROR;
        }

        if(bytes_read + spooler->offset != len)
        {
            spooler->offset += bytes_read;
            return BARNYARD2_READ_PARTIAL;
        }

#ifdef DEBUG
        Unified2PrintPacketRecord((Unified2Packet *)spooler->record.data);
#endif

        spooler->offset = 0;

        return 0;
    }

    return -1;
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
    
void Unified2PrintEventRecord(Unified2Event *evt)
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
        "  packet_action      = %d\n", evt->packet_action););
}

void Unified2PrintEvent6Record(Unified2Event6 *evt)
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
        "  packet_action      = %d\n", evt->packet_action););
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

void Unified2CleanExitFunc(int signal, void *arg)
{
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Unified2CleanExitFunc\n"););
}

void Unified2RestartFunc(int signal, void *arg)
{
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Unified2RestartFunc\n"););
}

