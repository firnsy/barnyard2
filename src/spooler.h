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

#ifndef __SPOOLER_H__
#define __SPOOLER_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif



#include <sys/types.h>

#include "unified2.h"
#include "plugbase.h"

#define SPOOLER_EXTENSION_FOUND     0
#define SPOOLER_EXTENSION_NONE      1
#define SPOOLER_EXTENSION_EPARAM    2
#define SPOOLER_EXTENSION_EOPEN     3

#define SPOOLER_STATE_OPENED        0
#define SPOOLER_STATE_HEADER_READ   1
#define SPOOLER_STATE_RECORD_READ   2

#define WALDO_STATE_ENABLED         0x01
#define WALDO_STATE_OPEN            0x02
#define WALDO_STATE_DIRTY           0x04

#define WALDO_MODE_NULL             0
#define WALDO_MODE_READ             1
#define WALDO_MODE_WRITE            2

#define WALDO_FILE_SUCCESS          0
#define WALDO_FILE_EEXIST           1
#define WALDO_FILE_EOPEN            2
#define WALDO_FILE_ETRUNC           3
#define WALDO_FILE_ECORRUPT         4
#define WALDO_STRUCT_EMPTY          10


#define MAX_FILEPATH_BUF    1024


/* From snort - spo_unified2.c */
/* with BY type */
#ifndef MAX_UNIFIED2_EVENT_SIZE
//#define MAX_UNIFIED2_EVENT_SIZE (sizeof(Serial_Unified2_Header) + sizeof(Serial_Unified2IDSEventIPv6_legacy) + IP_MAXPACKET);
//MAX_XFF_WRITE_BUF_LENGTH is still smaller than MAX_UNIFIED2_EVENT_SIZE so we should be ok for now.
#define MAX_UNIFIED2_EVENT_SIZE (sizeof(Unified2RecordHeader) + sizeof(Unified2IDSEventIPv6_legacy) + IP_MAXPACKET)
#endif


typedef struct _Record
{
    /* raw data */
    void                *header;
    void                *data;

    Packet              *pkt;       /* decoded packet */
} Record;

typedef struct _EventRecordNode
{
    uint32_t                type;   /* type of event stored */
    void                    *data;  /* unified2 event (eg IPv4, IPV6, MPLS, etc) */
    uint8_t                 used;   /* has the event be retrieved */
    
    struct _EventRecordNode *next;  /* reference to next event record */
} EventRecordNode;

typedef struct _PacketRecordNode
{
    Packet                  *data;  /* packet information */
    
    struct _PacketRecordNode *next; /* reference to next event record */
} PacketRecordNode;


typedef struct _Spooler_unified2_references
{
    /* Different type of unified2 event */
    Unified2IDSEvent_legacy *U2IdsEventLegacyPtr;
    Unified2IDSEventIPv6_legacy *U2IdeEventV6LegacyPtr;
    Unified2ExtraData *u2ExtraDataPtr;
    Unified2ExtraDataHdr *u2ExtraDataHdrPtr;
    Unified2Packet *u2PacketPtr;
    Unified2IDSEventIPv6 *U2IdsEventV6Ptr;
    Unified2IDSEvent *U2IdsEventPtr;
    
    /* Holder for possible packet */
    Packet *LogPacket;

    /* Event Pointer sent to output pluggin */
    void *SpoolerEventPtr;

    /* Spooler State */
    int SpoolerState;
    
} Spooler_unified2_references;

typedef struct _Spooler
{
    InputFuncNode           *ifn;       // Processing function of input file
    
    int                     fd;         // file descriptor of input file
    char                    filepath[MAX_FILEPATH_BUF]; // file path of input file
    time_t                  timestamp;  // time stamp of input file
    uint32_t                state;      // current read state
    uint32_t                offset;     // current file offest
    uint32_t                record_idx; // current record number
    
    uint32_t                magic;
    
    Spooler_unified2_references sur;    // Spooler Unified2 reference structures 

    void                    *header;    // header of input file

    Record                  record;     // data of current Record
} Spooler;

typedef struct _WaldoData
{
    char                    spool_dir[MAX_FILEPATH_BUF];
    char                    spool_filebase[MAX_FILEPATH_BUF];
    uint32_t                timestamp;
    uint32_t                record_idx;
} WaldoData;

typedef struct _Waldo
{
    int                     fd;                         // file descriptor of the waldo
    char                    filepath[MAX_FILEPATH_BUF]; // filepath to the waldo
    uint8_t                 mode;                       // read/write
    uint8_t                 state;

    WaldoData               data;    
} Waldo;


Spooler *spoolerOpen(const char *, const char *, uint32_t);
int spoolerClose(Spooler *);
int spoolerReadRecordHeader(Spooler *);
int spoolerReadRecord(Spooler *);
void spoolerProcessRecord(Spooler *, int);
void spoolerFreeRecord(Record *);
int spoolerWriteWaldo(Waldo *, Spooler *);
int spoolerOpenWaldo(Waldo *, uint8_t);
int spoolerCloseWaldo(Waldo *);
int ProcessContinuous(const char *, const char *, uint32_t, uint32_t);
int ProcessContinuousWithWaldo(struct _Waldo *);
int ProcessBatch(const char *, const char *);
int ProcessWaldoFile(const char *);
int spoolerReadWaldo(Waldo *);
int InitializeLogPacket(void);
int FreeLogPacket(void);
int SpoolerPacketGeneric(Spooler *);



#endif /* __SPOOLER_H__ */


