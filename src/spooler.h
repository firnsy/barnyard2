/* 
**
** Copyright (C) 2008-2013 Ian Firns (SecurixLive) <dev@securixlive.com>
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
#include <sys/queue.h>

#include "plugbase.h"
#ifdef RB_EXTRADATA
#include "unified2.h"
#endif

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
    
    TAILQ_ENTRY(_EventRecordNode) entry;  /* reference to next/prev event record */
} EventRecordNode;

typedef TAILQ_HEAD(_EventRecordList, _EventRecordNode) EventRecordCache;

typedef struct _PacketRecordNode
{
    Packet                  *data;  /* packet information */
    
    struct _PacketRecordNode *next; /* reference to next event record */
} PacketRecordNode;

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
    void                    *header;    // header of input file

    Record                  record;     // data of current Record
    
    EventRecordCache        event_cache; // linked list of cached events
    uint32_t                events_cached;

    PacketRecordNode        *packet_cache; // linked list of concurrent packets
    uint32_t                packets_cached;
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

int ProcessContinuous(const char *, const char *, uint32_t, uint32_t);
int ProcessContinuousWithWaldo(struct _Waldo *);
int ProcessBatch(const char *, const char *);
int ProcessWaldoFile(const char *);

int spoolerReadWaldo(Waldo *);
void spoolerEventCacheFlush(Spooler *);
void RegisterSpooler(Spooler *);
void UnRegisterSpooler(Spooler *);

int spoolerCloseWaldo(Waldo *);
int spoolerClose(Spooler *);

#endif /* __SPOOLER_H__ */


