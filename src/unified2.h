/*
**
** Copyright (C) 2008-2013 Ian Firns (SecurixLive) <dev@securixlive.com>
**
** Copyright (C) 2002-2009 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#ifndef __UNIFIED2_H__
#define __UNIFIED2_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

//SNORT DEFINES
//Long time ago...
#define UNIFIED2_EVENT                  1

//CURRENT
#define UNIFIED2_PACKET                 2
#define UNIFIED2_IDS_EVENT              7
#define UNIFIED2_IDS_EVENT_IPV6         72
#define UNIFIED2_IDS_EVENT_MPLS         99
#define UNIFIED2_IDS_EVENT_IPV6_MPLS    100
#define UNIFIED2_IDS_EVENT_VLAN         104
#define UNIFIED2_IDS_EVENT_IPV6_VLAN    105
#define UNIFIED2_EXTRA_DATA             110

#if defined(FEAT_OPEN_APPID)
#define UNIFIED2_IDS_EVENT_APPID        111
#define UNIFIED2_IDS_EVENT_APPID_IPV6   112
#define UNIFIED2_IDS_EVENT_APPSTAT      113

#define MAX_EVENT_APPNAME_LEN        16
#endif

/* Each unified2 record will start out with one of these */
typedef struct _Unified2RecordHeader
{
    uint32_t type;
    uint32_t length;
} Unified2RecordHeader;

//UNIFIED2_IDS_EVENT_VLAN = type 104
//comes from SFDC to EStreamer archive in serialized form with the extended header
typedef struct _Unified2IDSEvent
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t event_microsecond;
    uint32_t signature_id;
    uint32_t generator_id;
    uint32_t signature_revision;
    uint32_t classification_id;
    uint32_t priority_id;
    uint32_t ip_source;
    uint32_t ip_destination;
    uint16_t sport_itype;
    uint16_t dport_icode;
    uint8_t  protocol;
    uint8_t  impact_flag;//overloads packet_action
    uint8_t  impact;
    uint8_t  blocked;
    uint32_t mpls_label;
    uint16_t vlanId;
    uint16_t pad2;//Policy ID
#if defined(FEAT_OPEN_APPID)
    char     app_name[MAX_EVENT_APPNAME_LEN];
#endif /* defined(FEAT_OPEN_APPID) */
} Unified2IDSEvent;

//UNIFIED2_IDS_EVENT_IPV6_VLAN = type 105
typedef struct _Unified2IDSEventIPv6
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t event_microsecond;
    uint32_t signature_id;
    uint32_t generator_id;
    uint32_t signature_revision;
    uint32_t classification_id;
    uint32_t priority_id;
    struct in6_addr ip_source;
    struct in6_addr ip_destination;
    uint16_t sport_itype;
    uint16_t dport_icode;
    uint8_t  protocol;
    uint8_t  impact_flag;
    uint8_t  impact;
    uint8_t  blocked;
    uint32_t mpls_label;
    uint16_t vlanId;
    uint16_t pad2;/*could be IPS Policy local id to support local sensor alerts*/
#if defined(FEAT_OPEN_APPID)
    char     app_name[MAX_EVENT_APPNAME_LEN];
#endif /* defined(FEAT_OPEN_APPID) */
} Unified2IDSEventIPv6;

//UNIFIED2_PACKET = type 2
typedef struct _Unified2Packet
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t packet_second;
    uint32_t packet_microsecond;
    uint32_t linktype;
    uint32_t packet_length;
    uint8_t packet_data[4];   /* For debugging */
} Unified2Packet;


typedef struct _Unified2ExtraDataHdr{
    uint32_t event_type;
    uint32_t event_length;
}Unified2ExtraDataHdr;


//UNIFIED2_EXTRA_DATA - type 110
typedef struct _Unified2ExtraData{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t type;              /* EventInfo */
    uint32_t data_type;         /*EventDataType */
    uint32_t blob_length;       /* Length of the data + sizeof(blob_length) + sizeof(data_type)*/
} Unified2ExtraData;

typedef enum _EventInfoEnum
{
    EVENT_INFO_XFF_IPV4 = 1,
    EVENT_INFO_XFF_IPV6 ,
    EVENT_INFO_REVIEWED_BY,
    EVENT_INFO_GZIP_DATA
}EventInfoEnum;

typedef enum _EventDataType
{
    EVENT_DATA_TYPE_BLOB = 1,
    EVENT_DATA_TYPE_MAX
}EventDataType;

#define EVENT_TYPE_EXTRA_DATA   4

#define MAX_XFF_WRITE_BUF_LENGTH (sizeof(Unified2RecordHeader) + \
        sizeof(Unified2ExtraDataHdr) + sizeof(Unified2ExtraData) \
        + sizeof(struct in6_addr))


//---------------LEGACY, type '7'
//These structures are not used anymore in the product
typedef struct Unified2IDSEvent_legacy
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t event_microsecond;
    uint32_t signature_id;
    uint32_t generator_id;
    uint32_t signature_revision;
    uint32_t classification_id;
    uint32_t priority_id;
    uint32_t ip_source;
    uint32_t ip_destination;
    uint16_t sport_itype;
    uint16_t dport_icode;
    uint8_t  protocol;
    uint8_t  impact_flag;//sets packet_action
    uint8_t  impact;
    uint8_t  blocked;
} Unified2IDSEvent_legacy;

//----------LEGACY, type '72'
typedef struct Unified2IDSEventIPv6_legacy
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t event_microsecond;
    uint32_t signature_id;
    uint32_t generator_id;
    uint32_t signature_revision;
    uint32_t classification_id;
    uint32_t priority_id;
    struct in6_addr ip_source;
    struct in6_addr ip_destination;
    uint16_t sport_itype;
    uint16_t dport_icode;
    uint8_t  protocol;
    uint8_t  impact_flag;
    uint8_t  impact;
    uint8_t  blocked;
} Unified2IDSEventIPv6_legacy;

////////////////////-->LEGACY

/*
** Smaller subset of feature common across event,packet and extradata
**
**
*/
typedef struct _Unified2CacheCommon
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
} Unified2CacheCommon;

/* 
** The Unified2EventCommon structure is the common structure that occurs
** at the beginning of all Unified2Event* structures.
** 
** This structure allows the safe casting of any Unified2Event* structure
** in order to obtain common event information
*/
typedef struct _Unified2EventCommon
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t event_microsecond;
    uint32_t signature_id;
    uint32_t generator_id;
    uint32_t signature_revision;
    uint32_t classification_id;
    uint32_t priority_id;
} Unified2EventCommon;

#endif /* __UNIFIED2_H__ */
