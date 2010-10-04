/*
**
** Copyright (C) 2008-2010 SecurixLive   <dev@securixlive.com>
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

/* Each unified 2 record will start out with one of these */
typedef struct _Unified2RecordHeader
{
    uint32_t type;          /* Type of header.  A set most-significant
                               bit indicates presence of extended header */
    uint32_t length;

} Unified2RecordHeader;

/* The Unified2Event and Unified2Packet structures below are copied from the 
 * original unified 2 library, sfunified2 */
typedef struct _Unified2Event
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
    uint8_t  packet_action;
    uint16_t pad;  /* restore 4 byte alignment */
} Unified2Event;

typedef struct _Unified2Event_v2
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
    uint8_t  packet_action;
    uint16_t pad;  /* restore 4 byte alignment */
    uint32_t mpls_label;
    uint16_t vlanId;
    uint16_t configPolicyId;

} Unified2Event_v2;

typedef struct _Unified2Event6
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
    uint8_t  packet_action;
    uint16_t pad;  /* restore 4 byte alignment */

} Unified2Event6;

/**UnifiedEvent version 2 includes mpls tag, vlan tag and policy id in additional
 * to data contained in version 1. Version 2 will be used only when either vlan or
 * mpls tag is enabled using unified2 configuration.
 */
typedef struct _Unified2Event6_v2
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
    uint8_t  packet_action;
    uint16_t pad;  /* restore 4 byte alignment */
    uint32_t mpls_label;
    uint16_t vlanId;
    uint16_t configPolicyId;

} Unified2Event6_v2;

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

/* XXX Remove these when the real Unified 2 header becomes available */
#define UNIFIED2_EVENT 1
#define UNIFIED2_PACKET 2
#define UNIFIED2_IDS_EVENT 7
#define UNIFIED2_EVENT_EXTENDED 66
#define UNIFIED2_PERFORMANCE 67
#define UNIFIED2_PORTSCAN 68
#define UNIFIED2_IDS_EVENT_IPV6 72
#define UNIFIED2_IDS_EVENT_MPLS 99
#define UNIFIED2_IDS_EVENT_IPV6_MPLS 100

//version 2 
#define UNIFIED2_IDS_EVENT_V2 104
#define UNIFIED2_IDS_EVENT_IPV6_V2 105

#endif /* __UNIFIED2_H__ */
