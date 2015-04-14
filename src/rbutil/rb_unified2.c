/****************************************************************************
 *
 * Copyright (C) 2014 Eneo Tecnologia S.L.
 * Author: Eugenio Perez <eupm90@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 ****************************************************************************/
 
/**
 * @file   rb_unified2.c
 * @author Eugenio Pérez <eupm90@gmail.com>
 * @date   Wed May 29 2013
 * 
 * @brief  Defines redBorder utilities to work with unified2 events
 */


#include "rb_unified2.h"
#include <arpa/inet.h>

#include "unified2.h"
#include "util.h"
#include <stdlib.h>

#define U2_FLAG_ALLOWED 0x00        // impact_flag = 0 (packet allowed)
#define U2_FLAG_BLOCKED 0x20        // impact_flag = 32 (packet dropped)
#define U2_BLOCKED_FLAG_ALLOW 0x00  // blocked = 0 (packet allowed)
#define U2_BLOCKED_FLAG_BLOCK 0x01  // blocked = 2 (packet dropped)
#define U2_BLOCKED_FLAG_WOULD 0x02  // blocked = 3 (packet would have been dropped)
#define U2_BLOCKED_FLAG_CANT  0x03  // blocked = 4 (packet cant be dropped)

#define EVENT_IMPACT_FLAG(e) e->impact_flag
#define EVENT_BLOCKED(e)     e->blocked

/// @warning It's a macro, and it will return the caller function
#define RETURN_ACTION_OF_EVENT(event) \
    do{ \
        if(event==NULL && event_type ==0) return "log";\
        else if(EVENT_IMPACT_FLAG(event)==U2_FLAG_ALLOWED && EVENT_BLOCKED(event)==U2_BLOCKED_FLAG_ALLOW) return "alert";\
        else if(EVENT_IMPACT_FLAG(event)==U2_FLAG_BLOCKED && EVENT_BLOCKED(event)==U2_BLOCKED_FLAG_BLOCK) return "drop";\
        else if(EVENT_IMPACT_FLAG(event)==U2_FLAG_ALLOWED && EVENT_BLOCKED(event)==U2_BLOCKED_FLAG_WOULD) return "should_drop";\
        else if(EVENT_IMPACT_FLAG(event)==U2_FLAG_ALLOWED && EVENT_BLOCKED(event)==U2_BLOCKED_FLAG_CANT) return "cant_drop";\
        else return NULL;\
    }while(0)

const char *actionOfEvent(const void * voidevent,uint32_t event_type)
{
    switch(event_type){
        case UNIFIED2_IDS_EVENT:
        {
            const Unified2IDSEvent_legacy *event = (const Unified2IDSEvent_legacy *)voidevent;
            RETURN_ACTION_OF_EVENT(event);
        }
        break;
        case UNIFIED2_IDS_EVENT_MPLS:
        case UNIFIED2_IDS_EVENT_VLAN:
        {
            const Unified2IDSEvent *event = (const Unified2IDSEvent *)voidevent;
            RETURN_ACTION_OF_EVENT(event);
        }
        break;
        case UNIFIED2_IDS_EVENT_IPV6:
        {
            const Unified2IDSEventIPv6_legacy *event = (const Unified2IDSEventIPv6_legacy *)voidevent;
            RETURN_ACTION_OF_EVENT(event);
            }
        break;
        case UNIFIED2_IDS_EVENT_IPV6_MPLS:
        case UNIFIED2_IDS_EVENT_IPV6_VLAN:
        {
            const Unified2IDSEventIPv6 *event = (const Unified2IDSEventIPv6 *)voidevent;
            RETURN_ACTION_OF_EVENT(event);
        }
        break;
        default:
            LogMessage("WARNING: actionOfEvent(): event_type inconsistent (%d)\n", event_type);
        break;
    };
    return NULL;
}
