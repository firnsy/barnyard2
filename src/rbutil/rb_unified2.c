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
#include <stdlib.h>


#define EVENT_IMPACT_FLAG(e) e->impact_flag
#define EVENT_BLOCKED(e)     e->blocked

/// @warning It's a macro, and it will return the caller function
#define RETURN_ACTION_OF_EVENT(event) \
    do{ \
        if(EVENT_IMPACT_FLAG(event)==0 && EVENT_BLOCKED(event)==0) return "alert";\
        if(EVENT_IMPACT_FLAG(event)==32 && EVENT_BLOCKED(event)==1) return "drop";\
        if(event==NULL && event_type ==0) return "log";\
    }while(0)

const char *actionOfEvent(const void * voidevent,uint32_t event_type)
{
    switch(event_type){
        case UNIFIED2_IDS_EVENT:
        {
            const Unified2IDSEvent_legacy *event = (const Unified2IDSEvent_legacy *)voidevent;
            RETURN_ACTION_OF_EVENT(event);
        }
        case UNIFIED2_IDS_EVENT_VLAN:
        {
            const Unified2IDSEvent *event = (const Unified2IDSEvent *)voidevent;
            RETURN_ACTION_OF_EVENT(event);
        }
        case UNIFIED2_IDS_EVENT_IPV6:
        {
            const Unified2IDSEventIPv6_legacy *event = (const Unified2IDSEventIPv6_legacy *)voidevent;
            RETURN_ACTION_OF_EVENT(event);

        } 
        case UNIFIED2_IDS_EVENT_IPV6_VLAN:
        {
            const Unified2IDSEventIPv6 *event = (const Unified2IDSEventIPv6 *)voidevent;
            RETURN_ACTION_OF_EVENT(event);
        }
    };
    return NULL;
}
