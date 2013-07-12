/****************************************************************************
 *
 * Copyright (C) 2013 Eneo Tecnologia S.L.
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
 * @file   rb_numstrpair_list.h
 * @author Eugenio Pérez <eupm90@gmail.com>
 * @date   Wed May 29 2013
 * 
 * @brief  Declares a linked list to save a number -> str association. Useful to
 * save hostname -> hostip or service_name->service_number pairs.
 */

#include "sf_ip.h"

typedef struct _Number_str_assoc{
    char * human_readable_str;     /* Example: Google, tcp, ssh... */
    char * number_as_str;          /* Example: 8.8.8.8, 0x800, 22... String format*/
    union{sfip_t ip;uint16_t service;uint16_t protocol;} number;
    struct _Number_str_assoc * next;
} Number_str_assoc;

/* Enumeration for FillHostList */
typedef enum{HOSTS,NETWORKS,SERVICES,PROTOCOLS} FILLHOSTSLIST_MODE;

void freeNumberStrAssocList(Number_str_assoc * nstrList);
void FillHostsList(const char * filename,Number_str_assoc ** list, const FILLHOSTSLIST_MODE mode);
Number_str_assoc * SearchNumberStr(uint32_t number,const Number_str_assoc *iplist,FILLHOSTSLIST_MODE mode);