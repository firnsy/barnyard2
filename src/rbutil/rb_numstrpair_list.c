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
 * @file   rb_numstrpair_list.c
 * @author Eugenio Pérez <eupm90@gmail.com>
 * @date   Wed May 29 2013
 * 
 * @brief  Implements rb_numstrpair_list.h functions
 */

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "rb_numstrpair_list.h"
#include "barnyard2.h"
#include "util.h"
#include "mstring.h"


/*
 * Function freeNumberStrAssocList
 *
 * Purpose: Extract a node from a line in the file.
 *
 * Arguments: number   => nstrList: List to free.
 */
void freeNumberStrAssocList(Number_str_assoc * nstrList){
    Number_str_assoc * aux=nstrList,*aux2;
    while(aux){
        aux2 = aux->next;
        free(aux->human_readable_str);
        free(aux->number_as_str);
        free(aux);
        aux=aux2;
    }
};

/*
 * Function FillHostList_Node
 *
 * Purpose: Extract a node from a line in the file.
 *
 * Arguments: number   => line_buffer: line of the node in the text file
 *            mode     => See FILLHOSTSLIST_MODE
 */
static Number_str_assoc * FillHostList_Node(char *line_buffer, FILLHOSTSLIST_MODE mode){
    /* Assuming format of /etc/hosts: ip hostname */
    /* Assuming format of /etc/networks: netname ip/mask */
    /* Assuming format of /etc/services: servicename number */
    /* Assuming format of /etc/protocols: protocolname number */
    char ** toks=NULL;
    int num_toks;
    Number_str_assoc * node = SnortAlloc(sizeof(Number_str_assoc));
    if(node){
        if((toks = mSplit((char *)line_buffer, " \t", 2, &num_toks, '\\'))){
            node->human_readable_str = SnortStrdup(toks[0]);
            node->number_as_str = SnortStrdup(toks[1]);
            switch(mode){
                case HOSTS:
                case NETWORKS:
                {
                    const SFIP_RET ret = sfip_pton(node->number_as_str, &node->number.ip);
                    if(ret==SFIP_FAILURE){
                        free(node->number_as_str);
                        free(node->human_readable_str);
                        free(node);
                        node=NULL;
                    }
                }
                    break;
                case SERVICES:
                    node->number.protocol = atoi(node->number_as_str);
                    break;
                case PROTOCOLS:
                    node->number.service  = atoi(node->number_as_str);
                    break;
                case VLANS:
                    node->number.vlan  = atoi(node->number_as_str);
                break;
            };
            mSplitFree(&toks, num_toks);
        }
    }
    return node;
}

/*
 * Function FillHostsList
 *
 * Purpose: Fill a host/net -> ip assotiation list from a hosts or network file 
 *          (the format is the same as /etc/hosts and /etc/network)
 *
 * Arguments: filename => route to host/networks file
 *            list     => list to fill
 *            mode     => See FILLHOSTSLIST_MODE
 */
void FillHostsList(const char * filename,Number_str_assoc ** list, const FILLHOSTSLIST_MODE mode){
    char line_buffer[1024];
    FILE * file;
    int aok=1;
    
    if((file = fopen(filename, "r")) == NULL)
    {
        FatalError("fopen() alert file %s: %s\n",filename, strerror(errno));
    }

    Number_str_assoc ** llinst_iterator = list;
    while(NULL != fgets(line_buffer,1024,file) && aok){
        if(line_buffer[0]!='#' && line_buffer[0]!='\n'){
            Number_str_assoc * ip_str= FillHostList_Node(line_buffer,mode);
            if(ip_str==NULL)
                FatalError("alert_json: cannot parse '%s' line in '%s' file\n",line_buffer,filename);
            *llinst_iterator = ip_str;
            llinst_iterator = &ip_str->next;
            ip_str->next=NULL;
        }
    }

    fclose(file);
}

/*
 * Function SearchNumberStr
 *
 * Purpose: Find a number in the list and return the associated node.
 *
 * Arguments: number   => number to search
 *            list     => list to search in
 *            mode     => See FILLHOSTSLIST_MODE
 */
Number_str_assoc * SearchNumberStr(uint32_t number,const Number_str_assoc *iplist,FILLHOSTSLIST_MODE mode){
    Number_str_assoc * node=NULL;
    
    switch (mode){
        case HOSTS:
        case NETWORKS:
        {
            sfip_t ip_to_cmp;
            const SFIP_RET ret = sfip_set_raw(&ip_to_cmp, &number, AF_INET);
            if(ret!=SFIP_SUCCESS)
                FatalError("alert_json: Cannot create sfip to compare in line %lu",__LINE__);

            for(node = (Number_str_assoc *)iplist;node;node=node->next){
                if(mode==HOSTS && sfip_equals(ip_to_cmp,node->number.ip))
                    break;
                else if(mode==NETWORKS && sfip_fast_cont4(&node->number.ip,&ip_to_cmp))
                    break;
            }
        }
        break;
        case SERVICES:
        case PROTOCOLS:
        case VLANS:
            for(node=(Number_str_assoc *)iplist;node;node=node->next){
                if(node->number.service /* same as .protocol or .vlan*/ == number)
                    break;
            }
            break;
    };
    return node;
}