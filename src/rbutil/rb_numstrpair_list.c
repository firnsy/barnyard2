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
                default:
                    ErrorMessage("Value not handled in %s %s(%d)",__FUNCTION__,__FILE__,__LINE__);
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
        ErrorMessage("fopen() alert file %s: %s\n",filename, strerror(errno));
    }

    Number_str_assoc ** llinst_iterator = list;
    while(NULL != fgets(line_buffer,1024,file) && aok){
        if(line_buffer[0]!='#' && line_buffer[0]!='\n'){
            Number_str_assoc * ip_str= FillHostList_Node(line_buffer,mode);
            if(ip_str==NULL)
            {
                ErrorMessage("alert_json: cannot parse '%s' line in '%s' file\n",line_buffer,filename);
            }
            else
            {
                *llinst_iterator = ip_str;
                llinst_iterator = &ip_str->next;
                ip_str->next=NULL;
            }
        }
    }

    fclose(file);
}

void FillFixLengthList(const char *filename,char ** list,const int listlen)
{
    char line_buffer[1024];
    FILE * file;
    int aok=1;
    int num_toks=0;
    char ** toks=NULL;
    
    if((file = fopen(filename, "r")) == NULL)
    {
        ErrorMessage("fopen() alert file %s: %s\n",filename, strerror(errno));
    }

    while(NULL != fgets(line_buffer,1024,file) && aok){
        if(line_buffer[0]!='#' && line_buffer[0]!='\n'){
            if((toks = mSplit((char *)line_buffer, " \t", 2, &num_toks, '\\'))){
                int number = atoi(toks[1]);
                if(number<listlen)
                    list[number] = SnortStrdup(toks[0]);
                else
                    FatalError("Number %d more than maximum(%d) in %s\n",number,listlen,filename);
                mSplitFree(&toks, num_toks);
            }
            else
            {
                FatalError("Error splitting line '%s' into 2 tokens with ( \\t)",line_buffer);
            }
        }
    }

    fclose(file);
}