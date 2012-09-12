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
*/

/*
** Description:
**   In memory linked list structures of sid-msg.map, gen-msg.map and
** classification.config
**
** Author(s):
**   firnsy <firnsy@securixlive.com>
**   SecurixLive.com Team <dev@securixlive.com>
**
** Comments:
**   Ideas stolen liberally from:
**     1. the orginal barnyard (A. Baker, M. Roesch)
**
** 
**
**  
** TODO:
**   -ERROR CHECKING..........!@#$%@
**   1. Convert existing linked lists to adaptive splayed trees.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#ifdef SOLARIS
    #include <strings.h>
#endif

#include "debug.h"
#include "map.h"
#include "util.h"
#include "mstring.h"
#include "strlcatu.h"

#include "barnyard2.h"
#include "parser.h"

#include <string.h>
#include <stdlib.h>


/********************* Reference Implementation *******************************/

ReferenceNode * AddReference(Barnyard2Config *bc, ReferenceNode **head, char *system, char *id)
{
    ReferenceNode *node;

    if ((system == NULL) || (id == NULL) ||
        (bc == NULL) || (head == NULL))
    {
        return NULL;
    }

    /* create the new node */
    node = (ReferenceNode *)SnortAlloc(sizeof(ReferenceNode));
    
    /* lookup the reference system */
    node->system = ReferenceSystemLookup(bc->references, system);
    if (node->system == NULL)
        node->system = ReferenceSystemAdd(&bc->references, system, NULL);

    node->id = SnortStrdup(id);
    
    /* Add the node to the front of the list */
    node->next = *head;
    *head = node;
    
    return node;
}

/* print a reference node */
void FPrintReference(FILE *fp, ReferenceNode *ref_node)
{
    if ((fp == NULL) || (ref_node == NULL))
        return;

    if (ref_node->system != NULL)
    {
        if(ref_node->system->url)
        {
            fprintf(fp, "[Xref => %s%s]", ref_node->system->url, 
                    ref_node->id);
        }
        else
        {
            fprintf(fp, "[Xref => %s %s]", ref_node->system->name,
                    ref_node->id);
        }
    }
    else
    {
        fprintf(fp, "[Xref => %s]", ref_node->id);
    }
}

void ParseReference(Barnyard2Config *bc, char *args, SigNode *sn)
{
    char **toks, *system, *id;
    int num_toks;

    DEBUG_WRAP(DebugMessage(DEBUG_MAPS, "map: parsing reference %s\n", args););
    
    /* 2 tokens: system, id */
    toks = mSplit(args, ",", 2, &num_toks, 0);
    if(num_toks != 2)
    {
        LogMessage("WARNING: invalid Reference spec '%s'. Ignored\n", args);
    }
    else
    {
        system = toks[0];
        while ( isspace((int) *system) )
            system++;

        id = toks[1];
        while ( isspace((int) *id) )
            id++;
            
        sn->refs = AddReference(bc, &sn->refs, system, id);
    }

    mSplitFree(&toks, num_toks);

    return;
}


/********************* End of Reference Implementation ************************/

/********************** Reference System Implementation ***********************/

ReferenceSystemNode * ReferenceSystemAdd(ReferenceSystemNode **head, char *name, char *url)
{   
    ReferenceSystemNode *node;

    if (name == NULL)
    {
        ErrorMessage("NULL reference system name\n");
        return NULL;
    }

    if (head == NULL)
        return NULL;

    /* create the new node */
    node = (ReferenceSystemNode *)SnortAlloc(sizeof(ReferenceSystemNode));

    node->name = SnortStrdup(name);
    if (url != NULL)
        node->url = SnortStrdup(url);

    /* Add to the front of the list */
    node->next = *head;
    *head = node;

    return node;
}

ReferenceSystemNode * ReferenceSystemLookup(ReferenceSystemNode *head, char *name)
{
    if (name == NULL)
        return NULL;

    while (head != NULL)
    {
        if (strcasecmp(name, head->name) == 0)
            break;

        head = head->next;
    }

    return head;
}

void DeleteReferenceSystems(Barnyard2Config *bc)
{
    ReferenceSystemNode *current, *tmpReference;

    current = bc->references;
    while (current!= NULL)
    {
        tmpReference = current->next;
        if (current->url)
            free(current->url);
        if (current->name)
            free(current->name);
        free(current);
        current = tmpReference;
    }

    bc->references = NULL;
}

void ParseReferenceSystemConfig(Barnyard2Config *bc, char *args)
{
    char **toks;
    char *name = NULL;
    char *url = NULL;
    int num_toks;

    /* 2 tokens: name <url> */
    toks = mSplit(args, " ", 2, &num_toks, 0);
    name = toks[0];
    if(num_toks == 2)
    {
        url = toks[1];
        while(isspace((int)*url))
            url++;
        if(url[0] == '\0')
            url = NULL;
    }
    ReferenceSystemAdd(&bc->references, name, url);

    mSplitFree(&toks, num_toks);
    return;
}

int ReadReferenceFile(Barnyard2Config *bc, const char *file)
{
    FILE        *fd;
    char        buf[BUFFER_SIZE];
    char        *index;
    char        **toks;
    int         num_toks;
  int         count = 0;

    DEBUG_WRAP(DebugMessage(DEBUG_MAPS, "map: opening file %s\n", file););
    
    if((fd = fopen(file, "r")) == NULL)
    {
        LogMessage("ERROR: Unable to open Reference file '%s' (%s)\n", 
                file, strerror(errno));
        
        return -1;
    }

    memset(buf, 0, BUFFER_SIZE); /* bzero() deprecated, replaced with memset() */
    
    while ( fgets(buf, BUFFER_SIZE, fd) != NULL )
    {
        index = buf;

        /* advance through any whitespace at the beginning of the line */
        while (*index == ' ' || *index == '\t')
            index++;

        /* if it's not a comment or a <CR>, send it to the parser */
        if ( (*index != '#') && (*index != 0x0a) && (index != NULL) )
        {
            toks = mSplit(index, ":", 2, &num_toks, 0);
            
            if(num_toks > 1)
            {
                ParseReferenceSystemConfig(bc, toks[1]);
		count++;
            }

            mSplitFree(&toks, num_toks);
        }
    }

  if(fd != NULL)
    fclose(fd);

  return 0;
}

/****************** End of Reference System Implementation ********************/


/************************ Class/Priority Implementation ***********************/

/* NOTE:  This lookup can only be done during parse time */
/* Wut ...*/
ClassType * ClassTypeLookupByType(Barnyard2Config *bc, char *type)
{
    ClassType *node;

    if (bc == NULL)
        FatalError("Barnyard2 config is NULL.\n");

    if (type == NULL)
        return NULL;

    node = bc->classifications;

    while (node != NULL)
    {
        if (strcasecmp(type, node->type) == 0)
            break;

        node = node->next;
    }

    return node;
}

/* NOTE:  This lookup can only be done during parse time */
/* Wut ...*/
ClassType * ClassTypeLookupById(Barnyard2Config *bc, int id)
{
    ClassType *node;

    if (bc == NULL)
        FatalError("Barnyard2 config is NULL.\n");

    node = bc->classifications;

    while (node != NULL)
    {
        if (id == node->id)
            break;

        node = node->next;
    }

    return node;
}

int AddClassificationConfig(Barnyard2Config *bc, ClassType *newNode)
{
    int max_id = 0;
    ClassType *current = bc->classifications;

    while(current != NULL)
    {
        /* dup check */
        if(strcasecmp(current->type, newNode->type) == 0)
            return -1;
        
        if(current->id > max_id)
            max_id = current->id;
        
        current = current->next;
    }

    /* insert node */
    newNode->id = max_id + 1;
    newNode->next = bc->classifications;
    bc->classifications = newNode;

    return newNode->id;
}

void ParseClassificationConfig(Barnyard2Config *bc, char *args)
{
    char **toks;
    int num_toks;
    char *data;
    ClassType *newNode;

    toks = mSplit(args, ",", 3, &num_toks, '\\');

    if(num_toks != 3)
    {
        ErrorMessage(": Invalid classification config: %s\n", args);
    }
    else
    {
        /* create the new node */
        newNode = (ClassType *)SnortAlloc(sizeof(ClassType));

        data = toks[0];
        while(isspace((int)*data)) 
            data++;
        newNode->type = SnortStrdup(data);   /* XXX: oom check */

        data = toks[1];
        while(isspace((int)*data))
            data++;
        newNode->name = SnortStrdup(data);   /* XXX: oom check */

        data = toks[2];
        while(isspace((int)*data))
            data++;
        /* XXX: error checking needed */
        newNode->priority = atoi(data); /* XXX: oom check */

        if(AddClassificationConfig(bc, newNode) == -1)
        {
            ErrorMessage(": Duplicate classification \"%s\""
                    "found, ignoring this line\n", newNode->type);

            if(newNode)
            {
                if(newNode->name)
                    free(newNode->name);
                if(newNode->type)
                    free(newNode->type);
                free(newNode);
            }
        }
    }

    mSplitFree(&toks, num_toks);
    return;
}

void DeleteClassifications(Barnyard2Config *bc)
{
    ClassType           *current = bc->classifications;
    ClassType           *tmpClass;

    while (current != NULL)
    {
        tmpClass = current->next;
        if (current->type)
            free(current->type);
        if (current->name)
            free(current->name);
        free(current);
        current = tmpClass;
    }

    bc->classifications = NULL;
}

int ReadClassificationFile(Barnyard2Config *bc, const char *file)
{
    FILE        *fd;
    char        buf[BUFFER_SIZE];
    char        *index;
    char        **toks;
    int         num_toks;
    int         count = 0;
    
    
    DEBUG_WRAP(DebugMessage(DEBUG_MAPS, "map: opening file %s\n", file););
    
    if((fd = fopen(file, "r")) == NULL)
    {
        LogMessage("ERROR: Unable to open Classification file '%s' (%s)\n", 
                file, strerror(errno));
        
        return -1;
    }

    memset(buf, 0, BUFFER_SIZE); /* bzero() deprecated, replaced with memset() */
    
    while ( fgets(buf, BUFFER_SIZE, fd) != NULL )
    {
        index = buf;

        /* advance through any whitespace at the beginning of the line */
        while (*index == ' ' || *index == '\t')
            index++;

        /* if it's not a comment or a <CR>, send it to the parser */
        if ( (*index != '#') && (*index != 0x0a) && (index != NULL) )
        {
            toks = mSplit(index, ":", 2, &num_toks, 0);
            
            if(num_toks > 1)
            {
                ParseClassificationConfig(bc, toks[1]);
		count++;
            }

            mSplitFree(&toks, num_toks);
        }
    }

  if(fd != NULL)
    fclose(fd);

  return 0;
}

/***************** End of Class/Priority Implementation ***********************/

/************************* Sid/Gid Map Implementation *************************/

SigNode *sigTypes = NULL;

int ReadSidFile(Barnyard2Config *bc, const char *file)
{
    FILE *fd;
    char buf[BUFFER_SIZE];
    char *index;
    int count = 0;
    
    DEBUG_WRAP(DebugMessage(DEBUG_MAPS, "map: opening file %s\n", file););

    if( (fd = fopen(file, "r")) == NULL )
    {
        LogMessage("ERROR: Unable to open SID file '%s' (%s)\n", file, 
                strerror(errno));
        
        return -1;
    }

    memset(buf, 0, BUFFER_SIZE); /* bzero() deprecated, replaced by memset() */
    
    while(fgets(buf, BUFFER_SIZE, fd) != NULL)
    {
        index = buf;

        /* advance through any whitespace at the beginning of the line */
        while(*index == ' ' || *index == '\t')
            index++;

        /* if it's not a comment or a <CR>, send it to the parser */
        if((*index != '#') && (*index != 0x0a) && (index != NULL))
        {
            ParseSidMapLine(bc, index);
            count++;
        }
    }
    
    //LogMessage("Read [%u] signature \n",count);
    
  if(fd != NULL)
    fclose(fd);

  return count;
}

void DeleteSigNodes()
{
    SigNode *sn = NULL, *snn = NULL;
    ReferenceNode *rn = NULL, *rnn = NULL;

    sn = sigTypes;

    while(sn != NULL)
    {
        snn = sn->next;
    
        /* free the message */
        if(sn->msg)
            free(sn->msg);
    
        /* free the references (NOT the reference systems) */
        if(sn->refs)
        {
            rn = sn->refs;
            while(rn != NULL)
            {
                rnn = rn->next;
            
                /* free the id */
                if(rn->id)
                    free(rn->id);
            
                /* free the reference node */
                free(rn);

                rn = rnn;
            }
        }

        /* free the signature node */
        free(sigTypes);

        sigTypes = snn;
    }

    sigTypes = NULL;
}

void ParseSidMapLine(Barnyard2Config *bc, char *data)
{
    char **toks;
    char *idx;
    int num_toks;
    int i;
    SigNode *sn; 

    toks = mSplitSpecial(data, "||", 32, &num_toks, '\0');

    if(num_toks < 2)
    {
        LogMessage("WARNING: Ignoring bad line in SID file: '%s'\n", data);
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_MAPS, "map: creating new node\n"););

        sn = CreateSigNode(&sigTypes);
    
        for(i = 0; i<num_toks; i++)
        { 
            strtrim(toks[i]);
            strip(toks[i]);
            idx = toks[i];
            while(*idx == ' ') idx++;
              
            switch(i)
            {
                case 0: /* sid */
                    sn->generator = 1;
                    sn->id = strtoul(idx, NULL, 10);
                    break;

                case 1: /* msg */
                    sn->msg = SnortStrdup(idx);
                    break;

                default: /* reference data */
                    ParseReference(bc, idx, sn);
                    break;
            }
        }
    }

    mSplitFree(&toks, num_toks);

    return;
}

SigNode *GetSigByGidSid(u_int32_t gid, u_int32_t sid)
{
  /* set temp node pointer to the Sid map list head */
    SigNode *sn = sigTypes;
  
  /* a snort general rule (gid=1) and a snort dynamic rule (gid=3) use the  */
  /* the same sids and thus can be considered one in the same. */
  if (gid == 3)
    gid = 1;

    /* find any existing Snort ID's that match */
    while (sn != NULL)
    {
        if (sn->generator == gid && sn->id == sid)
        {
            return sn;
        }

        sn = sn->next;
    }

  /* create a default message since we didn't find any match */
    sn = CreateSigNode(&sigTypes);
    sn->generator = gid;
    sn->id = sid;
    sn->rev = 0;
    sn->msg = (char *)SnortAlloc(42);
    snprintf(sn->msg, 42, "Snort Alert [%u:%u:%u]", gid, sid, 0);
 
    return sn;
}

SigNode *CreateSigNode(SigNode **head)
{
    SigNode       *sn;

    if (*head == NULL)
    {
        *head = (SigNode *) SnortAlloc(sizeof(SigNode));
        return *head;
    }
    else
    {
        sn = *head;

        while (sn->next != NULL) 
	    sn = sn->next;
	
        sn->next = (SigNode *) SnortAlloc(sizeof(SigNode));
	
        return sn->next;
    }
    
    /* XXX */
    return NULL;
}

int ReadGenFile(Barnyard2Config *bc, const char *file)
{
    FILE        *fd;
    char        buf[BUFFER_SIZE];
    char        *index;
  int         count = 0;
    

    if ( (fd = fopen(file, "r")) == NULL )
    {
        LogMessage("ERROR: Unable to open Generator file \"%s\": %s\n", file, 
                strerror(errno));
        
        return -1;
    }

    memset(buf, 0, BUFFER_SIZE); /* bzero() deprecated, replaced by memset() */
    
    while( fgets(buf, BUFFER_SIZE, fd) != NULL )
    {
        index = buf;

        /* advance through any whitespace at the beginning of the line */
        while (*index == ' ' || *index == '\t')
            index++;

        /* if it's not a comment or a <CR>, send it to the parser */
        if( (*index != '#') && (*index != 0x0a) && (index != NULL) )
        {
            ParseGenMapLine(index);
	    count++;
        }
    }

    //LogMessage("Read [%u] gen \n",count);

  if(fd != NULL)
    fclose(fd);

  return 0;
}


void ParseGenMapLine(char *data)
{
    char **toks;
    int num_toks;
    int i;
    char *idx;
    SigNode       *sn; 
    
    toks = mSplitSpecial(data, "||", 32, &num_toks, '\0');
    
    if(num_toks < 2)
    {
        LogMessage("WARNING: Ignoring bad line in SID file: \"%s\"\n", data);
	return;
    }
    
    sn = CreateSigNode(&sigTypes);
    
    for(i=0; i<num_toks; i++)
    {
        strip(toks[i]);
        idx = toks[i];
        while(*idx == ' ') idx++;
            
        switch(i)
        {
	case 0: /* gen */
		//TODO: error checking on conversion
	    sn->generator = strtoul(idx, NULL, 10);
	    break;
	    
	case 1: /* sid */
		//TODO: error checking on conversion
	    sn->id = strtoul(idx, NULL, 10);
	    break;
	    
	case 2: /* msg */
	    sn->msg = SnortStrdup(idx);
	    break;
	    
	default: 
	    break;
        }
    }
    
    mSplitFree(&toks, num_toks);
}
