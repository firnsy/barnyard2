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

    DEBUG_WRAP(DebugMessage(DEBUG_MAPS_DEEP, "map: parsing reference %s\n", args););
    
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

ClassType * ClassTypeLookupByTypePure(ClassType *node, char *type)
{
    
    if( (node == NULL) ||
	(type == NULL))
    {
        return NULL;
    }
    
    
    while (node != NULL)
    {
        if (strcasecmp(type, node->type) == 0)
	    return node;
	
        node = node->next;
    }
    
    return NULL;
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

int ReadClassificationFile(Barnyard2Config *bc)
{
    FILE        *fd;
    char        buf[BUFFER_SIZE];
    char        *index;
    char        **toks;
    int         num_toks;
    int         count = 0;
    
    if( (bc == NULL) ||
	(bc->class_file == NULL))
    {
	/* XXX */
	return 1;
    }
    
    DEBUG_WRAP(DebugMessage(DEBUG_MAPS, "map: opening file %s\n", bc->class_file););
    
    if((fd = fopen(bc->class_file, "r")) == NULL)
    {
        LogMessage("ERROR: Unable to open Classification file '%s' (%s)\n", 
		   bc->class_file, strerror(errno));
        
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



/*
   Classification parsing should happen before signature parsing,
   so classification resolution should be done at signature initialization.

   But at the moment this function was written classification could be parsed before
   signature or signature before classification, thus leading to possible unresolvability.

   hence.
*/
int SignatureResolveClassification(ClassType *class,SigNode *sig,char *sid_msg_file,char *classification_file)
{
    
    ClassType *found = NULL;
    
    if( (class == NULL) ||
        (sig == NULL) ||
	(sid_msg_file == NULL) ||
	(classification_file == NULL))
    {
	DEBUG_WRAP(DebugMessage(DEBUG_MAPS,"ERROR [%s()]: Failed class ptr [0x%x], sig ptr [0x%x], "
				"sig_literal ptr [0x%x], sig_map_file ptr [0x%x], classification_file ptr [0x%x] \n",
				__FUNCTION__,
				class,
				sig,
				sig->classLiteral,
				sid_msg_file,
				classification_file););
	return 1;
    }
    
    while(sig != NULL)
    {
	found = NULL;

	if(sig->classLiteral)
	{
	    if(strncasecmp(sig->classLiteral,"NOCLASS",strlen("NOCLASS")) == 0)
	    {
		DEBUG_WRAP(DebugMessage(DEBUG_MAPS,
					"\nINFO: [%s()],In File [%s] \n"
					"Signature [gid: %d] [sid : %d] [revision: %d] message [%s] has no classification [%s] defined, signature priority is [%d]\n\n",
					__FUNCTION__,
					BcGetSourceFile(sig->source_file),
					sig->generator,
					sig->id,
					sig->rev,
					sig->msg,
					sig->classLiteral,
					sig->priority););
			   
	    }
	    else if( (found = ClassTypeLookupByTypePure(class,sig->classLiteral)) == NULL)
	    {
		sig->class_id = 0;
	    }
	    else
	    {
		sig->class_id = found->id;
	    }
	}
	else
	{
	    if(sig->class_id == 0)
	    {
		
		DEBUG_WRAP(DebugMessage(DEBUG_MAPS,
					"\nINFO: [%s()],In file [%s]\n"
					"Signature [gid: %d] [sid : %d] [revision: %d] message [%s] has no classification literal defined, signature priority is [%d]\n\n",
					__FUNCTION__,
					BcGetSourceFile(sig->source_file),
					sig->generator,
					sig->id,
					sig->rev,
					sig->msg,
					sig->priority););
	    }
	}
	
	if(sig->priority == 0)
	{
	    if(found)
		sig->priority = found->priority;
	}
	else
	{
	    if( (found) &&
		(found->priority != sig->priority))
	    {
		DEBUG_WRAP(DebugMessage(DEBUG_MAPS,
					"\nINFO: [%s()],In file [%s]\n"
					"Signature [gid: %d] [sid : %d] [revision: %d] message [%s] has classification [%s] priority [%d]\n"
					"The priority define by the rule will overwride classification [%s] priority [%d] defined in [%s] using [%d] as priority \n\n",
					__FUNCTION__,
					BcGetSourceFile(sig->source_file),
					sig->generator,
					sig->id,
					sig->rev,
					sig->msg,
					sig->classLiteral,
					sig->priority,
					found->type,
					found->priority,
					classification_file,
					sig->priority););
	    }
	}
    	
	if(sig->classLiteral)
	{
	    free(sig->classLiteral);
	    sig->classLiteral = NULL;
	}
	
	sig = sig->next;
    }

    return 0;
}

u_int32_t SigLookup(SigNode *head,u_int32_t gid,u_int32_t sid,u_int8_t source_file,SigNode **r_node)
{
    if( (head == NULL) ||
	(r_node == NULL))
    {
	return 0;
    }

    while(head != NULL)
    {

	if(head->source_file == source_file)
	{
	    if( (head->generator == gid) &&
		(head->id == sid))
	    {
		*r_node = head;
		return 1;
	    }
	}

	head = head->next;
    }
    

    *r_node = NULL;
    return 0;

}



int ReadSidFile(Barnyard2Config *bc)
{
    FILE *fd;
    char buf[BUFFER_SIZE];
    char *index;
    int count = 0;
    
    if(bc == NULL)
    {
	return 1;
    }

    if(bc->sid_msg_file == NULL)
    {
	return 0;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_MAPS, "[%s()] map: opening file %s\n", 
			    __FUNCTION__,
			    bc->sid_msg_file););   

    if( (fd = fopen(bc->sid_msg_file, "r")) == NULL )
    {
        LogMessage("ERROR: Unable to open SID file '%s' (%s)\n", 
		   bc->sid_msg_file, 
		   strerror(errno));
	return 1;
    }
    
    memset(buf, 0, BUFFER_SIZE); /* bzero() deprecated, replaced by memset() */
    
    while(fgets(buf, BUFFER_SIZE, fd) != NULL)
    {
        index = buf;
	
        /* advance through any whitespace at the beginning of the line */
        while(*index == ' ' || *index == '\t')
            index++;
	
	/* Check if we are dealing with a sidv2 file */
	if( (count == 0) && 
	    (bc->sidmap_version == 0))
	{
	    if(*index == '#')
	    {
		index++;
		if(strncasecmp(index,SIDMAPV1STRING,strlen(SIDMAPV1STRING)) == 0)
		{
		    bc->sidmap_version=SIDMAPV1;
		    continue;
		}
		else if( strncasecmp(index,SIDMAPV2STRING,strlen(SIDMAPV2STRING)) == 0)
		{
		    bc->sidmap_version=SIDMAPV2;
		    continue;
		}
	    }
	    else
	    {
		bc->sidmap_version=SIDMAPV1;
	    }
	}

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

  return 0;
}



void ParseSidMapLine(Barnyard2Config *bc, char *data)
{

    SigNode *sn = NULL;
    SigNode t_sn = {0}; 

    char **toks = NULL;
    char *idx = NULL;
    
    int num_toks = 0;
    int min_toks = 0;
    int i = 0;
    
    toks = mSplitSpecial(data, "||", 32, &num_toks, '\0');
    
    switch(bc->sidmap_version)
    {
    case SIDMAPV1:
	min_toks = 2;
	break;

    case SIDMAPV2:
	min_toks = 6;
	break;
	
    default:
	FatalError("[%s()]: Unknown sidmap file version [%d] \n",
		   __FUNCTION__,
		   bc->sidmap_version);
    }
    
    if(num_toks < min_toks)
    {
        LogMessage("WARNING: Ignoring bad line in SID file: '%s'\n", data);
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_MAPS_DEEP, "map: creating new node\n"););

	
        for(i = 0; i<num_toks; i++)
        { 
            strtrim(toks[i]);
            strip(toks[i]);
            idx = toks[i];
            while(*idx == ' ') idx++;

	    if( (idx == NULL) ||
		(strlen(idx) == 0))
	    {
		LogMessage("\n");
		FatalError("[%s()], File [%s],\nError in map definition [%s] for value [%s] \n\n",
			   __FUNCTION__,
			   bc->sid_msg_file,
			   data,
			   idx);
	    }

	    switch(bc->sidmap_version)
	    {
	    case SIDMAPV1:
		switch(i)
		{
                case 0: /* sid */
                    t_sn.generator = 1;
		    if( (t_sn.id = strtoul(idx, NULL, 10)) == ULONG_MAX)
		    {
			FatalError("[%s()], error converting integer [%s] for line [%s] \n",
				   __FUNCTION__,
				   strerror(errno),
				   data);
		    }
		    break;
		    
                case 1: /* msg */
                    if( (t_sn.msg = SnortStrdup(idx)) == NULL)
		    {
			FatalError("[%s()], error converting string for line [%s] \n",
				   __FUNCTION__,
				   data);
		    }
                    break;
		    
                default: /* reference data */
                    ParseReference(bc, idx, &t_sn);
                    break;
		}
		break;
		
	    case SIDMAPV2:

		switch(i)
		{

		case 0: /*gid */
		    if( (t_sn.generator = strtoul(idx,NULL,10)) == ULONG_MAX)
		    {
                        FatalError("[%s()], error converting integer [%s] for line [%s] \n",
                                   __FUNCTION__,
                                   strerror(errno),
                                   data);
                    }

		    break;

		case 1: /* sid */
		    if( (t_sn.id = strtoul(idx, NULL, 10)) == ULONG_MAX)
		    {
                        FatalError("[%s()], error converting integer [%s] for line [%s] \n",
                                   __FUNCTION__,
                                   strerror(errno),
                                   data);
                    }
		    break;

		case 2: /* revision */
		    if( (t_sn.rev = strtoul(idx, NULL, 10)) == ULONG_MAX)
		    {
                        FatalError("[%s()], error converting integer [%s] for line [%s] \n",
                                   __FUNCTION__,
                                   strerror(errno),
                                   data);
                    }
		    break;
		    
		case 3: /* classification */
		    if( (t_sn.classLiteral = SnortStrdup(idx)) == NULL)
		    {
			FatalError("[%s()], error converting string for line [%s] \n",
				   __FUNCTION__,
				   data);
		    }
		    break;

		case 4: /* priority */
		    
		    if( (t_sn.priority = strtoul(idx, NULL, 10)) == ULONG_MAX)
		    {
                        FatalError("[%s()], error converting integer [%s] for line [%s] \n",
                                   __FUNCTION__,
                                   strerror(errno),
                                   data);
                    }
		    break;

		case 5: /* msg */
		    if( (t_sn.msg = SnortStrdup(idx)) == NULL)
		    {
			FatalError("[%s()], error converting string for line [%s] \n",
				   __FUNCTION__,
				   data);
		    }
		    break;
		    
		default: /* reference data */
		    ParseReference(bc, idx, &t_sn);
		    break;
		}
		break;
	    }
	}
    }
    
    sn = (SigNode *)*BcGetSigNodeHead();
    
    /* Look if we have a brother inserted from sid map file */
    sig_lookup_continue:
    if(SigLookup(sn,t_sn.generator,t_sn.id,SOURCE_SID_MSG,&sn))
    {
	if(t_sn.rev == sn->rev)
	{
	    DEBUG_WRAP(DebugMessage(DEBUG_MAPS,
				    "[%s()],Item not inserted [ gid:[%d] sid:[%d] rev:[%d] msg:[%s] class:[%d] prio:[%d] ] in signature list \n"
 				    "\t Item already present  [ gid:[%d] sid:[%d] rev:[%d] msg:[%s] class:[%d] prio:[%d] ] \n",
				    __FUNCTION__,
				    t_sn.generator,t_sn.id,t_sn.rev,t_sn.msg,t_sn.class_id,t_sn.priority, /* revision,class_id and priority are hardcoded for generator */
				    sn->generator,sn->id,sn->rev,sn->msg,sn->class_id,sn->priority););
	}
	else
	{
	    /* Continue to traverse the list to be sure */
	    sn = sn->next;
	    goto sig_lookup_continue;
	}
    }
    else
    {
        if( (sn = CreateSigNode(BcGetSigNodeHead(),SOURCE_SID_MSG)) == NULL)
        {
            FatalError("[%s()], CreateSigNode() returned a NULL node, bailing \n",
                       __FUNCTION__);
        }

        memcpy(sn,&t_sn,sizeof(SigNode));

	sn->source_file = SOURCE_SID_MSG;
    }

    mSplitFree(&toks, num_toks);
    
    return;
}

SigNode *GetSigByGidSid(u_int32_t gid, u_int32_t sid,u_int32_t revision)
{
    /* set temp node pointer to the Sid map list head */
    SigNode **sh = BcGetSigNodeHead();
    SigNode *sn = *sh;
    
    switch(BcSidMapVersion())
    {
    case SIDMAPV1:
	/* The comment below is not true anymore with  sidmapv2 files generated by pulled pork */
	
	/* a snort general rule (gid=1) and a snort dynamic rule (gid=3) use the  */
	/* the same sids and thus can be considered one in the same. */
	if (gid == 3)
	{
	    gid = 1;
	}
	
	/* find any existing Snort ID's that match */
	while (sn != NULL)
	{
	    if (sn->generator == gid && sn->id == sid)
	    {
		return sn;
	    }
	    
	    sn = sn->next;
	}
	break;
	
    case SIDMAPV2:
	while (sn != NULL)
        {
            if ( (sn->generator == gid) && 
		 (sn->id == sid) &&
		 (sn->rev == revision))
            {
                return sn;
            }
	    
            sn = sn->next;
        }
	break;
    }
    
    /* create a default message since we didn't find any match */
    sn = CreateSigNode(BcGetSigNodeHead(),SOURCE_GEN_RUNTIME);
    sn->generator = gid;
    sn->id = sid;
    sn->rev = revision;
    sn->msg = (char *)SnortAlloc(42);
    snprintf(sn->msg, 42, "Snort Alert [%u:%u:%u]", gid, sid, revision);
 
    return sn;
}



SigNode *CreateSigNode(SigNode **head,const u_int8_t source_file)
{
    SigNode       *sn = NULL;
    
    if (*head == NULL)
    {
        *head = (SigNode *) SnortAlloc(sizeof(SigNode));
	sn = *head;
	sn->source_file = source_file;
        return *head;
    }
    else
    {
        sn = *head;
	
        while (sn->next != NULL) 
	    sn = sn->next;
	
        sn->next = (SigNode *) SnortAlloc(sizeof(SigNode));
	sn->next->source_file = source_file;
        return sn->next;
    }
    
    /* XXX */
    return NULL;
}

int ReadGenFile(Barnyard2Config *bc)
{
    FILE        *fd;
    char        buf[BUFFER_SIZE];
    char        *index;
    int         count = 0;
    
    if(bc->gen_msg_file == NULL)
    {
	return 0;
    }
    
    DEBUG_WRAP(DebugMessage(DEBUG_MAPS, "[%s()] map: opening file %s\n", 
			    __FUNCTION__,
			    bc->gen_msg_file););

    if ( (fd = fopen(bc->gen_msg_file, "r")) == NULL )
    {
	LogMessage("ERROR: Unable to open Generator file \"%s\": %s\n", 
		   bc->gen_msg_file, 
		   strerror(errno));
	
	return 1;
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
    char **toks = NULL;
    char *idx = NULL;

    SigNode *sn = NULL; 
    SigNode t_sn = {0};  /* used for temp storage before lookup */
    
    int num_toks = 0;
    int i = 0;

    toks = mSplitSpecial(data, "||", 32, &num_toks, '\0');
    
    if(num_toks < 2)
    {
        LogMessage("WARNING: Ignoring bad line in SID file: \"%s\"\n", data);
	return;
    }
    
    for(i=0; i<num_toks; i++)
    {
        strip(toks[i]);
        idx = toks[i];
        while(*idx == ' ') idx++;
        
        switch(i)
        {
	case 0: /* gen */
	    if( (t_sn.generator = strtoul(idx, NULL, 10)) == ULONG_MAX)
	    {
		FatalError("[%s()], error converting integer [%s] for line [%s] \n",
			   __FUNCTION__,
			   strerror(errno),
			   data);
	    }
	    break;
	    
	case 1: /* sid */
	    if( (t_sn.id = strtoul(idx, NULL, 10)) == ULONG_MAX)
	    {
		FatalError("[%s()], error converting integer [%s] for line [%s] \n",
			   __FUNCTION__,
			   strerror(errno),
			   data);
	    }
	    break;
	    
	case 2: /* msg */
	    if( (t_sn.msg = SnortStrdup(idx)) == NULL)
	    {
		FatalError("[%s()], error converting string for line [%s] \n",
			   __FUNCTION__,
			   data);
	    }
	    break;
	    
	default: 
	    break;
        }
    }
    
    switch(BcSidMapVersion())
    {
        case SIDMAPV1:
           t_sn.rev = 1;
           t_sn.priority = 0;
           t_sn.classLiteral = strdup("NOCLASS"); /* default */
           t_sn.class_id = 0;
           break;

        case SIDMAPV2:
           /*
              Generators have pre-defined revision,classification and priority
           */
           t_sn.rev = 1;
           t_sn.classLiteral = strdup("NOCLASS"); /* default */
           t_sn.class_id = 0;
           t_sn.priority = 3;
           break;
    }
    
    /* Look if we have a brother inserted from sid map file */
    if(SigLookup((SigNode *)*BcGetSigNodeHead(),t_sn.generator,t_sn.id,SOURCE_SID_MSG,&sn))
    {

	DEBUG_WRAP(DebugMessage(DEBUG_MAPS,
				"[%s()],Item not inserted [ gid:[%d] sid:[%d] rev:[%d] msg:[%s] class:[%d] prio:[%d] ] in signature list \n"
				"\t Item already present  [ gid:[%d] sid:[%d] rev:[%d] msg:[%s] class:[%d] prio:[%d] ] \n",
				__FUNCTION__,
				t_sn.generator,t_sn.id,t_sn.rev,t_sn.msg,t_sn.class_id,t_sn.priority, /* revision,class_id and priority are hardcoded for generator */
				sn->generator,sn->id,sn->rev,sn->msg,sn->class_id,sn->priority););

	/* 
	   This is a quick hack for now to put sweet gid-msg.map messages up there 
	*/
	if(t_sn.msg)
	{
	    DEBUG_WRAP(DebugMessage(DEBUG_MAPS,"[%s()], swapping message [%s] for [%s] \n",
				    __FUNCTION__,
				    sn->msg,
				    t_sn.msg););
	    free(sn->msg);
	    sn->msg = NULL;
	    sn->msg = t_sn.msg;
	    t_sn.msg = NULL;
	}

	if(t_sn.classLiteral)
	{
	    free(t_sn.classLiteral);
	    t_sn.classLiteral = NULL;
	}
	
	DEBUG_WRAP(DebugMessage(DEBUG_MAPS,"\n"););
	
    }
    else
    {
	if(SigLookup((SigNode *)*BcGetSigNodeHead(),t_sn.generator,t_sn.id,SOURCE_GEN_MSG,&sn) == 0)
	{
	    if( (sn = CreateSigNode(BcGetSigNodeHead(),SOURCE_GEN_MSG)) == NULL)
	    {
		FatalError("[%s()], CreateSigNode() returned a NULL node, bailing \n",
			   __FUNCTION__);
	    }
	 
	    memcpy(sn,&t_sn,sizeof(SigNode));
	    
	    sn->source_file = SOURCE_GEN_MSG;
	}
	else
	{
	    
	    DEBUG_WRAP(DebugMessage(DEBUG_MAPS,
				    "[%s()],Item not inserted [ gid:[%d] sid:[%d] rev:[%d] msg:[%s] class:[%d] prio:[%d] ] in signature list \n"
				    "\t Item already present  [ gid:[%d] sid:[%d] rev:[%d] msg:[%s] class:[%d] prio:[%d] ] \n\n",
				    __FUNCTION__,
				    t_sn.generator,t_sn.id,t_sn.rev,t_sn.msg,t_sn.class_id,t_sn.priority, /* revision,class_id and priority are hardcoded for generator */
				    sn->generator,sn->id,sn->rev,sn->msg,sn->class_id,sn->priority););
	    
	    if(t_sn.msg)
	    {
		free(t_sn.msg);
		t_sn.msg = NULL;
	    }
	    
	    if(t_sn.classLiteral)
	    {
		free(t_sn.classLiteral);
		t_sn.classLiteral = NULL;
	    }

	}
    }
	
    mSplitFree(&toks, num_toks);

    return;
}

/* 
 * Some destructors 
 * 
 *
 */

void FreeSigNodes(SigNode **sigHead)
{
    SigNode *sn = NULL, *snn = NULL;
    ReferenceNode *rn = NULL, *rnn = NULL;
    sn = *sigHead;

    while(sn != NULL)
    {
        snn = sn->next;
    
        /* free the message */
        if(sn->msg)
	{
            free(sn->msg);
	    sn->msg = NULL;
	}
    
	if(sn->classLiteral)
	{
	    free(sn->classLiteral);
	    sn->classLiteral = NULL;
	}

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
	free(sn);
	sn = NULL;
        sn = snn;
    }

    *sigHead = NULL;
    
    return;
}

void FreeClassifications(ClassType **i_head)
{
    ClassType *head = *i_head;
    
    while (head != NULL)
    {
        ClassType *tmp = head;

        head = head->next;

        if (tmp->name != NULL)
            free(tmp->name);

        if (tmp->type != NULL)
            free(tmp->type);

        free(tmp);
    }

    *i_head = NULL;
}


void FreeReferences(ReferenceSystemNode **i_head)
{
    ReferenceSystemNode *head = *i_head;
    
    while (head != NULL)
    {
        ReferenceSystemNode *tmp = head;

        head = head->next;
	
        if (tmp->name != NULL)
            free(tmp->name);
	
        if (tmp->url != NULL)
            free(tmp->url);
	
        free(tmp);
    }

    *i_head = NULL;
}

void FreeSigSuppression(SigSuppress_list **i_head)
{
    SigSuppress_list *head = *i_head;
    
    while(head != NULL)
    {
	SigSuppress_list *next = head->next;
	
	free(head);
	head = next;
    }

    *i_head = NULL;
}
