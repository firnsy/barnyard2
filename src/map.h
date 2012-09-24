/* 
**
** Copyright (C) 2008-2012 Ian Firns (SecurixLive) <dev@securixlive.com>
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
*/

#ifndef __MAP_H__
#define __MAP_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <sys/types.h>

#include "sf_types.h"

#define BUGTRAQ_URL_HEAD   "http://www.securityfocus.com/bid/"
#define CVE_URL_HEAD       "http://cve.mitre.org/cgi-bin/cvename.cgi?name="
#define ARACHNIDS_URL_HEAD "http://www.whitehats.com/info/IDS"
#define MCAFEE_URL_HEAD    "http://vil.nai.com/vil/content/v_"
#define URL_HEAD           "http://"
#define NESSUS_URL_HEAD	   "http://cgi.nessus.org/plugins/dump.php3?id="

#define BUFFER_SIZE  1024

struct _Barnyard2Config;

/* this contains a list of the URLs for various reference systems */
typedef struct _ReferenceSystemNode
{
    char *name;
    char *url;
    struct _ReferenceSystemNode *next;

} ReferenceSystemNode;

ReferenceSystemNode * ReferenceSystemAdd(ReferenceSystemNode **, char *, char *);
ReferenceSystemNode * ReferenceSystemLookup(ReferenceSystemNode *, char *);

int ReadReferenceFile(struct _Barnyard2Config *, const char *);
void ParseReferenceSystemConfig(struct _Barnyard2Config *, char *args);

void DeleteReferenceSystems(struct _Barnyard2Config *);


typedef struct _ReferenceNode
{
    char *id;
    ReferenceSystemNode *system;
    struct _ReferenceNode *next;
} ReferenceNode;

ReferenceNode * AddReference(struct _Barnyard2Config *, ReferenceNode **, char *, char *);
void DeleteReferences(struct _Barnyard2Config *);


typedef struct _ClassType
{
    char *type;		
    char *name;		/* "pretty" name */
    uint32_t id;			
    uint32_t priority;	
    struct _ClassType	*next;


} ClassType;


typedef struct _SigNode
{
    uint32_t			generator;	/* generator ID */
    uint32_t			id;			/* Snort ID */
    uint32_t			rev;		/* revision (for future expansion) */
    uint32_t			class_id;
    uint32_t			priority;			
    char			*msg;		/* messages */
    ClassType			*classType;
    ReferenceNode		*refs;		/* references (eg bugtraq) */
    struct _SigNode		*next;

} SigNode;



ClassType * ClassTypeLookupByType(struct _Barnyard2Config *, char *);
ClassType * ClassTypeLookupById(struct _Barnyard2Config *, int);

int ReadClassificationFile(struct _Barnyard2Config *, const char *);
void ParseClassificationConfig(struct _Barnyard2Config *, char *args);

void DeleteClassTypes();

SigNode *GetSigByGidSid(uint32_t, uint32_t);

int ReadSidFile(struct _Barnyard2Config *, const char *);
void ParseSidMapLine(struct _Barnyard2Config *, char *);

int ReadGenFile(struct _Barnyard2Config *, const char *);
void ParseGenMapLine(char *);

void DeleteSigNodes();

SigNode *CreateSigNode(SigNode **);


#endif  /* __MAP_H__ */
