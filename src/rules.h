/*
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
*/

/* $Id$ */
#ifndef __RULES_H__
#define __RULES_H__


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "decode.h"
#include "plugbase.h"
#include "sf_types.h"

#define EXCEPT_SRC_IP  0x01
#define EXCEPT_DST_IP  0x02
#define ANY_SRC_PORT   0x04
#define ANY_DST_PORT   0x08
#define ANY_FLAGS      0x10
#define EXCEPT_SRC_PORT 0x20
#define EXCEPT_DST_PORT 0x40
#define BIDIRECTIONAL   0x80
#define ANY_SRC_IP      0x100
#define ANY_DST_IP      0x200

#define EXCEPT_IP      0x01

#define R_FIN          0x01
#define R_SYN          0x02
#define R_RST          0x04
#define R_PSH          0x08
#define R_ACK          0x10
#define R_URG          0x20
#define R_RES2         0x40
#define R_RES1         0x80

#define MODE_EXIT_ON_MATCH   0
#define MODE_FULL_SEARCH     1

#define CHECK_SRC_IP         0x01
#define CHECK_DST_IP         0x02
#define INVERSE              0x04
#define CHECK_SRC_PORT       0x08
#define CHECK_DST_PORT       0x10

#define SESSION_PRINTABLE    1
#define SESSION_ALL          2

#define RESP_RST_SND         0x01
#define RESP_RST_RCV         0x02
#define RESP_BAD_NET         0x04
#define RESP_BAD_HOST        0x08
#define RESP_BAD_PORT        0x10

#define MODE_EXIT_ON_MATCH   0
#define MODE_FULL_SEARCH     1

#define SRC                  0
#define DST                  1

#ifndef PARSERULE_SIZE
#define PARSERULE_SIZE	     65535
#endif

/*  D A T A  S T R U C T U R E S  *********************************************/
/* I'm forward declaring the rules structures so that the function
   pointer lists can reference them internally */

struct _OptTreeNode;      /* forward declaration of OTN data struct */
struct _RuleTreeNode;     /* forward declaration of RTN data struct */
struct _ListHead;    /* forward decleartion of ListHead data struct */

typedef enum _RuleType
{
    RULE_TYPE__NONE = 0,
    RULE_TYPE__ACTIVATE,
    RULE_TYPE__ALERT,
    RULE_TYPE__DROP,
    RULE_TYPE__DYNAMIC,
    RULE_TYPE__LOG,
    RULE_TYPE__PASS,
#ifdef GIDS
    RULE_TYPE__REJECT,
    RULE_TYPE__SDROP,
#endif
    RULE_TYPE__MAX

} RuleType;

/* function pointer list for rule head nodes */
typedef struct _RuleFpList
{
    /* context data for this test */
    void *context;

    /* rule check function pointer */
    int (*RuleHeadFunc)(Packet *, struct _RuleTreeNode *, struct _RuleFpList *, int);

    /* pointer to the next rule function node */
    struct _RuleFpList *next;
} RuleFpList;

/* same as the rule header FP list */
typedef struct _OptFpList
{
    /* context data for this test */
    void *context;

    int (*OptTestFunc)(void *option_data, Packet *p);

    struct _OptFpList *next;

    unsigned char isRelative;
	// firnsy
	// required for detection-plugins
    //option_type_t type;			

} OptFpList;

typedef struct _RspFpList
{
    int (*func)(Packet *, struct _RspFpList *);
    void *params; /* params for the plugin.. type defined by plugin */
    struct _RspFpList *next;
} RspFpList;



typedef struct _TagData
{
    int tag_type;       /* tag type (session/host) */
    int tag_seconds;    /* number of "seconds" units to tag for */
    int tag_packets;    /* number of "packets" units to tag for */
    int tag_bytes;      /* number of "type" units to tag for */
    int tag_metric;     /* (packets | seconds | bytes) units */
    int tag_direction;  /* source or dest, used for host tagging */
} TagData;


typedef struct _OptTreeNode
{
    /* plugin/detection functions go here */
    OptFpList *opt_func;
    RspFpList *rsp_func;  /* response functions */
    OutputFuncNode *outputFuncs; /* per sid enabled output functions */

    /* the ds_list is absolutely essential for the plugin system to work,
       it allows the plugin authors to associate "dynamic" data structures
       with the rule system, letting them link anything they can come up 
       with to the rules list */
//    void *ds_list[PLUGIN_MAX];   /* list of plugin data struct pointers */

    int chain_node_number;

    int evalIndex;       /* where this rule sits in the evaluation sets */
                            
    int proto;           /* protocol, added for integrity checks 
                            during rule parsing */

    int session_flag;    /* record session data */

    char *logto;         /* log file in which to write packets which 
                            match this rule*/
    /* metadata about signature */
//    SigInfo sigInfo;

    uint8_t stateless;  /* this rule can fire regardless of session state */
    uint8_t established; /* this rule can only fire if it is established */
    uint8_t unestablished;

//    Event event_data;

//    void* detection_filter; /* if present, evaluated last, after header checks */
    TagData *tag;

    /* stuff for dynamic rules activation/deactivation */
    int active_flag;
    int activation_counter;
    int countdown;
    int activates;
    int activated_by;

    struct _OptTreeNode *OTN_activation_ptr;
    struct _RuleTreeNode *RTN_activation_ptr;

    struct _OptTreeNode *next;

    struct _OptTreeNode *nextSoid;

    /* ptr to list of RTNs (head part) */
    struct _RuleTreeNode **proto_nodes; 

    /**number of proto_nodes. */
    unsigned short proto_node_num;

    uint8_t failedCheckBits;

    int rule_state; /* Enabled or Disabled */

#ifdef PERF_PROFILING
    uint64_t ticks;
    uint64_t ticks_match;
    uint64_t ticks_no_match;
    uint64_t checks;
    uint64_t matches;
    uint64_t alerts;
    uint8_t noalerts; 
#endif

    int pcre_flag; /* PPM */
    uint64_t ppm_suspend_time; /* PPM */
    uint64_t ppm_disable_cnt; /*PPM */

    char generated;
    uint32_t num_detection_opts;

    /**unique index generated in ruleIndexMap.
     */ 
    int ruleIndex;

} OptTreeNode;


typedef struct _ActivateListNode
{
    int activated_by;
    struct _ActivateListNode *next;

} ActivateListNode;
 

#if 0 /* RELOCATED to parser/IpAddrSet.h */
typedef struct _IpAddrSet
{
    uint32_t ip_addr;   /* IP addr */
    uint32_t netmask;   /* netmask */
    uint8_t  addr_flags; /* flag for normal/exception processing */

    struct _IpAddrSet *next;
} IpAddrSet;
#endif /* RELOCATED to parser/IpAddrSet.h */

typedef struct _RuleTreeNode
{
    RuleFpList *rule_func; /* match functions.. (Bidirectional etc.. ) */

    int head_node_number;

    RuleType type;

//    IpAddrSet *sip;
//    IpAddrSet *dip;
    
    //PORTLISTS used for debugging.
    int proto;

#ifdef PORTLISTS
    PortObject * src_portobject;
    PortObject * dst_portobject;
#else
    int not_sp_flag;     /* not source port flag */

    uint16_t hsp;         /* hi src port */
    uint16_t lsp;         /* lo src port */

    int not_dp_flag;     /* not dest port flag */

    uint16_t hdp;         /* hi dest port */
    uint16_t ldp;         /* lo dest port */
#endif

    uint32_t flags;     /* control flags */

    /* stuff for dynamic rules activation/deactivation */
    int active_flag;
    int activation_counter;
    int countdown;
    ActivateListNode *activate_list;

#if 0
    struct _RuleTreeNode *right;  /* ptr to the next RTN in the list */

    /** list of rule options to associate with this rule node */
    OptTreeNode *down;   
#endif

    /**points to global parent RTN list (Drop/Alert) which contains this 
     * RTN.
     */
    struct _ListHead *listhead;

    /**reference count from otn. Multiple OTNs can reference this RTN with the same
     * policy.
     */
    unsigned int otnRefCount;

} RuleTreeNode;

struct _RuleListNode;

typedef struct _ListHead
{
    struct _OutputFuncNode *LogList;
    struct _OutputFuncNode *AlertList;
    struct _RuleListNode *ruleListNode;
} ListHead; 

typedef struct _RuleListNode
{
    ListHead *RuleList;         /* The rule list associated with this node */
    RuleType mode;              /* the rule mode */
    int rval;                   /* 0 == no detection, 1 == detection event */
    int evalIndex;              /* eval index for this rule set */
    char *name;                 /* name of this rule list (for debugging)  */
    struct _RuleListNode *next; /* the next RuleListNode */
} RuleListNode;

typedef struct _RuleState
{
    uint32_t sid;
    uint32_t gid;
    int state;
    RuleType action;
    struct _RuleState *next;

} RuleState;

#endif /* __RULES_H__ */
