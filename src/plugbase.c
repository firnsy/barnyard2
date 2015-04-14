/* $Id$ */
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

/*
** Modifications by: Ian Firns <firnsy@securixlive.com>
**
** History:
**   2008-05-09 - Cleaned and amalgamated the input and output plugin API into
**                the one file.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

//#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>

#include "plugbase.h"
#include "barnyard2.h"
#include "debug.h"
#include "util.h"

#include "unified2.h"

/* built-in input plugins */
#include "input-plugins/spi_unified2.h"

/* built-in output plugins */
#include "output-plugins/spo_alert_arubaaction.h"
#include "output-plugins/spo_alert_bro.h"
#include "output-plugins/spo_alert_cef.h"
#include "output-plugins/spo_alert_csv.h"
#include "output-plugins/spo_alert_json.h"
#include "output-plugins/spo_alert_fast.h"
#include "output-plugins/spo_alert_full.h"
#include "output-plugins/spo_alert_fwsam.h"
#include "output-plugins/spo_alert_syslog.h"
#include "output-plugins/spo_alert_test.h"
#include "output-plugins/spo_alert_prelude.h"
#include "output-plugins/spo_alert_unixsock.h"
#include "output-plugins/spo_database.h"
#include "output-plugins/spo_log_ascii.h"
#include "output-plugins/spo_log_null.h"
#include "output-plugins/spo_log_tcpdump.h"
#include "output-plugins/spo_echidna.h"
#include "output-plugins/spo_sguil.h"
#include "output-plugins/spo_syslog_full.h"

extern InputConfigFuncNode  *input_config_funcs;
extern OutputConfigFuncNode *output_config_funcs;
extern PluginSignalFuncNode *plugin_shutdown_funcs;
extern PluginSignalFuncNode *plugin_clean_exit_funcs;
extern PluginSignalFuncNode *plugin_restart_funcs;

extern InputFuncNode  *InputList;
extern OutputFuncNode *AlertList;
extern OutputFuncNode *LogList;

extern Barnyard2Config *barnyard2_conf_for_parsing;
extern int file_line;
extern char *file_name;

/***************************** Input Plugin API  *****************************/
/*InputKeywordList *InputKeywords;

InputFuncNode *InputList;
*/
void RegisterInputPlugins()
{
    LogMessage("Initializing Input Plugins!\n");
    Unified2Setup();
}

InputFuncNode *GetInputPlugin(char *keyword)
{
    InputFuncNode *node = InputList;

    if (keyword == NULL)
        return NULL;

    while ((node != NULL) && (strcasecmp(keyword, node->keyword) != 0))
    {
        node = node->next;
    }

    if (node == NULL)
    {
        FatalError("unknown input plugin: '%s'\n", keyword);
    }

    return node;
}

/****************************************************************************
 *
 * Function: RegisterInputPlugin(char *, InputConfigFunc *)
 *
 * Purpose:  Associates an input statement with its function. It will also
 * setup a InputFunctionNode of the same keyword which stores the 
 * apppropriate file processing methods.
 *
 * Arguments: keyword => The input keyword to associate with the
 *                       input processor
 *            *func => function pointer to the handler
 *
 * Returns: void function
 *
 ***************************************************************************/
void RegisterInputPlugin(char *keyword, InputConfigFunc func)
{
    InputConfigFuncNode *node = (InputConfigFuncNode *)SnortAlloc(sizeof(InputConfigFuncNode));
    InputFuncNode *node2 = (InputFuncNode *)SnortAlloc(sizeof(InputFuncNode));

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Registering keyword:input => %s:%p\n", 
                            keyword, func););

    if (input_config_funcs == NULL)
    {
        input_config_funcs = node;
    }
    else
    {
        InputConfigFuncNode *tmp = input_config_funcs;
        InputConfigFuncNode *last;

        do
        {
            if (strcasecmp(tmp->keyword, keyword) == 0)
            {
                free(node);
                FatalError("Duplicate input keyword: %s\n", keyword);
            }

            last = tmp;
            tmp = tmp->next;

        } while (tmp != NULL);

        last->next = node;
    }

    node->keyword = SnortStrdup(keyword);
    node->func = func;

    if (InputList == NULL)
    {
        InputList = node2;
    }
    else
    {
        InputFuncNode *tmp2 = InputList;
        InputFuncNode *last2;

        do
        {
            if (strcasecmp(tmp2->keyword, keyword) == 0)
            {
                free(node2);
                FatalError("Duplicate input keyword: %s\n", keyword);
            }

            last2 = tmp2;
            tmp2 = tmp2->next;

        } while (tmp2 != NULL);

        last2->next = node2;
    }

    node2->keyword = SnortStrdup(keyword);
}


InputConfigFunc GetInputConfigFunc(char *keyword)
{
    InputConfigFuncNode *head = input_config_funcs;

    if (keyword == NULL)
        return NULL;

    while (head != NULL)
    {
        if (strcasecmp(head->keyword, keyword) == 0)
           return head->func; 

        head = head->next;
    }

    return NULL;
}

/****************************************************************************
 *
 * Function: DumpInputPlugins()
 *
 * Purpose:  Prints the keyword->function list
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ***************************************************************************/
void DumpInputPlugins()
{
    InputConfigFuncNode *idx = input_config_funcs;
    InputFuncNode *ifn = NULL;

    LogMessage("-------------------------------------------------\n");
    LogMessage(" Keyword     |          Input @ \n");
    LogMessage("-------------------------------------------------\n");
    while(idx != NULL)
    {
        LogMessage("%-13s: init() = %p\n", idx->keyword, idx->func);
        ifn = GetInputPlugin(idx->keyword);

        if ((ifn != NULL) && ifn->configured_flag)
        {
            LogMessage("%-13s:   - readRecordHeader() = %p\n", 
                            ifn->keyword, ifn->readRecordHeader);
            LogMessage("%-13s:   - readRecord()       = %p\n", 
                            ifn->keyword, ifn->readRecord);
        }

        idx = idx->next;
    }
    LogMessage("-------------------------------------------------\n\n");
}

int AddArgToInputList(char *keyword, void *arg)
{
    InputFuncNode *node;

    if(keyword == NULL)
        return -1;
    
    node = GetInputPlugin(keyword);

    node->arg = arg;

    return 0;
}

int AddReadRecordHeaderFuncToInputList(char *keyword, int (*readRecordHeader)(void *))
{
    InputFuncNode *node;

    if(keyword == NULL)
        return -1;
    
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Registering keyword:readRecordHeader => %s:%p\n", 
                            keyword, readRecordHeader););

    node = GetInputPlugin(keyword);

    node->readRecordHeader = readRecordHeader;
    node->configured_flag = InputFuncNodeConfigured(node);
    
    return 0;
}

int AddReadRecordFuncToInputList(char *keyword, int (*readRecord)(void *))
{
    InputFuncNode *node;

    if(keyword == NULL)
        return -1;
    
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Registering keyword:readRecord => %s:%p\n", 
                            keyword, readRecord););

    node = GetInputPlugin(keyword);

    node->readRecord = readRecord;
    node->configured_flag = InputFuncNodeConfigured(node);

    return 0;
}

int InputFuncNodeConfigured(InputFuncNode *ifn)
{
    /* if not all functions are defined then return a zero flag */
    if (!ifn->readRecordHeader || !ifn->readRecord)
        return 0;

    return 1;
}


/***************************** Output Plugin API  *****************************/
extern OutputConfigFuncNode *output_config_funcs;

static void AppendOutputFuncList(OutputFunc, void *, OutputFuncNode **);

void RegisterOutputPlugins(void)
{
    LogMessage("Initializing Output Plugins!\n");
    
    AlertCEFSetup();
    AlertSyslogSetup();

#ifdef HAVE_LIBPCAP
    LogTcpdumpSetup();
#endif /* HAVE_LIBPCAP */

    DatabaseSetup();
    AlertFastSetup();
    AlertFullSetup();
    AlertFWsamSetup();
#ifndef WIN32
    /* Win32 doesn't support AF_UNIX sockets */
    AlertUnixSockSetup();
#endif /* !WIN32 */
    AlertCSVSetup();
		AlertJSONSetup();
    LogNullSetup();
    LogAsciiSetup();

#ifdef ARUBA
    AlertArubaActionSetup();
#endif

#ifdef HAVE_LIBPRELUDE
    AlertPreludeSetup();
#endif

#ifdef BROCCOLI
    AlertBroSetup();
#endif

    AlertTestSetup();

#ifdef ENABLE_PLUGIN_ECHIDNA
    EchidnaSetup();
#endif

    SguilSetup();

    OpSyslog_Setup();

}

/****************************************************************************
 *
 * Function: RegisterOutputPlugin(char *, void (*func)(Packet *, u_char *))
 *
 * Purpose:  Associates an output statement with its function.
 *
 * Arguments: keyword => The output keyword to associate with the
 *                       output processor
 *            type => alert or log types
 *            *func => function pointer to the handler
 *
 * Returns: void function
 *
 ***************************************************************************/
void RegisterOutputPlugin(char *keyword, int type_flags, OutputConfigFunc func)
{
    OutputConfigFuncNode *node = (OutputConfigFuncNode *)SnortAlloc(sizeof(OutputConfigFuncNode));

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Registering keyword:output => %s:%p\n", 
                            keyword, func););

    if (output_config_funcs == NULL)
    {
        output_config_funcs = node;
    }
    else
    {
        OutputConfigFuncNode *tmp = output_config_funcs;
        OutputConfigFuncNode *last;

        do
        {
            if (strcasecmp(tmp->keyword, keyword) == 0)
            {
                free(node);
                FatalError("Duplicate output keyword: %s\n", keyword);
            }

            last = tmp;
            tmp = tmp->next;

        } while (tmp != NULL);

        last->next = node;
    }

    node->keyword = SnortStrdup(keyword);
    node->func = func;
    node->output_type_flags = type_flags;
}

OutputConfigFunc GetOutputConfigFunc(char *keyword)
{
    OutputConfigFuncNode *head = output_config_funcs;

    if (keyword == NULL)
        return NULL;

    while (head != NULL)
    {
        if (strcasecmp(head->keyword, keyword) == 0)
           return head->func; 

        head = head->next;
    }

    return NULL;
}

int GetOutputTypeFlags(char *keyword)
{
    OutputConfigFuncNode *head = output_config_funcs;

    if (keyword == NULL)
        return 0;

    while (head != NULL)
    {
        if (strcasecmp(head->keyword, keyword) == 0)
           return head->output_type_flags;

        head = head->next;
    }

    return 0;
}

void FreeOutputConfigFuncs(void)
{
    OutputConfigFuncNode *head = output_config_funcs;
    OutputConfigFuncNode *tmp;

    while (head != NULL)
    {
        tmp = head->next;
        if (head->keyword != NULL)
            free(head->keyword);
        free(head);
        head = tmp;
    }

    output_config_funcs = NULL;
}


void FreeInputPlugins(void)
{

    InputConfigFuncNode *tmp = input_config_funcs;
    InputConfigFuncNode *next = NULL;

    InputFuncNode *tmp2 = InputList;
    InputFuncNode *next2 = NULL;
    
    while(tmp != NULL)
    {
	next = tmp->next;

	if(tmp->keyword != NULL)
	{
	    free(tmp->keyword);
	    tmp->keyword = NULL;
	}
	
       	free(tmp);
	tmp = next;
    }
    

    while(tmp2 != NULL)
    {
	next2 =tmp2->next;
	
	if( tmp2->keyword != NULL)
	{
	    free(tmp2->keyword);
	    tmp2->keyword = NULL;
	}

	if( tmp2->arg != NULL)
	{
	    free(tmp2->arg);
	    tmp2->arg = NULL;
	}

	free(tmp2);
	tmp2 = next2;
    }
    
    input_config_funcs = NULL;
    InputList = NULL;
    return;
}


void FreeOutputList(OutputFuncNode *list)
{
    while (list != NULL)
    {
        OutputFuncNode *tmp = list;

        list = list->next;

	if(tmp != NULL)
	{
	    free(tmp);
	}
    }

}

/****************************************************************************
 *
 * Function: DumpOutputPlugins()
 *
 * Purpose:  Prints the Output keyword list
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ***************************************************************************/
void DumpOutputPlugins(void)
{
    OutputConfigFuncNode *idx = output_config_funcs;

    LogMessage("-------------------------------------------------\n");
    LogMessage(" Keyword     |          Output @ \n");
    LogMessage("-------------------------------------------------\n");
    while(idx != NULL)
    {
        LogMessage("%-13s:       %p\n", idx->keyword, idx->func);
        idx = idx->next;
    }
    LogMessage("-------------------------------------------------\n\n");
}

void AddFuncToOutputList(OutputFunc func, OutputType type, void *arg)
{
    switch (type)
    {
        case OUTPUT_TYPE__ALERT:
            AppendOutputFuncList(func, arg, &AlertList);
            break;

        case OUTPUT_TYPE__LOG:
            AppendOutputFuncList(func, arg, &LogList);
            break;

        default:
            /* just to be error-prone */
            FatalError("Unknown output type: %i. Possible bug, please "
                       "report.\n", type);
    }
}

void AppendOutputFuncList(OutputFunc func, void *arg, OutputFuncNode **list)
{
    OutputFuncNode *node;

    if (list == NULL)
        return;

    node = (OutputFuncNode *)SnortAlloc(sizeof(OutputFuncNode));

    if (*list == NULL)
    {
        *list = node;
    }
    else
    {
        OutputFuncNode *tmp = *list;

        while (tmp->next != NULL)
            tmp = tmp->next;

        tmp->next = node;
    }

    node->func = func;
    node->arg = arg;
}

int pbCheckSignatureSuppression(void *event)
{
    Unified2EventCommon *uCommon = (Unified2EventCommon *)event;
    SigSuppress_list **sHead = BCGetSigSuppressHead();
    SigSuppress_list *cNode = NULL;
    u_int32_t gid = 0;
    u_int32_t sid = 0;

    if( (uCommon == NULL) ||
	(sHead == NULL))
    {
	return 0;
    }
    
    cNode = *sHead;

    gid = ntohl(uCommon->generator_id);
    sid = ntohl(uCommon->signature_id);

    while(cNode)
    {
	if(cNode->gid == gid)
	{
	    switch(cNode->ss_type)
	    {
	    case SS_SINGLE:
		if(cNode->ss_min == sid)
		{
		    SigSuppressCount();
		    return 1;
		}
		break;
		
	    case SS_RANGE:
		if( (sid >= cNode->ss_min) &&
		    (sid <= cNode->ss_max))
		{
		    SigSuppressCount();
		    return 1;
		}
		break;

	    default:
		FatalError("[%s()], Unknown Signature suppress type \n",
			   __FUNCTION__);
		break;
	    }

	}
	cNode = cNode->next;
    }
    
    return 0;
}



void CallOutputPlugins(OutputType out_type, Packet *packet, void *event, uint32_t event_type)
{
    OutputFuncNode *idx = NULL;

    /* Plug for sid suppression */
    if(event)
    {
	if(pbCheckSignatureSuppression(event))
	    return;
    }


    if (out_type == OUTPUT_TYPE__SPECIAL)
    {
        idx = AlertList;
        while (idx != NULL)
        {
            idx->func(packet, event, event_type, idx->arg);
            idx = idx->next;
        }

        idx = LogList;
        while (idx != NULL)
        {
            idx->func(packet, event, event_type, idx->arg);
            idx = idx->next;
        }
    }
    else
    {
	//All those sub "Log" type will go away in the future..
	//Iterate Log and Alert.
	idx = LogList;
	
        while (idx != NULL)
        {
            idx->func(packet, event, event_type, idx->arg);
            idx = idx->next;
        }
	
	idx = AlertList;

        while (idx != NULL)
        {
            idx->func(packet, event, event_type, idx->arg);
            idx = idx->next;
        }
	
    }
}


/************************** Miscellaneous Functions  **************************/

void PostConfigInitPlugins(PluginSignalFuncNode *post_config_funcs)
{
    while (post_config_funcs != NULL)
    {
        post_config_funcs->func(0, post_config_funcs->arg);
        post_config_funcs = post_config_funcs->next;
    }
}

/* functions to aid in cleaning up after plugins
 * Used for both rule options and output.  Preprocessors have their own */
void AddFuncToRestartList(PluginSignalFunc func, void *arg)
{
    AddFuncToSignalList(func, arg, &plugin_restart_funcs);
}

void AddFuncToCleanExitList(PluginSignalFunc func, void *arg)
{
    AddFuncToSignalList(func, arg, &plugin_clean_exit_funcs);
}

void AddFuncToShutdownList(PluginSignalFunc func, void *arg)
{
    AddFuncToSignalList(func, arg, &plugin_shutdown_funcs);
}

void AddFuncToPostConfigList(PluginSignalFunc func, void *arg)
{
    Barnyard2Config *bc = barnyard2_conf_for_parsing;

    if (bc == NULL)
    {
        FatalError("%s(%d) Barnyard2 config for parsing is NULL.\n",
                   __FILE__, __LINE__);
    }

    AddFuncToSignalList(func, arg, &bc->plugin_post_config_funcs);
}

void AddFuncToSignalList(PluginSignalFunc func, void *arg, PluginSignalFuncNode **list)
{
    PluginSignalFuncNode *node;

    if (list == NULL)
        return;

    node = (PluginSignalFuncNode *)SnortAlloc(sizeof(PluginSignalFuncNode));

    if (*list == NULL)
    {
        *list = node;
    }
    else
    {
        PluginSignalFuncNode *tmp = *list;

        while (tmp->next != NULL)
            tmp = tmp->next;

        tmp->next = node;
    }

    node->func = func;
    node->arg = arg;
}


void FreePluginSigFuncs(PluginSignalFuncNode *head)
{
    while (head != NULL)
    {
        PluginSignalFuncNode *tmp = head;

        head = head->next;

        /* don't free sig->arg, that's free'd by the CleanExit/Restart func */
        free(tmp);
    }
}
