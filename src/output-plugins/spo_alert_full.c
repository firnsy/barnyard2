/*
** Copyright (C) 2002-2009 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 2000,2001 Andrew R. Baker <andrewb@uab.edu>
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

/* spo_alert_full
 * 
 * Purpose:  output plugin for full alerting
 *
 * Arguments:  alert file (eventually)
 *   
 * Effect:
 *
 * Alerts are written to a file in the snort full alert format
 *
 * Comments:   Allows use of full alerts with other output plugin types
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include <sys/types.h>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* !WIN32 */

#include <stdio.h>
#include <stdlib.h>

#include "barnyard2.h"
#include "decode.h"
#include "plugbase.h"
#include "debug.h"
#include "parser.h"
#include "util.h"
#include "log.h"
#include "mstring.h"
#include "map.h"
#include "unified2.h"

#include "sfutil/sf_textlog.h"
#include "log_text.h"

#include "spo_alert_full.h"

typedef struct _SpoAlertFullData
{
    TextLog* log;
} SpoAlertFullData;

static void AlertFullInit(char *);
static SpoAlertFullData *ParseAlertFullArgs(char *);
static void AlertFull(Packet *, void *, uint32_t, void *);
static void AlertFullCleanExit(int, void *);
static void AlertFullRestart(int, void *);

/*
 * not defined for backwards compatibility
 * (default is produced by OpenAlertFile()
#define DEFAULT_FILE  "alert.full"
 */
#define DEFAULT_LIMIT (128*M_BYTES)
#define LOG_BUFFER    (4*K_BYTES)

/*
 * Function: SetupAlertFull()
 *
 * Purpose: Registers the output plugin keyword and initialization 
 *          function into the output plugin list.  This is the function that
 *          gets called from InitOutputPlugins() in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void AlertFullSetup(void)
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterOutputPlugin("alert_full", OUTPUT_TYPE_FLAG__ALERT, AlertFullInit);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Output plugin: AlertFull is setup...\n"););
}


/*
 * Function: AlertFullInit(char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
static void AlertFullInit(char *args)
{
    SpoAlertFullData *data;
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output: AlertFull Initialized\n"););
    
    /* parse the argument list from the rules file */
    data = ParseAlertFullArgs(args);
    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Linking AlertFull functions to call lists...\n"););

    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(AlertFull, OUTPUT_TYPE__ALERT, data);
    AddFuncToCleanExitList(AlertFullCleanExit, data);
    AddFuncToRestartList(AlertFullRestart, data);
}

static void AlertFull(Packet *p, void *event, uint32_t event_type, void *arg)
{
    SpoAlertFullData	*data;
	SigNode				*sn;

	if( p == NULL || event == NULL || arg == NULL )
	{
		return;
	}

    data = (SpoAlertFullData *)arg;
	sn = GetSigByGidSid(ntohl(((Unified2EventCommon *)event)->generator_id),
			    ntohl(((Unified2EventCommon *)event)->signature_id),
			    ntohl(((Unified2EventCommon *)event)->signature_revision));



    if(sn != NULL)
    {
        TextLog_Puts(data->log, "[**] ");

        if(event != NULL)
        {
                TextLog_Print(data->log, "[%lu:%lu:%lu] ",
						(unsigned long) ntohl(((Unified2EventCommon *)event)->generator_id),
		                (unsigned long) ntohl(((Unified2EventCommon *)event)->signature_id),
		                (unsigned long) ntohl(((Unified2EventCommon *)event)->signature_revision));
        }

        if(BcAlertInterface())
        {
            TextLog_Print(data->log, " <%s> ", PRINT_INTERFACE(barnyard2_conf->interface));
            TextLog_Puts(data->log, sn->msg);
            TextLog_Puts(data->log, " [**]\n");
        }
        else
        {
            TextLog_Puts(data->log, sn->msg);
            TextLog_Puts(data->log, " [**]\n");
        }
    }
    else
    {
        TextLog_Puts(data->log, "[**] Snort Alert! [**]\n");
    }

    if(p && IPH_IS_VALID(p))
    {
        LogPriorityData(data->log,
		                ntohl(((Unified2EventCommon *)event)->classification_id),
						ntohl(((Unified2EventCommon *)event)->priority_id),
						TRUE);
    }

    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "Logging Alert data!\n"););

    LogTimeStamp(data->log, p);

    if(p && IPH_IS_VALID(p))
    {
        /* print the packet header to the alert file */

        if (BcOutputDataLink())
        {
            Log2ndHeader(data->log, p);
        }

      LogIPHeader(data->log, p);

        /* if this isn't a fragment, print the other header info */
        if(!p->frag_flag)
        {
            switch(GET_IPH_PROTO(p))
            {
                case IPPROTO_TCP:
                   LogTCPHeader(data->log, p);
                    break;

                case IPPROTO_UDP:
                   LogUDPHeader(data->log, p);
                    break;

                case IPPROTO_ICMP:
                   LogICMPHeader(data->log, p);
                    break;

                default:
                    break;
            }

           LogXrefs(data->log, sn, 1);
        }

        TextLog_Putc(data->log, '\n');
    } /* End of if(p) */
    else
    {
        TextLog_Puts(data->log, "\n\n");
    }
    TextLog_Flush(data->log);
}

/*
 * Function: ParseAlertFullArgs(char *)
 *
 * Purpose: Process positional args, if any.  Syntax is:
 * output alert_full: [<logpath> [<limit>]]
 * limit ::= <number>('G'|'M'|K')
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 */
static SpoAlertFullData *ParseAlertFullArgs(char *args)
{
    char **toks;
    int num_toks;
    SpoAlertFullData *data;
    char* filename = NULL;
    unsigned long limit = DEFAULT_LIMIT;
    int i;

    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "ParseAlertFullArgs: %s\n", args););
    data = (SpoAlertFullData *)SnortAlloc(sizeof(SpoAlertFullData));

    if ( !data )
    {
        FatalError("alert_full: unable to allocate memory!\n");
    }
    if ( !args ) args = "";
    toks = mSplit((char *)args, " \t", 0, &num_toks, '\\');

    for (i = 0; i < num_toks; i++)
    {
        const char* tok = toks[i];
        char *end;

        switch (i)
        {
            case 0:
                if ( !strcasecmp(tok, "stdout") )
                    filename = SnortStrdup(tok);

                else
                    filename = ProcessFileOption(barnyard2_conf_for_parsing, tok);
                break;

            case 1:
                limit = strtol(tok, &end, 10);

                if ( tok == end )
                    FatalError("alert_full error in %s(%i): %s\n",
                        file_name, file_line, tok);

                if ( end && toupper(*end) == 'G' )
                    limit <<= 30; /* GB */

                else if ( end && toupper(*end) == 'M' )
                    limit <<= 20; /* MB */

                else if ( end && toupper(*end) == 'K' )
                    limit <<= 10; /* KB */
                break;

            case 2:
                FatalError("alert_full: error in %s(%i): %s\n",
                    file_name, file_line, tok);
                break;
        }
    }
    mSplitFree(&toks, num_toks);

#ifdef DEFAULT_FILE
    if ( !filename ) filename = ProcessFileOption(barnyard2_conf_for_parsing, DEFAULT_FILE);
#endif

    DEBUG_WRAP(DebugMessage(
        DEBUG_INIT, "alert_full: '%s' %ld\n",
        filename ? filename : "alert", limit
    ););
    data->log = TextLog_Init(filename, LOG_BUFFER, limit);
    if ( filename ) free(filename);

    return data;
}

static void AlertFullCleanup(int signal, void *arg, const char* msg)
{
    SpoAlertFullData *data = (SpoAlertFullData *)arg;
    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "%s\n", msg););

    /* free memory from SpoAlertFullData */
    if ( data->log ) 
    {
	TextLog_Term(data->log);
    }
    
    if(data)
	free(data);
    
    return;
}

static void AlertFullCleanExit(int signal, void *arg)
{
    AlertFullCleanup(signal, arg, "AlertFullCleanExit");
}

static void AlertFullRestart(int signal, void *arg)
{
    AlertFullCleanup(signal, arg, "AlertFullRestart");
}

