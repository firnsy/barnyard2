/*
** Copyright (C) 2007-2009 Sourcefire, Inc.
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

/* spo_alert_test_
 * 
 * Purpose:  output plugin for test alerting
 *
 * Arguments: file <file>, stdout, rebuilt, session, msg
 * arguments should be comma delimited.
 * file - specifiy alert file
 * stdout - no alert file, just print to screen
 * rebuilt - include info of whether packet was rebuilt or not
 *           S - Stream rebuilt
 *           F - IP frag rebuilt
 *           outputs: <rebuilt type>:<rebuilt count>
 * session - include src/dst IPs and ports  
 *           outputs: <sip>:<sport>-<dip>:<dport>
 * msg - include alert message
 *
 * Output is tab delimited in the following order:
 * packet count, gid, sid, rev, msg, session, rebuilt
 *
 * Examples:
 * output alert_test
 * output alert_test: session
 * output alert_test: session, msg
 * output alert_test: rebuilt, session, msg
 * output alert_test: stdout, rebuilt, session, msg
 * output alert_test: file test.alert, rebuilt, session, msg
 *   
 * Effect:
 *
 * Alerts are written to a file in the snort test alert format
 *
 * Comments:   Allows use of test alerts with other output plugin types
 *
 */

/* output plugin header file */
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
#include <string.h>

#include "barnyard2.h"
#include "decode.h"
#include "debug.h"
#include "log.h"
#include "map.h"
#include "mstring.h"
#include "parser.h"
#include "plugbase.h"
#include "unified2.h"
#include "util.h"

#include "spo_alert_test.h"
#include "ipv6_port.h"

#define TEST_FLAG_FILE     0x01
#define TEST_FLAG_STDOUT   0x02
#define TEST_FLAG_MSG      0x04
#define TEST_FLAG_SESSION  0x08
#define TEST_FLAG_REBUILT  0x10

typedef struct _SpoAlertTestData
{
    FILE *file;
    uint8_t flags;

} SpoAlertTestData;

void AlertTestInit(char *);
SpoAlertTestData *ParseAlertTestArgs(char *);
void AlertTestCleanExitFunc(int, void *);
void AlertTestRestartFunc(int, void *);
void AlertTest(Packet *, void *, uint32_t, void *);

/*
 * Function: SetupAlertTest()
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
void AlertTestSetup(void)
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterOutputPlugin("alert_test", OUTPUT_TYPE_FLAG__ALERT, AlertTestInit);
    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Output plugin: AlertTest is setup...\n"););
}


/*
 * Function: AlertTestInit(char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
void AlertTestInit(char *args)
{
    SpoAlertTestData *data;

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Output: AlertTest Initialized\n"););

    /* parse the argument list from the rules file */
    data = ParseAlertTestArgs(args);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Linking AlertTest functions to call lists...\n"););
    
    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(AlertTest, OUTPUT_TYPE__ALERT, data);
    AddFuncToCleanExitList(AlertTestCleanExitFunc, data);
    AddFuncToRestartList(AlertTestRestartFunc, data);
}

void AlertTest(Packet *p, void *event, u_int32_t event_type, void *arg)
{
    SpoAlertTestData	*data;
	SigNode				*sn;

    if (p == NULL || arg == NULL)
        return;

    data = (SpoAlertTestData *)arg;

    if(event != NULL)
    {
        fprintf(data->file, "%lu\t%lu\t%lu\t",
                (unsigned long) ntohl(((Unified2EventCommon *)event)->generator_id),
                (unsigned long) ntohl(((Unified2EventCommon *)event)->signature_id),
                (unsigned long) ntohl(((Unified2EventCommon *)event)->signature_revision));
    }
    
    if (data->flags & TEST_FLAG_MSG)
    {
		sn = GetSigByGidSid(ntohl(((Unified2EventCommon *)event)->generator_id),
				    ntohl(((Unified2EventCommon *)event)->signature_id),
				    ntohl(((Unified2EventCommon *)event)->signature_revision));

        if(sn != NULL)
        {
            fprintf(data->file, "%s\t", sn->msg); 
        }
    }

    if (data->flags & TEST_FLAG_SESSION)
    {
        if (IPH_IS_VALID(p))
        {
            fprintf(data->file, "%s:%d",
                    inet_ntoa(GET_SRC_ADDR(p)), p->sp);
            fprintf(data->file, "-%s:%d\t",
                    inet_ntoa(GET_DST_ADDR(p)), p->dp);
        }
    }

/*
    if (data->flags & TEST_FLAG_REBUILT)
    {
        if (p->packet_flags & PKT_REBUILT_FRAG)
        {
            fprintf(data->file, "F:" STDu64 "\t", pc.rebuilt_frags);
        }
        else if (p->packet_flags & PKT_REBUILT_STREAM)
        {
            fprintf(data->file, "S:" STDu64 "\t", pc.rebuilt_tcp);
        }
    }
*/
    fprintf(data->file, "\n");

    fflush(data->file);

    return;
}

/*
 * Function: ParseAlertTestArgs(char *)
 *
 * Purpose: Process the preprocessor arguements from the rules file and 
 *          initialize the preprocessor's data struct.  This function doesn't
 *          have to exist if it makes sense to parse the args in the init 
 *          function.
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 *
 */
SpoAlertTestData * ParseAlertTestArgs(char *args)
{
    char **toks;
    char *option;
    int num_toks;
    SpoAlertTestData *data;
    int i;

    data = (SpoAlertTestData *)SnortAlloc(sizeof(SpoAlertTestData));

    if(args == NULL)
    {
        data->file = OpenAlertFile(NULL);
        data->flags |= TEST_FLAG_FILE;
        return data;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "ParseAlertTestArgs: %s\n", args););

    toks = mSplit(args, ",", 5, &num_toks, 0);

    for (i = 0; i < num_toks; i++)
    {
        option = toks[i];

        while (isspace((int)*option))
            option++;

        if(strncasecmp("stdout", option, strlen("stdout")) == 0)
        {
            if (data->flags & TEST_FLAG_FILE)
            {
                FatalError("alert_test: cannot specify both stdout and file\n");
            }

            data->file = stdout;
            data->flags |= TEST_FLAG_STDOUT;
        }
        else if (strncasecmp("session", option, strlen("session")) == 0)
        {
            data->flags |= TEST_FLAG_SESSION;
        }
        else if (strncasecmp("rebuilt", option, strlen("rebuilt")) == 0)
        {
            data->flags |= TEST_FLAG_REBUILT;
        }
        else if (strncasecmp("msg", option, strlen("msg")) == 0)
        {
            data->flags |= TEST_FLAG_MSG;
        }
        else if (strncasecmp("file", option, strlen("file")) == 0)
        {
            char *filename;

            if (data->flags & TEST_FLAG_STDOUT)
            {
                FatalError("alert_test: cannot specify both stdout and file\n");
            }
                
            filename = strstr(option, " ");

            if (filename == NULL)
            {
                data->file = OpenAlertFile(NULL);
                data->flags |= TEST_FLAG_FILE;
            }
            else
            {
                while (isspace((int)*filename))
                    filename++;

                if (*filename == '\0')
                {
                    data->file = OpenAlertFile(NULL);
                    data->flags |= TEST_FLAG_FILE;
                }
                else
                {
                    char *filename_end;
                    char *outfile;

                    filename_end = filename + strlen(filename) - 1;
                    while (isspace((int)*filename_end))
                        filename_end--;

                    filename_end++;
                    filename_end = '\0';

                    outfile = ProcessFileOption(barnyard2_conf_for_parsing, filename);
                    data->file = OpenAlertFile(outfile);
                    data->flags |= TEST_FLAG_FILE;
                    free(outfile);
                }
            }
        }
        else
        {
            FatalError("Unrecognized alert_test option: %s\n", option);
        }
    }

    /* free toks */
    mSplitFree(&toks, num_toks);

    /* didn't get stdout or a file to log to */
    if (!(data->flags & (TEST_FLAG_STDOUT | TEST_FLAG_FILE)))
    {
        data->file = OpenAlertFile(NULL);
        data->flags |= TEST_FLAG_FILE;
    }

    return data;
}

void AlertTestCleanExitFunc(int signal, void *arg)
{
    SpoAlertTestData *data = (SpoAlertTestData *)arg;

    /* close alert file */
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"AlertTestCleanExitFunc\n"););
    fclose(data->file);

    /*free memory from SpoAlertTestData */
    free(data);
}

void AlertTestRestartFunc(int signal, void *arg)
{
    SpoAlertTestData *data = (SpoAlertTestData *)arg;

    /* close alert file */
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"AlertTestRestartFunc\n"););
    fclose(data->file);

    /*free memory from SpoAlertTestData */
    free(data);
}

