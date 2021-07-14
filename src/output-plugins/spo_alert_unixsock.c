/* $Id$ */
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

/* spo_alert_unixsock
 * 
 * Purpose:  output plugin for Unix Socket alerting
 *
 * Arguments:  none (yet)
 *   
 * Effect:	???
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#ifndef WIN32
#include <sys/un.h>
#endif /* !WIN32 */
#include <unistd.h>
#include <errno.h>

#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "util.h"
#include "map.h"
#include "mstring.h"
#include "unified2.h"
#include "spo_alert_unixsock.h"
#include "barnyard2.h"

#define UNSOCK_FILE "barnyard2_alert"



/*
 * Win32 does not support Unix sockets (sockaddr_un).  This file
 * will not be compiled on Win32 until a proper patch is supported.
 */
#ifndef WIN32




/* not used yet */
typedef struct _SpoAlertUnixSockData
{
    char *filename;
    int alertsd;
    int sync;

} SpoAlertUnixSockData;


void AlertUnixSockInit(char *);
void AlertUnixSock(Packet *, void *, uint32_t, void *);
SpoAlertUnixSockData *ParseAlertUnixSockArgs(char *);
void AlertUnixSockCleanExit(int, void *);
void AlertUnixSockRestart(int, void *);
void OpenAlertSock(SpoAlertUnixSockData *);
void CloseAlertSock(SpoAlertUnixSockData *);

/*
 * Function: SetupAlertUnixSock()
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
void AlertUnixSockSetup(void)
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterOutputPlugin("alert_unixsock", OUTPUT_TYPE_FLAG__ALERT, AlertUnixSockInit);
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output plugin: AlertUnixSock is setup...\n"););
}


/*
 * Function: AlertUnixSockInit(char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
void AlertUnixSockInit(char *args)
{
    SpoAlertUnixSockData *data;

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Output: AlertUnixSock Initialized\n"););

    /* parse the argument list from the rules file */
    data = ParseAlertUnixSockArgs(args);

    OpenAlertSock(data);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Linking UnixSockAlert functions to call lists...\n"););

    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(AlertUnixSock, OUTPUT_TYPE__ALERT, data);

    AddFuncToCleanExitList(AlertUnixSockCleanExit, data);
    AddFuncToRestartList(AlertUnixSockRestart, data);
}


/*
 * Function: ParseAlertUnixSockArgs(char *)
 *
 * Purpose: Process positional args, if any.  Syntax is:
 * output alert_unixsock: [path ["sync"]]
 * path ::= <path of filesystem relative to log dir>
 * "sync" ::= specify that communication must be synchronous
 *
 * Arguments: args => argument list
 *
 * Returns: pointer to SpoAlertUnixSockData
 */
SpoAlertUnixSockData *ParseAlertUnixSockArgs(char *args)
{
    SpoAlertUnixSockData *data;
    char **toks;
    int num_toks, i;
    const char *filename = NULL;

    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"ParseAlertUnixSockArgs: %s\n", args););
    data = (SpoAlertUnixSockData *)SnortAlloc(sizeof(SpoAlertUnixSockData));
    if ( !data )
    {
        FatalError("alert_unixsock: unable to allocate memory!\n");
    }
    data->sync = 0;

    if ( !args ) args = "";
    toks = mSplit((char *)args, " \t", 0, &num_toks, '\\');

    for (i = 0; i < num_toks; i++)
    {
        const char* tok = toks[i];

        switch (i)
        {
            case 0:
                filename = tok;
                break;

            case 1:
                if ( !strcasecmp(tok, "sync") )
                {
                    data->sync = 1;
                    continue;
                }
                /* Otherwise fall through to error */
            case 2:
                FatalError("alert_unixsock: error in %s(%i): %s\n",
                    file_name, file_line, tok);
                break;
        }
    }
    
    if ( !filename )
    { 
	filename = strdup(UNSOCK_FILE);
    }

    data->filename = ProcessFileOption(barnyard2_conf_for_parsing, filename);
    
    mSplitFree(&toks, num_toks);

    DEBUG_WRAP(DebugMessage(
        DEBUG_INIT, "alert_unixsock: '%s'\n",
            data->filename
    ););

    return data;
}

/****************************************************************************
 *
 * Function: SpoUnixSockAlert(Packet *, char *)
 *
 * Arguments: p => pointer to the packet data struct
 *            msg => the message to print in the alert
 *
 * Returns: void function
 *
 ***************************************************************************/
void AlertUnixSock(Packet *p, void *event, uint32_t event_type, void *arg)
{
    static Alertpkt		alertpkt;
	SigNode				*sn;
    SpoAlertUnixSockData *data;
    char buf[1];
    int err;

    if( p == NULL || event == NULL || arg == NULL )
        return;

    data = (SpoAlertUnixSockData *)arg;

    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "Logging Alert data!\n"););

    memset((char *)&alertpkt, 0, sizeof(alertpkt)); /* bzero() deprecated, replaced with memset() */
    if (event)
    {
	memmove((void *) &alertpkt.event, (const void *)event, sizeof(Unified2EventCommon)); /* bcopy() deprecated, replaced by memmove() */
    }

    if(p && p->pkt)
    {
	/* bcopy() deprecated, replaced by memmove() */
	memmove((void *) &alertpkt.pkth, (const void *)p->pkth, sizeof(struct pcap_pkthdr));
	memmove(alertpkt.pkt, (const void *)p->pkt,
		 alertpkt.pkth.caplen > PKT_SNAPLEN ? PKT_SNAPLEN : alertpkt.pkth.caplen);
    }
    else
        alertpkt.val|=NOPACKET_STRUCT;

	sn = GetSigByGidSid(ntohl(((Unified2EventCommon *)event)->generator_id),
			    ntohl(((Unified2EventCommon *)event)->signature_id),
			    ntohl(((Unified2EventCommon *)event)->signature_revision));


    if (sn != NULL)
    {
	/* bcopy() deprecated, replaced by memmove() */
	memmove((void *) alertpkt.alertmsg, (const void *) sn->msg,
		strlen(sn->msg) > ALERTMSG_LENGTH-1 ? ALERTMSG_LENGTH - 1 : strlen(sn->msg));
    }

    /* some data which will help monitoring utility to dissect packet */
    if(!(alertpkt.val & NOPACKET_STRUCT))
    {
        if(p)
        {
            if (p->eh) 
            {
                alertpkt.dlthdr=(char *)p->eh-(char *)p->pkt;
            }
    
            /* we don't log any headers besides eth yet */
            if (IPH_IS_VALID(p) && p->pkt) 
            {
                alertpkt.nethdr=(char *)p->iph-(char *)p->pkt;
	
                switch(GET_IPH_PROTO(p))
                {
                    case IPPROTO_TCP:
                       if (p->tcph) 
                       {
                           alertpkt.transhdr=(char *)p->tcph-(char *)p->pkt;
                       }
                       break;
		    
                    case IPPROTO_UDP:
                        if (p->udph) 
                        {
                            alertpkt.transhdr=(char *)p->udph-(char *)p->pkt;
                        }
                        break;
		    
                    case IPPROTO_ICMP:
                       if (p->icmph) 
                       {
                           alertpkt.transhdr=(char *)p->icmph-(char *)p->pkt;
                       }
                       break;
		    
                    default:
                        /* alertpkt.transhdr is null due to initial bzero */
                        alertpkt.val|=NO_TRANSHDR;
                        break;
                }
            }

            if (p->data && p->pkt) alertpkt.data=p->data - p->pkt;
        }
    }


    err = send(data->alertsd,(const void *)&alertpkt,sizeof(Alertpkt),0);

    if( !data->sync )
        /* For backward compatability, in non-sync mode errors are ignored */
        return;

    if( err < 0 )
        FatalError("alert_unixsock: error writing alert to '%s': %s!\n", data->filename, strerror(errno));

    /* Wait for a message which indicates remote end has processed alerts */
    err = read(data->alertsd, buf, 1);

    if( err < 0 )
        FatalError("alert_unixsock: error reading response from '%s': %s!\n", data->filename, strerror(errno));
}



/*
 * Function: OpenAlertSock
 *
 * Purpose:  Connect to UNIX socket for alert logging..
 *
 * Arguments: none..
 *
 * Returns: void function
 */
void OpenAlertSock(SpoAlertUnixSockData *data)
{
#ifndef WIN32
    struct sockaddr_un alertaddr;
#else
    struct sockaddr_in alertaddr;
#endif

    if(access(data->filename, W_OK))
    {
       ErrorMessage("alert_unixsock: %s file doesn't exist or isn't writable!\n",
            data->filename);
    }

    memset((char *) &alertaddr, 0, sizeof(alertaddr)); /* bzero() deprecated, replaced with memset() */
    
    /* 108 is the size of sun_path */
    strncpy(alertaddr.sun_path, data->filename, 108);

    alertaddr.sun_family = AF_UNIX;

    if((data->alertsd = socket(AF_UNIX, data->sync?SOCK_SEQPACKET:SOCK_DGRAM, 0)) < 0)
    {
        FatalError("alert_unixsock: socket() call failed: %s\n", strerror(errno));
    }

    /* Connect to the target */
    if( connect(data->alertsd, (struct sockaddr *)&alertaddr, sizeof(alertaddr)) < 0)
    {
        FatalError("alert_unixsock: connect() to '%s' failed: %s\n", data->filename, strerror(errno));
    }
}

void AlertUnixSockCleanExit(int signal, void *arg) 
{
    SpoAlertUnixSockData *data = (SpoAlertUnixSockData *)arg;
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"AlertUnixSockCleanExitFunc\n"););
    CloseAlertSock(data);

    if(data->filename)
    {
	free(data->filename);
    }

    if(data)
    {
	free(data);
    }

}

void AlertUnixSockRestart(int signal, void *arg) 
{
    SpoAlertUnixSockData *data = (SpoAlertUnixSockData *)arg;
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"AlertUnixSockRestartFunc\n"););
    CloseAlertSock(data);

    if(data->filename)
    {
	free(data->filename);
    }

    if(data)
    {
	free(data);
    }

}

void CloseAlertSock(SpoAlertUnixSockData *data)
{
    if(data->alertsd >= 0) {
        close(data->alertsd);
        data->alertsd = -1;
    }
}




#endif /* !WIN32 */

