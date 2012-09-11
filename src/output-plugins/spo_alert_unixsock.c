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

} SpoAlertUnixSockData;


static int alertsd;
#ifndef WIN32
struct sockaddr_un alertaddr;
#else
struct sockaddr_in alertaddr;
#endif

void AlertUnixSockInit(char *);
void AlertUnixSock(Packet *, void *, uint32_t, void *);
void ParseAlertUnixSockArgs(char *);
void AlertUnixSockCleanExit(int, void *);
void AlertUnixSockRestart(int, void *);
void OpenAlertSock(void);
void CloseAlertSock(void);

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
    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Output: AlertUnixSock Initialized\n"););

    /* parse the argument list from the rules file */
    ParseAlertUnixSockArgs(args);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Linking UnixSockAlert functions to call lists...\n"););

    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(AlertUnixSock, OUTPUT_TYPE__ALERT, NULL);

    AddFuncToCleanExitList(AlertUnixSockCleanExit, NULL);
    AddFuncToRestartList(AlertUnixSockRestart, NULL);
}


/*
 * Function: ParseAlertUnixSockArgs(char *)
 *
 * Purpose: Process the preprocessor arguements from the rules file and 
 *          initialize the preprocessor's data struct.  This function doesn't
 *          have to exist if it makes sense to parse the args in the init 
 *          function.
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 */
void ParseAlertUnixSockArgs(char *args)
{
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"ParseAlertUnixSockArgs: %s\n", args););
    /* eventually we may support more than one socket */
    OpenAlertSock();
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
	memmmove(alertpkt.pkt, (const void *)p->pkt,
		 alertpkt.pkth.caplen > SNAPLEN ? SNAPLEN : alertpkt.pkth.caplen);
    }
    else
        alertpkt.val|=NOPACKET_STRUCT;

	sn = GetSigByGidSid(ntohl(((Unified2EventCommon *)event)->generator_id),
						ntohl(((Unified2EventCommon *)event)->signature_id));

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


    if(sendto(alertsd,(const void *)&alertpkt,sizeof(Alertpkt),
              0,(struct sockaddr *)&alertaddr,sizeof(alertaddr))==-1)
    {
        /* whatever we do to sign that some alerts could be missed */
    }


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
void OpenAlertSock(void)
{
    char srv[STD_BUF];

    /* srv is our filename workspace. Set it to file UNSOCK_FILE inside the log directory. */
    SnortSnprintf(srv, STD_BUF, "%s%s/%s",
                  barnyard2_conf->chroot_dir == NULL ? "" : barnyard2_conf->chroot_dir,
                  barnyard2_conf->log_dir, UNSOCK_FILE);

    if(access(srv, W_OK))
    {
       ErrorMessage("%s file doesn't exist or isn't writable!\n",
            srv);
    }

    memset((char *) &alertaddr, 0, sizeof(alertaddr)); /* bzero() deprecated, replaced with memset() */
    
    /* 108 is the size of sun_path */
    strncpy(alertaddr.sun_path, srv, 108);

    alertaddr.sun_family = AF_UNIX;

    if((alertsd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
    {
        FatalError("socket() call failed: %s", strerror(errno));
    }
}

void AlertUnixSockCleanExit(int signal, void *arg) 
{
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"AlertUnixSockCleanExitFunc\n"););
    CloseAlertSock();
}

void AlertUnixSockRestart(int signal, void *arg) 
{
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"AlertUnixSockRestartFunc\n"););
    CloseAlertSock();
}

void CloseAlertSock(void)
{
    if(alertsd >= 0) {
        close(alertsd);
    }
}




#endif /* !WIN32 */

