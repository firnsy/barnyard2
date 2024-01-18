/*
** spo_alert_fwsam.c
**
** Copyright (c) 2001-2005        Frank Knobbe <frank@knobbe.us>
** Portions Copyright (c) 2012    Ian Firns    <firnsy@securixlive.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
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
 * Purpose:
 *
 * This module sends alerts to a remote service on a host running SnortSam
 * (the agent) which will block the intruding IP address on a variety of
 * host and network firewalls.
 *
 * SnortSam also performs checks against a white-list of never-to-be-blocked IP addresses,
 * can override block durations (for example for known proxies), and can detect attack conditions
 * where too many blocks are received within a defined interval. If an attack is detected
 * it will unblock the last x blocks and wait for the attack to end.
 *
 * See the SnortSam documentation for more information.
 *
 *
 * Output Plugin Parameters:
 ***************************
 *
 * output alert_fwsam: <SnortSam Station>:<port>/<key>
 *
 *  <FW Mgmt Station>:  IP address or host name of the host running SnortSam.
 *  <port>:         Port the remote SnortSam service listens on (default 898).
 *  <key>:              Key used for authentication (encryption really)
 *              of the communication to the remote service.
 *
 * Examples:
 *
 * output alert_fwsam: snortsambox/idspassword
 * output alert_fwsam: fw1.domain.tld:898/mykey
 * output alert_fwsam: 192.168.0.1/borderfw  192.168.1.254/wanfw
 *
 *
 * sid-fwsam Parameters:
 ***********************
 *
 * <sid>:   who[how],time;
 *
 *  who: src, source, dst, dest, destination
 *          IP address to be blocked according to snort rule (some rules
 *          are reversed, i.e. homenet -> any [and you want to block any]).
 *          src denotes IP to the left of -> and dst denotes IP to the right
 *
 *  how: Optional. In, out, src, dest, either, both, this, conn, connection
 *          Tells SnortSam to block packets INcoming from host, OUTgoing to host,
 *          EITHERway, or only THIS connection (IP/Service pair).
 *          See 'fw sam' on Firewall-1 for more information.
 *          This option may be ignored by other plugins.
 *
 * time: Duration of block in seconds. (Accepts 'days', 'months', 'weeks',
 *       'years', 'minutes', 'seconds', 'hours'. Alternatively, a value of
 *       0, or the keyword PERManent, INFinite, or ALWAYS, will block the
 *       host permanently. Be careful with this!
 *          Tells SnortSam how long to inhibit packets from the host.
 *
 * Examples:
 *
 * 1487: src[either],15min;
 * 1292: dst[in], 2 days 4 hours
 * 1638: src, 1 hour
 *
*/

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include "barnyard2.h"
#include "decode.h"
#include "spo_alert_fwsam.h"
#include "twofish.h"
#include "plugbase.h"
#include "unified2.h"
#include "util.h"

/* just some compatibility stuff */
#ifdef WIN32
#if !defined(_WINSOCKAPI_) && !defined(_WINSOCK2API_)
#include <winsock.h>
#endif
#define waitms(x)               Sleep(x)

#else

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netdb.h>

#ifdef SOLARIS
#include <sys/filio.h>
#endif

typedef int SOCKET;

#ifndef INVALID_SOCKET
#define INVALID_SOCKET  -1
#endif

#define waitms(x)               usleep((x)*1000)

#endif

#ifndef FALSE
#define FALSE   0
#endif
#ifndef TRUE
#define TRUE    !FALSE
#endif
#ifndef bool
#define bool    int
#endif


#if defined(_DEBUG) || defined(DEBUG)
#ifndef FWSAMDEBUG
#define FWSAMDEBUG
#endif
#else
#endif



/* fixed defines */

#define FWSAM_DEFAULTPORT       898 /* Default port if user does not specify one in barnyard2.conf */
                                    /* (Was unused last time I checked...) */
#define FWSAM_PACKETVERSION     14  /* version of the packet. Will increase with enhancements. */

#define FWSAM_STATUS_CHECKIN    1   /* snort to fw */
#define FWSAM_STATUS_CHECKOUT   2
#define FWSAM_STATUS_BLOCK      3
#define FWSAM_STATUS_UNBLOCK    9

#define FWSAM_STATUS_OK         4   /* fw to snort */
#define FWSAM_STATUS_ERROR      5
#define FWSAM_STATUS_NEWKEY     6
#define FWSAM_STATUS_RESYNC     7
#define FWSAM_STATUS_HOLD       8

#define FWSAM_LOG_NONE          0
#define FWSAM_LOG_SHORTLOG      1
#define FWSAM_LOG_SHORTALERT    2
#define FWSAM_LOG_LONGLOG       3
#define FWSAM_LOG_LONGALERT     4
#define FWSAM_LOG               (FWSAM_LOG_SHORTLOG|FWSAM_LOG_SHORTALERT|FWSAM_LOG_LONGLOG|FWSAM_LOG_LONGALERT)
#define FWSAM_WHO_DST           8
#define FWSAM_WHO_SRC           16
#define FWSAM_WHO               (FWSAM_WHO_DST|FWSAM_WHO_SRC)
#define FWSAM_HOW_IN            32
#define FWSAM_HOW_OUT           64
#define FWSAM_HOW_INOUT         (FWSAM_HOW_IN|FWSAM_HOW_OUT)
#define FWSAM_HOW_THIS          128
#define FWSAM_HOW               (FWSAM_HOW_IN|FWSAM_HOW_OUT|FWSAM_HOW_THIS)


/* user adjustable defines */

#define FWSAM_REPET_BLOCKS      10  /* Snort remembers this amount of last blocks and... */
#define FWSAM_REPET_TIME        20  /* ...checks if they fall within this time. If so,... */
                                    /* ...the blocking request is not send. */

#define FWSAM_NETWAIT           300     /* 100th of a second. 3 sec timeout for network connections */
#define FWSAM_NETHOLD           6000    /* 100th of a second. 60 sec timeout for holding */

#define SID_MAPFILE             "sid-block.map"
#define SID_ALT_MAPFILE         "sid-fwsam.map"

#define FWSAM_FANCYFETCH        /* This will invoke a fast sid lookup routine */


/* vars */

typedef struct _FWsamstation            /* structure of a mgmt station */
{
    unsigned short      myseqno;
    unsigned short      stationseqno;
    unsigned char       mykeymod[4];
    unsigned char       fwkeymod[4];
    unsigned short      stationport;
    //struct in_addr        stationip;
    sfip_t          stationip;
    struct sockaddr_in  localsocketaddr;
    struct sockaddr_in  stationsocketaddr;
    TWOFISH         *stationfish;
    char            initialkey[TwoFish_KEY_LENGTH+2];
    char            stationkey[TwoFish_KEY_LENGTH+2];
    time_t          lastcontact;
/*  time_t          sleepstart; */
}   FWsamStation;

typedef struct _FWsampacket         /* 2 blocks (3rd block is header from TwoFish) */
{
    unsigned short      endiancheck;    /* 0  */
    unsigned char       srcip[4];       /* 2  */
    unsigned char       dstip[4];       /* 6  */
    unsigned char       duration[4];    /* 10 */
    unsigned char       snortseqno[2];  /* 14 */
    unsigned char       fwseqno[2];     /* 16 */
    unsigned char       srcport[2];     /* 18 */
    unsigned char       dstport[2];     /* 20 */
    unsigned char       protocol[2];    /* 22 */
    unsigned char       fwmode;         /* 24 */
    unsigned char       version;        /* 25 */
    unsigned char       status;         /* 26 */
    unsigned char       sig_id[4];      /* 27 */
    unsigned char       fluff;          /* 31 */
}   FWsamPacket;                        /* 32 bytes in size */

typedef struct _FWsampacket2            /* 4 blocks (3rd block is header from TwoFish) */
{
    unsigned short      endiancheck;    /* 0  */
    unsigned char       srcip[16];      /* 2  */
    unsigned char       dstip[16];      /* 18 */
    unsigned char       ipver;          /* 34 */
    unsigned char       duration[4];    /* 35 */
    unsigned char       snortseqno[2];  /* 39 */
    unsigned char       fwseqno[2];     /* 41 */
    unsigned char       srcport[2];     /* 43 */
    unsigned char       dstport[2];     /* 45 */
    unsigned char       protocol[2];    /* 47 */
    unsigned char       fwmode;         /* 49 */
    unsigned char       version;        /* 50 */
    unsigned char       status;         /* 51 */
    unsigned char       sig_id[4];      /* 52 */
    unsigned char       reserved[7];    /* 56 */
}   FWsamPacket2;                       /* 64 bytes in size */

typedef struct _FWsamoptions    /* snort rule options */
{
    unsigned long   sid;
    unsigned long   duration;
    unsigned char   who;
    unsigned char   how;
    unsigned char   loglevel;
}   FWsamOptions;

typedef struct _FWsamlistpointer
{
    FWsamStation *station;
    struct _FWsamlistpointer *next;
}   FWsamList;

/*
** PROTOTYPES
*/
void AlertFWsamInit(char *args);
void AlertFWsamCleanExitFunc(int signal, void *arg);
void AlertFWsamRestartFunc(int signal, void *arg);
void AlertFWsam(Packet *p, void *event, uint32_t type, void *arg);
int FWsamCheckIn(FWsamStation *station);
void FWsamCheckOut(FWsamStation *station);
void FWsamNewStationKey(FWsamStation *station, FWsamPacket *packet);
void FWsamFixPacketEndian(FWsamPacket *p);
unsigned long FWsamParseDuration(char *p);
void FWsamFree(FWsamList *fwsamlist);
int FWsamStationExists(FWsamStation *who, FWsamList *list);
int FWsamReadLine(char *, unsigned long, FILE *);
void FWsamParseLine(FWsamOptions *, char *);
FWsamOptions *FWsamGetOption(unsigned long);
int FWsamParseOption(FWsamOptions *, char *);


/*
** GLOBALS
*/

/* external globals from rules.c  */
extern char *file_name;
extern int file_line;

/* external globals from barnyard.c */
extern Barnyard2Config *barnyard2_conf;

FWsamList *FWsamStationList=NULL;           /* Global (for all alert-types) list of snortsam stations */
FWsamOptions *FWsamOptionField=NULL;
unsigned long FWsamMaxOptions=0;


/*
 * Function: AlertFWsamSetup()
 *
 * Purpose: Registers the output plugin keyword and initialization
 *          function into the output plugin list.  This is the function that
 *          gets called from InitOutputPlugins() in plugbase.c.
 *          It also registers itself as a plugin in order to parse every rule
 *          and to set the appropiate flags from fwsam: option.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
*/
void AlertFWsamSetup(void)
{
    /* link the preprocessor keyword to the init function in the preproc list */
    RegisterOutputPlugin("alert_fwsam", OUTPUT_TYPE_FLAG__ALERT, AlertFWsamInit);

#ifdef FWSAMDEBUG   /* This allows debugging of fwsam only */
    LogMessage("DEBUG => [Alert_FWsam](AlertFWsamSetup) Output plugin is plugged in...\n");
#endif
}


/*
 * Function: AlertFWsamInit(char *args)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
*/
void AlertFWsamInit(char *args)
{
    char *ap;
    unsigned long statip,cnt,again,i;
    char *stathost, *statport, *statpass;
    FWsamStation *station;
    FWsamList *fwsamlist=NULL;  /* alert-type dependent list of snortsam stations  */
    FWsamList *listp,*newlistp;
    struct hostent *hoste;
    char buf[1024]="";
    FILE *fp;
    FWsamOptions tempopt;

#ifdef FWSAMDEBUG
    unsigned long hostcnt=0;
    LogMessage("DEBUG => [Alert_FWsam](AlertFWsamInit) Output plugin initializing...\n");
#endif

    /* parse the argument list from the rules file */
    if(args == NULL)
        FatalError("[Alert_FWsam](AlertFWsamInit) No arguments to alert_fwsam preprocessor!\n");

    if(!FWsamOptionField && !FWsamMaxOptions)
    {
        strncpy(buf, barnyard2_conf->config_dir, sizeof(buf)-1);
        strncpy(buf+strlen(buf), SID_MAPFILE, sizeof(buf)-strlen(buf)-1);
#ifdef FWSAMDEBUG
        LogMessage("DEBUG => [Alert_FWsam](AlertFWsamSetup) Using file: %s\n",buf);
#endif
        fp=fopen(buf,"rt");
        if(!fp)
        {
            strncpy(buf, barnyard2_conf->config_dir, sizeof(buf)-1);
            strncpy(buf+strlen(buf), SID_ALT_MAPFILE, sizeof(buf)-strlen(buf)-1);
            LogMessage("DEBUG => [Alert_FWsam](AlertFWsamSetup) Using alternative file: %s\n",buf);
            fp=fopen(buf,"rt");
        }

        if(fp)  /* Check for presence of map file and read those in, sorted. */
        {
            LogMessage("INFO => [Alert_FWsam](AlertFWsamSetup) Using sid-map file: %s\n",buf);
            while( FWsamReadLine(buf,sizeof(buf),fp) )
                if( *buf )
                    FWsamMaxOptions++;

            if( FWsamMaxOptions )
            {
                if( (FWsamOptionField=(FWsamOptions *)malloc(sizeof(FWsamOptions)*FWsamMaxOptions)) == NULL )
                    FatalError("ERROR => [Alert_FWsam](AlertFWsamSetup) malloc failed for OptionField!\n");

                fseek(fp,0,SEEK_SET);
                for(cnt=0; cnt<FWsamMaxOptions; )
                {
                    FWsamReadLine(buf,sizeof(buf),fp);

                if( *buf )
                    FWsamParseLine(&(FWsamOptionField[cnt++]),buf);
                }

                if( FWsamMaxOptions>1 )
                {
                    for(again=TRUE,cnt=FWsamMaxOptions-1; cnt>=1 && again; cnt--)
                    {
                        for(again=FALSE,i=0; i<cnt; i++)
                        {
                            if( FWsamOptionField[i].sid>FWsamOptionField[i+1].sid )
                            {   memcpy(&tempopt,&(FWsamOptionField[i]),sizeof(FWsamOptions));
                                memcpy(&(FWsamOptionField[i]),&(FWsamOptionField[i+1]),sizeof(FWsamOptions));
                                memcpy(&(FWsamOptionField[i+1]),&tempopt,sizeof(FWsamOptions));
                                again=TRUE;
                            }
                        }
                    }
                }
            }
            else
                FWsamMaxOptions=1;

            fclose(fp);
        }
        else
            FWsamMaxOptions=1;
    }


    ap=args; /* start at the beginning of the argument */
    while(*ap && isspace(*ap)) ap++;
    while(*ap)
    {
        stathost=ap; /* first argument should be host */
        statport=NULL;
        statpass=NULL;
        while(*ap && *ap!=':' && *ap!='/' && !isspace(*ap)) ap++; /* find token */
        switch(*ap)
        {
            case ':':
                *ap++=0; /* grab the port */
                statport=ap;
                while(*ap && *ap!='/' && !isspace(*ap)) ap++;
                if(*ap!='/')
                    break;

            case '/':
                *ap++=0; /* grab the key */
                    statpass=ap;
                    while(*ap && !isspace(*ap)) ap++;
                    break;

            default:
                    break;
        }

        if(*ap)
        {
            *ap++=0;
            while(isspace(*ap)) ap++;
        }

        /* now we have the first host with port and password (key) */
        /* next we check for valid/blank password/port */
        if(statpass!=NULL)
            if(!*statpass)
                statpass=NULL;

        if(statport!=NULL)
            if(!*statport)
                statport=NULL;

        statip=0;
        /* now we check if a valid host was specified */
        if(inet_addr(stathost)==INADDR_NONE)
        {
            hoste=gethostbyname(stathost);

            if (!hoste)
                LogMessage("WARNING %s (%d) => [Alert_FWsam](AlertFWsamInit) Unable to resolve host '%s'!\n",file_name,file_line,stathost);
            else
                statip=*(unsigned long *)hoste->h_addr;
        }
        else
        {
            statip=inet_addr(stathost);
            if(!statip)
                LogMessage("WARNING %s (%d) => [Alert_FWsam](AlertFWsamInit) Invalid host address '%s'!\n",file_name,file_line,stathost);
        }

        if(statip)
        {   /* groovie, a valid host. Let's alloc and assemble the structure for it. */
            if((station=(FWsamStation *)malloc(sizeof(FWsamStation)))==NULL)
                FatalError("ERROR => [Alert_FWsam](AlertFWsamInit) malloc failed for station!\n");

            station->stationip.ip32[0] = statip; /* the IP address */
            if(statport!=NULL && atoi(statport)>0) /* if the user specified one */
                station->stationport=atoi(statport); /* use users setting */
            else
                station->stationport=FWSAM_DEFAULTPORT; /* set the default port */

            if(statpass!=NULL) /* if specified by user */
                strncpy(station->stationkey,statpass,TwoFish_KEY_LENGTH); /* use defined key */
            else
                station->stationkey[0]=0;

            station->stationkey[TwoFish_KEY_LENGTH]=0; /* make sure it's terminated. (damn strncpy...) */

            strcpy(station->initialkey,station->stationkey);
            station->stationfish=TwoFishInit(station->stationkey);

            station->localsocketaddr.sin_port=htons(0); /* let's use dynamic ports for now */
            station->localsocketaddr.sin_addr.s_addr=0;
            station->localsocketaddr.sin_family=AF_INET;
            station->stationsocketaddr.sin_port=htons(station->stationport);

            station->stationsocketaddr.sin_addr.s_addr=station->stationip.ip32[0];
            station->stationsocketaddr.sin_family=AF_INET; /* load all socket crap and keep for later */

            do
                station->myseqno=rand(); /* the seqno this host will use */
            while(station->myseqno<20 || station->myseqno>65500);

            station->mykeymod[0]=rand();
            station->mykeymod[1]=rand();
            station->mykeymod[2]=rand();
            station->mykeymod[3]=rand();
            station->stationseqno=0;                /* peer hasn't answered yet. */


            /* If we don't have the station already in global list....*/
            if(!FWsamStationExists(station,FWsamStationList))
            {
                if(FWsamCheckIn(station))           /* ...and we can talk to the agent...  */
                {
                    if((newlistp=(FWsamList *)malloc(sizeof(FWsamList)))==NULL)
                        FatalError("ERROR => [Alert_FWsam](AlertFWsamInit) malloc failed for global newlistp!\n");

                    newlistp->station=station;
                    newlistp->next=NULL;

                    if(!FWsamStationList)               /* ... add it to the global list/ */
                        FWsamStationList=newlistp;
                    else
                    {
                        listp=FWsamStationList;
                        while(listp->next)
                            listp=listp->next;
                        listp->next=newlistp;
                    }
                }
                else
                {
                    TwoFishDestroy(station->stationfish); /* if not, we trash it. */
                    free(station);
                    station=NULL;
                }
            }
#ifdef FWSAMDEBUG
            else
                LogMessage("DEBUG => [Alert_FWsam](AlertFWsamInit) Host %s:%i already in global list, skipping CheckIn.\n", sfip_ntoa(&station->stationip),station->stationport);
#endif

            if(station)
            {
                /* If we don't have the station already in local list....*/
                if(!FWsamStationExists(station,fwsamlist))
                {
                    if((newlistp=(FWsamList *)malloc(sizeof(FWsamList)))==NULL)
                        FatalError("ERROR => [Alert_FWsam](AlertFWsamInit) malloc failed for local newlistp!\n");

                    newlistp->station=station;
                    newlistp->next=NULL;

                    if(!fwsamlist)              /* ... add it to the local list/ */
                        fwsamlist=newlistp;
                    else
                    {
                        listp=fwsamlist;
                        while(listp->next)
                            listp=listp->next;
                        listp->next=newlistp;
                    }
                }

#ifdef FWSAMDEBUG
                else
                    LogMessage("DEBUG => [Alert_FWsam](AlertFWsamInit) Host %s:%i already in local list, skipping.\n",sfip_ntoa(&station->stationip),station->stationport);

                LogMessage("DEBUG => [Alert_FWsam](AlertFWsamInit) #%i: Host %s [%s] port %i password %s\n",++hostcnt,stathost,sfip_ntoa(&station->stationip),station->stationport,station->stationkey);
#endif
            }
        }
    }   /* next one */

#ifdef FWSAMDEBUG
    LogMessage("DEBUG => [Alert_FWsam](AlertFWsamInit) Linking fwsam alert function to call list...\n");
#endif

    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(AlertFWsam, OUTPUT_TYPE__LOG, fwsamlist);
    AddFuncToCleanExitList(AlertFWsamCleanExitFunc, fwsamlist);
    AddFuncToRestartList(AlertFWsamRestartFunc, fwsamlist);
}


/*  This routine reads in a str from a file, snips white-spaces
 *  off the front and back, removes comments, and pretties the
 *  string. Returns true or false if a line was read or not.
*/
int FWsamReadLine(char *buf,unsigned long bufsize,FILE *fp)
{   char *p;

    if(fgets(buf,bufsize-1,fp))
    {
        buf[bufsize-1]=0;

#ifdef FWSAMDEBUG
        LogMessage("DEBUG => [Alert_FWsam](AlertFWsamReadLine) Line: %s\n",buf);
#endif

        p=buf;
        while(isspace(*p))
          p++;
        if(p>buf);
            strcpy(buf,p);
        if(*buf)
        {
            p=buf+strlen(buf)-1;    /* remove leading and trailing spaces */
            while(isspace(*p))
                *p-- =0;
        }
        p=buf;
        if(*p=='#' || *p==';')
            *p=0;
        else
            p++;
        while(*p)                   /* remove inline comments (except escaped #'s and ;'s) */
        {
            if(*p=='#' || *p==';')
            {
                if(*(p-1)=='\\')
                    strcpy(p-1,p);
                else
                    *p=0;
            }
            else
                p++;
        }
        return TRUE;
    }
    return FALSE;
}

/*  This function checks if a given snortsam station is already in
 *  a given list.
*/
int FWsamStationExists(FWsamStation *who,FWsamList *list)
{
    while(list)
    {
        if(list->station)
        {
            if( IP_EQUALITY(&who->stationip, &list->station->stationip) &&
                who->stationport==list->station->stationport )
            return TRUE;
        }
        list=list->next;
    }
    return FALSE;
}


/* Parses the duration of the argument, recognizing minutes, hours, etc..
*/
unsigned long FWsamParseDuration(char *p)
{   unsigned long dur=0,tdu;
    char *tok,c1,c2;

    while(*p)
    {
        tok=p;
        while(*p && isdigit(*p))
            p++;
        if(*p)
        {
            c1=tolower(*p);
            *p=0;
            p++;
            if(*p && !isdigit(*p))
            {
                c2=tolower(*p++);
                while(*p && !isdigit(*p))
                    p++;
            }
            else
                c2=0;
            tdu=atol(tok);
            switch(c1)
            {
                case 'm':
                    if(c2=='o')             /* month */
                        tdu*=(60*60*24*30); /* use 30 days */
                    else
                        tdu*=60;            /* minutes */
                    break;
                case 's':
                    break;                  /* seconds */
                case 'h':
                    tdu*=(60*60);           /* hours */
                    break;
                case 'd':
                    tdu*=(60*60*24);        /* days */
                    break;
                case 'w':
                    tdu*=(60*60*24*7);      /* week */
                    break;
                case 'y':
                    tdu*=(60*60*24*365);    /* year */
                    break;
            }
            dur+=tdu;
        }
        else
            dur+=atol(tok);
    }

    return dur;
}


/*  This routine parses an option line. It is called by FWsamParseLine,
 *  which parses the sid-block.map file, and also by AlertFWsamOptionInit,
 *  which is called by Snort when processing fwsam: options in rules.
 *  It returns TRUE it there is a possible option problem, otherwise FALSE.
*/
int FWsamParseOption(FWsamOptions *optp,char *ap)
{
    int possprob=FALSE;

    /* set defaults */

    optp->duration=300;                 /* default of 5 minute block */
    optp->how=FWSAM_HOW_INOUT;          /* inbound and outbound block */
    optp->who=FWSAM_WHO_SRC;            /* the source  */
    optp->loglevel=FWSAM_LOG_LONGALERT; /* the log level default */
    /* parse the fwsam keywords */

#ifdef FWSAMDEBUG
    LogMessage("DEBUG => [Alert_FWsam](AlertFWamOptionInit) Parse Options Args: %s\n",ap);
#endif

    if(*ap)     /* should be dst/src (the WHO) or duration */
    {
        if(isdigit(*ap))
            optp->duration=FWsamParseDuration(ap);
        else
        {
            switch(*ap)         /* yeah, we're lazy and check only the first character */
            {
                case 'p':                                   /* permanent, perm */
                case 'f':                                   /* forever */
                case 'i':                                   /* infinite, inf */
                    optp->duration=0;
                    break;
                case 'd':                                   /* destination, dest, dst */
                    optp->who=FWSAM_WHO_DST;
                    break;
                case 's':                                   /* source, src */
                    optp->who=FWSAM_WHO_SRC;
                    break;
                default:
                    possprob=TRUE;
            }
            while(*ap && *ap!=',' && *ap!='[')
                ap++;
            if(*ap=='[')
            {   ap++;       /* now we have the HOW */
                switch(*ap)
                {
                    case 'i':                               /* in */
                    case 's':                               /* source, src */
                        optp->how=FWSAM_HOW_IN;
                        break;
                    case 'o':   ;                           /* out */
                    case 'd':                               /* destination, dest, dst */
                        optp->how=FWSAM_HOW_OUT;
                        break;
                    case 'b':   ;                           /* both */
                    case 'e':                               /* either */
                        optp->how=FWSAM_HOW_INOUT;
                        break;
                    case 't':   ;                           /* this */
                    case 'c':                               /* connection, conn */
                        optp->how=FWSAM_HOW_THIS;
                        break;
                    default:
                        possprob=TRUE;
                }
                while(*ap && *ap!=',')
                    ap++;
            }
            if(*ap==',')
            {
                ap++;
                if(isdigit(*ap))  /* and figure out how long to block */
                    optp->duration=FWsamParseDuration(ap);
                else if(*ap=='p' || *ap=='f' || *ap=='i')
                    optp->duration=0;
                else
                    possprob=TRUE;
            }
            else if(!*ap)
                possprob=TRUE;
        }
    }
    else
        possprob=TRUE;

    return possprob;
}


/*  This goes through the lines of sid-block.map and sets the
 *  options for fwsam if the file is being used.
*/
void FWsamParseLine(FWsamOptions *optp,char *buf)
{
    char *ap;

    ap=buf; /* start at the beginning of the argument */

    while(*ap)
    {
        if(isspace(*ap))        /* normalize spaces (tabs into space, etc) */
            *ap=' ';
        if(isupper(*ap))        /* and set to lower case */
            *ap=tolower(*ap);
        ap++;
    }
    while((ap=strrchr(buf,' '))!=NULL)  /* remove spaces */
        strcpy(ap,ap+1);

    ap=buf;
    if(*ap)
    {
        while(*ap && *ap!=':' && *ap!='|') ap++;
        *ap++ =0;
        while(*ap && (*ap==':' || *ap=='|')) ap++;

        optp->sid=(unsigned long)atol(buf);

        if(FWsamParseOption(optp,ap))
            LogMessage("WARNING %s (%d) => [Alert_FWsam](AlertFWamOptionInit) Possible option problem. Using %s[%s],%lu.\n",file_name,file_line,(optp->who==FWSAM_WHO_SRC)?"src":"dst",(optp->how==FWSAM_HOW_IN)?"in":((optp->how==FWSAM_HOW_OUT)?"out":"either"),optp->duration);
    }
    else
        optp->sid=0;
}


/* Generates a new encryption key for TwoFish based on seq numbers and a random that
 * the SnortSam agents send on checkin (in protocol)
*/
void FWsamNewStationKey(FWsamStation *station,FWsamPacket *packet)
{
    char newkey[TwoFish_KEY_LENGTH+2];
    int i;

    newkey[0]=packet->snortseqno[0];        /* current snort seq # (which both know) */
    newkey[1]=packet->snortseqno[1];
    newkey[2]=packet->fwseqno[0];           /* current SnortSam seq # (which both know) */
    newkey[3]=packet->fwseqno[1];
    newkey[4]=packet->protocol[0];      /* the random SnortSam chose */
    newkey[5]=packet->protocol[1];

    strncpy(newkey+6,station->stationkey,TwoFish_KEY_LENGTH-6); /* append old key */
    newkey[TwoFish_KEY_LENGTH]=0;

    newkey[0]^=station->mykeymod[0];        /* modify key with key modifiers which were */
    newkey[1]^=station->mykeymod[1];        /* exchanged during the check-in handshake. */
    newkey[2]^=station->mykeymod[2];
    newkey[3]^=station->mykeymod[3];
    newkey[4]^=station->fwkeymod[0];
    newkey[5]^=station->fwkeymod[1];
    newkey[6]^=station->fwkeymod[2];
    newkey[7]^=station->fwkeymod[3];

    for(i=0;i<=7;i++)
        if(newkey[i]==0)
            newkey[i]++;

    strcpy(station->stationkey,newkey);
    TwoFishDestroy(station->stationfish);
    station->stationfish=TwoFishInit(newkey);
}


#ifdef FWSAMDEBUG
/* This does nothing else than inet_ntoa, but it keeps 4 results in a static string
 * unlike inet_ntoa which keeps only one. This is used for (s)printf's were two IP
 * addresses are printed.
*/
/*
char *inettoa(unsigned long ip)
{
    struct in_addr ips;
    static char addr[4][20];
    static unsigned char toggle;

    ips.s_addr=ip;
    toggle=(toggle+1)&3;
    strncpy(addr[toggle],inet_ntoa(ips),18);
    return addr[toggle];
}
*/
#endif


/*  This routing will search the option list as defined
 *  by the sid-block.map file and return a pointer
 *  to the matching record.
*/
FWsamOptions *FWsamGetOption(unsigned long sid)
{
    signed long i,step,diff,o,o2;

#ifdef FWSAM_FANCYFETCH       /* Fancy-fetch jumps in decreasing n/2 steps and takes much less lookups */
    o=o2= -1;
    i=step=FWsamMaxOptions>>1;
    while(i>=0 && i<FWsamMaxOptions && i!=o2)
    {
        diff=sid-FWsamOptionField[i].sid;
        if(!diff)
            return &(FWsamOptionField[i]);
        if(step>1)
            step=step>>1;
        o2=o;
        o=i;
        if(diff>0)
            i+=step;
        else
            i-=step;
    }
#else                       /* This is just a sequential list lookup */
    for(i=0;i<FWsamMaxOptions;i++)
        if(FWsamOptionField[i].sid==sid)
            return &(FWsamOptionField[i]);
#endif
    return NULL;
}


/****************************************************************************
 *
 * Function: AlertFWsam(Packet *, char *)
 *
 * Purpose: Send the current alert to a remote module on a FW-1 mgmt station
 *
 * Arguments: p => pointer to the packet data struct
 *            msg => the message to print in the alert
 *
 * Returns: void function
 *
 ***************************************************************************/
void AlertFWsam(Packet *p, void *event, uint32_t event_type, void *arg)
{
    FWsamOptions *optp;
    FWsamPacket sampacket;
    FWsamStation *station=NULL;
    FWsamList *fwsamlist;
    SOCKET stationsocket;
    int i,len,deletestation,stationtry=0;
    char *encbuf,*decbuf;
    static unsigned long lastbsip[FWSAM_REPET_BLOCKS];
    static unsigned long lastbdip[FWSAM_REPET_BLOCKS];
    static unsigned long lastbduration[FWSAM_REPET_BLOCKS];
    static unsigned long lastbtime[FWSAM_REPET_BLOCKS];
    static unsigned short lastbsp[FWSAM_REPET_BLOCKS];
    static unsigned short lastbdp[FWSAM_REPET_BLOCKS];
    static unsigned short lastbproto[FWSAM_REPET_BLOCKS];
    static unsigned short lastbpointer;
    static unsigned char lastbmode[FWSAM_REPET_BLOCKS];
    static unsigned long btime=0;

    SigNode     *sn = NULL;
    ClassType   *cn = NULL;

    /*
    ** Remove Compiler warning.
      ReferenceNode   *rn = NULL;
    */

    if(event==NULL)
    {
#ifdef FWSAMDEBUG
        LogMessage("DEBUG => [Alert_FWsam] NULL event!\n");
#endif
        return;
    }

    if(p == NULL)
    {
#ifdef FWSAMDEBUG
        LogMessage("DEBUG => [Alert_FWsam] NULL packet!\n");
#endif
        return;
    }

    if(arg == NULL)
    {
#ifdef FWSAMDEBUG
        LogMessage("DEBUG => [Alert_FWsam] NULL arg!\n");
#endif
        return;
    }

    /* SnortSam does no IPv6 */
    if (!IS_IP4(p)) {
#ifdef FWSAMDEBUG
        LogMessage("DEBUG => [Alert_FWsam] not acting on non-IP4 packet!\n");
#endif
        return;
    }

    optp=NULL;
    sn = GetSigByGidSid(ntohl(((Unified2EventCommon *)event)->generator_id),
                        ntohl(((Unified2EventCommon *)event)->signature_id),
			ntohl(((Unified2EventCommon *)event)->signature_revision));
    
    cn = ClassTypeLookupById(barnyard2_conf, ntohl(((Unified2EventCommon *)event)->classification_id));

    if(FWsamOptionField)            /* If using the file (field present), let's use that */
        optp=FWsamGetOption(ntohl(((Unified2EventCommon *)event)->signature_id));

    if(optp)    /* if options specified for this rule */
    {
        if(!btime)          /* if this is the first time this function is */
        {
            for(i=0;i<FWSAM_REPET_BLOCKS;i++)   /*  called, reset the time and protocol to 0. */
            {
                lastbproto[i]=0;
                lastbtime[i]=0;
            }
        }

        fwsamlist=(FWsamList *)arg;

#ifdef FWSAMDEBUG
        LogMessage("DEBUG => [Alert_FWsam] Alert -> Msg=\"%s\"\n",sn->msg);
        LogMessage("DEBUG => [Alert_FWsam] Alert -> Option: %s[%s],%lu.\n",(optp->who==FWSAM_WHO_SRC)?"src":"dst",(optp->how==FWSAM_HOW_IN)?"in":((optp->how==FWSAM_HOW_OUT)?"out":"either"),optp->duration);
#endif

        len=TRUE;
        btime=(unsigned long)time(NULL);    /* get current time */
        /* This is a cheap check to see if the blocking request matches any of the previous requests. */
        for(i=0; i<FWSAM_REPET_BLOCKS && len; i++)
        {
            if( ( ( optp->how==FWSAM_HOW_THIS ) ?   /* if blocking mode SERVICE, check for src and dst    */
		  ( lastbsip[i]==(unsigned long)GET_SRC_IP(p) && lastbdip[i]==(unsigned long)GET_DST_IP(p) && lastbproto[i]==GET_IPH_PROTO(p) &&
		    ( IP_HAS_PORTS(p) ? /* check port only of TCP or UDP */
/*                  ((optp->who==FWSAM_WHO_SRC)?(lastbsp[i]==record->sp):(lastbdp[i]==record->dp)):TRUE) ): */
                        lastbdp[i]==p->dp : TRUE
                      )
                    ) :
                    (
                      ( optp->who==FWSAM_WHO_SRC) ?
		      ( lastbsip[i]==(unsigned long)GET_SRC_IP(p) ) :
		      ( lastbdip[i]==(unsigned long)GET_DST_IP(p) )
                    )
                 ) && /* otherwise if we block source, only compare source. Same for dest. */
                 lastbduration[i]==optp->duration &&
                 (lastbmode[i] & (FWSAM_HOW|FWSAM_WHO))==(optp->how|optp->who) &&
                 ( btime-lastbtime[i]<((optp->duration>FWSAM_REPET_TIME) ? FWSAM_REPET_TIME : optp->duration))
               )
            {
                len=FALSE;      /* If so, we don't need to block again. */
            }
        }

        if(len)
        {
            if(++lastbpointer>=FWSAM_REPET_BLOCKS)      /* increase repetitive check pointer */
                lastbpointer=0;

            lastbsip[lastbpointer]=(unsigned long)GET_SRC_IP(p);     /* and note packet details */
            lastbdip[lastbpointer]=(unsigned long)GET_DST_IP(p);
            lastbduration[lastbpointer]=optp->duration;
            lastbmode[lastbpointer]=optp->how|optp->who|optp->loglevel;
            lastbproto[lastbpointer]=GET_IPH_PROTO(p);
            if(IP_HAS_PORTS(p))
            {
                lastbsp[lastbpointer]=p->sp;                   /* set ports if TCP or UDP */
                lastbdp[lastbpointer]=p->dp;
            }
            lastbtime[lastbpointer]=btime;


            while(fwsamlist!=NULL)
            {
                station=fwsamlist->station;
                //if(station->stationip.s_addr)
                if(station->stationip.ip32[0])
                {
                    deletestation=FALSE;
                    stationtry++;               /* first try */
                    /* create a socket for the station */
                    stationsocket=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
                    if(stationsocket==INVALID_SOCKET)
                        FatalError("ERROR => [Alert_FWsam] Funky socket error (socket)!\n");
                    if(bind(stationsocket,(struct sockaddr *)&(station->localsocketaddr),sizeof(struct sockaddr)))
                        FatalError("ERROR => [Alert_FWsam] Could not bind socket!\n");

                    /* let's connect to the agent */
                    if(connect(stationsocket,(struct sockaddr *)&station->stationsocketaddr,sizeof(struct sockaddr)))
                    {
                        LogMessage("WARNING => [Alert_FWsam] Could not send block to host %s. Will try later.\n",sfip_ntoa(&station->stationip));
#ifdef WIN32
                        closesocket(stationsocket);
#else
                        close(stationsocket);
#endif
                        stationtry=0;
                    }
                    else
                    {
#ifdef FWSAMDEBUG
                        LogMessage("DEBUG => [Alert_FWsam] Connected to host %s.\n",sfip_ntoa(&station->stationip));
#endif
                        /* now build the packet */
                        station->myseqno+=station->stationseqno; /* increase my seqno by adding agent seq no */
                        sampacket.endiancheck=1;                        /* This is an endian indicator for Snortsam */
                        sampacket.snortseqno[0]=(char)station->myseqno;
                        sampacket.snortseqno[1]=(char)(station->myseqno>>8);
                        sampacket.fwseqno[0]=(char)station->stationseqno;/* fill station seqno */
                        sampacket.fwseqno[1]=(char)(station->stationseqno>>8);
                        sampacket.status=FWSAM_STATUS_BLOCK;            /* set block mode */
                        sampacket.version=FWSAM_PACKETVERSION;          /* set packet version */
                        sampacket.duration[0]=(char)optp->duration;     /* set duration */
                        sampacket.duration[1]=(char)(optp->duration>>8);
                        sampacket.duration[2]=(char)(optp->duration>>16);
                        sampacket.duration[3]=(char)(optp->duration>>24);
                        sampacket.fwmode=optp->how|optp->who|optp->loglevel; /* set the mode */
                        sampacket.dstip[0]=(char)p->iph->ip_dst.s_addr; /* destination IP */
                        sampacket.dstip[1]=(char)(p->iph->ip_dst.s_addr>>8);
                        sampacket.dstip[2]=(char)(p->iph->ip_dst.s_addr>>16);
                        sampacket.dstip[3]=(char)(p->iph->ip_dst.s_addr>>24);
                        sampacket.srcip[0]=(char)p->iph->ip_src.s_addr; /* source IP */
                        sampacket.srcip[1]=(char)(p->iph->ip_src.s_addr>>8);
                        sampacket.srcip[2]=(char)(p->iph->ip_src.s_addr>>16);
                        sampacket.srcip[3]=(char)(p->iph->ip_src.s_addr>>24);
                        sampacket.protocol[0]=(char)p->iph->ip_proto;   /* protocol */
                        sampacket.protocol[1]=(char)(p->iph->ip_proto>>8);/* protocol */

                        if(IP_HAS_PORTS(p))
                        {   sampacket.srcport[0]=(char)p->sp;   /* set ports */
                            sampacket.srcport[1]=(char)(p->sp>>8);
                            sampacket.dstport[0]=(char)p->dp;
                            sampacket.dstport[1]=(char)(p->dp>>8);
                        }
                        else
                            sampacket.srcport[0]=sampacket.srcport[1]=sampacket.dstport[0]=sampacket.dstport[1]=0;

                        uint32_t sig_id = ntohl(((Unified2EventCommon *)event)->signature_id);
                        sampacket.sig_id[0]=(char)sig_id;        /* set signature ID */
                        sampacket.sig_id[1]=(char)(sig_id>>8);
                        sampacket.sig_id[2]=(char)(sig_id>>16);
                        sampacket.sig_id[3]=(char)(sig_id>>24);

#ifdef FWSAMDEBUG
                        LogMessage("DEBUG => [Alert_FWsam] Sending BLOCK\n");
                        LogMessage("DEBUG => [Alert_FWsam] Snort SeqNo:  %x\n",station->myseqno);
                        LogMessage("DEBUG => [Alert_FWsam] Mgmt SeqNo :  %x\n",station->stationseqno);
                        LogMessage("DEBUG => [Alert_FWsam] Status     :  %i\n",FWSAM_STATUS_BLOCK);
                        LogMessage("DEBUG => [Alert_FWsam] Mode       :  %i\n",optp->how|optp->who|optp->loglevel);
                        LogMessage("DEBUG => [Alert_FWsam] Duration   :  %li\n",optp->duration);
                        LogMessage("DEBUG => [Alert_FWsam] Protocol   :  %i\n",GET_IPH_PROTO(p));
#ifdef SUP_IP6
                        LogMessage("DEBUG => [Alert_FWsam] Src IP     :  %s\n",sfip_ntoa(GET_SRC_IP(p)));
                        LogMessage("DEBUG => [Alert_FWsam] Dest IP    :  %s\n",sfip_ntoa(GET_DST_IP(p)));
#else
                        LogMessage("DEBUG => [Alert_FWsam] Src IP     :  %s\n",inet_ntoa(GET_SRC_ADDR(p)));
                        LogMessage("DEBUG => [Alert_FWsam] Dest IP    :  %s\n",inet_ntoa(GET_DST_ADDR(p)));
#endif
                        LogMessage("DEBUG => [Alert_FWsam] Src Port   :  %i\n",p->sp);
                        LogMessage("DEBUG => [Alert_FWsam] Dest Port  :  %i\n",p->dp);
                        LogMessage("DEBUG => [Alert_FWsam] Sig_ID     :  %lu\n",ntohl(((Unified2EventCommon *)event)->signature_id));

#endif

                        encbuf=TwoFishAlloc(sizeof(FWsamPacket),FALSE,FALSE,station->stationfish); /* get the encryption buffer */
                        len=TwoFishEncrypt((char *)&sampacket,&encbuf,sizeof(FWsamPacket),FALSE,station->stationfish); /* encrypt the packet with current key */

                        if(send(stationsocket,encbuf,len,0)!=len) /* weird...could not send */
                        {   LogMessage("WARNING => [Alert_FWsam] Could not send to host %s. Will try again later.\n",sfip_ntoa(&station->stationip));
#ifdef WIN32
                            closesocket(stationsocket);
#else
                            close(stationsocket);
#endif
                            stationtry=0;
                        }
                        else
                        {   i=FWSAM_NETWAIT;
#ifdef WIN32
                            ioctlsocket(stationsocket,FIONBIO,&i);  /* set non blocking and wait for  */
#else
                            ioctl(stationsocket,FIONBIO,&i);        /* set non blocking and wait for  */
#endif
                            while(i-- >1)                           /* the response packet   */
                            {   waitms(10); /* wait for response (default maximum 3 secs */
                                if(recv(stationsocket,encbuf,len,0)==len)
                                    i=0; /* if we received packet we set the counter to 0. */
                                         /* by the time we check with if, it's already dec'ed to -1 */
                            }
                            if(!i) /* id we timed out (i was one, then dec'ed)... */
                            {   LogMessage("WARNING => [Alert_FWsam] Did not receive response from host %s. Will try again later.\n",sfip_ntoa(&station->stationip));
#ifdef WIN32
                                closesocket(stationsocket);
#else
                                close(stationsocket);
#endif
                                stationtry=0;
                            }
                            else /* got a packet */
                            {   decbuf=(char *)&sampacket; /* get the pointer to the packet struct */
                                len=TwoFishDecrypt(encbuf,&decbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,FALSE,station->stationfish); /* try to decrypt the packet with current key */

                                if(len!=sizeof(FWsamPacket)) /* invalid decryption */
                                {   strcpy(station->stationkey,station->initialkey); /* try the intial key */
                                    TwoFishDestroy(station->stationfish);
                                    station->stationfish=TwoFishInit(station->stationkey); /* re-initialize the TwoFish with the intial key */
                                    len=TwoFishDecrypt(encbuf,&decbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,FALSE,station->stationfish); /* try again to decrypt */
                                    LogMessage("INFO => [Alert_FWsam] Had to use initial key!\n");
                                }
                                if(len==sizeof(FWsamPacket)) /* valid decryption */
                                {   if(sampacket.version==FWSAM_PACKETVERSION)/* master speaks my language */
                                    {   if(sampacket.status==FWSAM_STATUS_OK || sampacket.status==FWSAM_STATUS_NEWKEY
                                        || sampacket.status==FWSAM_STATUS_RESYNC || sampacket.status==FWSAM_STATUS_HOLD)
                                        {   station->stationseqno=sampacket.fwseqno[0] | (sampacket.fwseqno[1]<<8); /* get stations seqno */
                                            station->lastcontact=(unsigned long)time(NULL); /* set the last contact time (not used yet) */
#ifdef FWSAMDEBUG
                                    LogMessage("DEBUG => [Alert_FWsam] Received %s\n",sampacket.status==FWSAM_STATUS_OK?"OK":
                                                                           sampacket.status==FWSAM_STATUS_NEWKEY?"NEWKEY":
                                                                           sampacket.status==FWSAM_STATUS_RESYNC?"RESYNC":
                                                                           sampacket.status==FWSAM_STATUS_HOLD?"HOLD":"ERROR");
                                    LogMessage("DEBUG => [Alert_FWsam] Snort SeqNo:  %x\n",sampacket.snortseqno[0]|(sampacket.snortseqno[1]<<8));
                                    LogMessage("DEBUG => [Alert_FWsam] Mgmt SeqNo :  %x\n",station->stationseqno);
                                    LogMessage("DEBUG => [Alert_FWsam] Status     :  %i\n",sampacket.status);
                                    LogMessage("DEBUG => [Alert_FWsam] Version    :  %i\n",sampacket.version);
#endif
                                            if(sampacket.status==FWSAM_STATUS_HOLD)
                                            {   i=FWSAM_NETHOLD;            /* Stay on hold for a maximum of 60 secs (default) */
                                                while(i-- >1)                           /* the response packet   */
                                                {   waitms(10); /* wait for response  */
                                                    if(recv(stationsocket,encbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,0)==sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE)
                                                      i=0; /* if we received packet we set the counter to 0. */
                                                }
                                                if(!i) /* id we timed out (i was one, then dec'ed)... */
                                                {   LogMessage("WARNING => [Alert_FWsam] Did not receive response from host %s. Will try again later.\n",sfip_ntoa(&station->stationip));
                                                    stationtry=0;
                                                    sampacket.status=FWSAM_STATUS_ERROR;
                                                }
                                                else /* got a packet */
                                                {   decbuf=(char *)&sampacket; /* get the pointer to the packet struct */
                                                    len=TwoFishDecrypt(encbuf,&decbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,FALSE,station->stationfish); /* try to decrypt the packet with current key */

                                                    if(len!=sizeof(FWsamPacket)) /* invalid decryption */
                                                    {   strcpy(station->stationkey,station->initialkey); /* try the intial key */
                                                        TwoFishDestroy(station->stationfish);
                                                        station->stationfish=TwoFishInit(station->stationkey); /* re-initialize the TwoFish with the intial key */
                                                        len=TwoFishDecrypt(encbuf,&decbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,FALSE,station->stationfish); /* try again to decrypt */
                                                        LogMessage("INFO => [Alert_FWsam] Had to use initial key again!\n");
                                                    }
#ifdef FWSAMDEBUG
                                    LogMessage("DEBUG => [Alert_FWsam] Received %s\n",sampacket.status==FWSAM_STATUS_OK?"OK":
                                                                           sampacket.status==FWSAM_STATUS_NEWKEY?"NEWKEY":
                                                                           sampacket.status==FWSAM_STATUS_RESYNC?"RESYNC":
                                                                           sampacket.status==FWSAM_STATUS_HOLD?"HOLD":"ERROR");
                                    LogMessage("DEBUG => [Alert_FWsam] Snort SeqNo:  %x\n",sampacket.snortseqno[0]|(sampacket.snortseqno[1]<<8));
                                    LogMessage("DEBUG => [Alert_FWsam] Mgmt SeqNo :  %x\n",station->stationseqno);
                                    LogMessage("DEBUG => [Alert_FWsam] Status     :  %i\n",sampacket.status);
                                    LogMessage("DEBUG => [Alert_FWsam] Version    :  %i\n",sampacket.version);
#endif
                                                    if(len!=sizeof(FWsamPacket)) /* invalid decryption */
                                                    {   ErrorMessage("ERROR => [Alert_FWsam] Password mismatch! Ignoring host %s.\n",sfip_ntoa(&station->stationip));
                                                        deletestation=TRUE;
                                                        sampacket.status=FWSAM_STATUS_ERROR;
                                                    }
                                                    else if(sampacket.version!=FWSAM_PACKETVERSION) /* invalid protocol version */
                                                    {   ErrorMessage("ERROR => [Alert_FWsam] Protocol version error! Ignoring host %s.\n",sfip_ntoa(&station->stationip));
                                                        deletestation=TRUE;
                                                        sampacket.status=FWSAM_STATUS_ERROR;
                                                    }
                                                    else if(sampacket.status!=FWSAM_STATUS_OK && sampacket.status!=FWSAM_STATUS_NEWKEY && sampacket.status!=FWSAM_STATUS_RESYNC)
                                                    {   ErrorMessage("ERROR => [Alert_FWsam] Funky handshake error! Ignoring host %s.\n",sfip_ntoa(&station->stationip));
                                                        deletestation=TRUE;
                                                        sampacket.status=FWSAM_STATUS_ERROR;
                                                    }
                                                }
                                            }
                                            if(sampacket.status==FWSAM_STATUS_RESYNC)  /* if station want's to resync... */
                                            {   strcpy(station->stationkey,station->initialkey); /* ...we use the intial key... */
                                                memcpy(station->fwkeymod,sampacket.duration,4);  /* and note the random key modifier */
                                            }
                                            if(sampacket.status==FWSAM_STATUS_NEWKEY || sampacket.status==FWSAM_STATUS_RESYNC)
                                            {
                                                FWsamNewStationKey(station,&sampacket); /* generate new TwoFish keys */
#ifdef FWSAMDEBUG
                                                    LogMessage("DEBUG => [Alert_FWsam] Generated new encryption key...\n");
#endif
                                            }
#ifdef WIN32
                                            closesocket(stationsocket);
#else
                                            close(stationsocket);
#endif
                                            stationtry=0;
                                        }
                                        else if(sampacket.status==FWSAM_STATUS_ERROR) /* if SnortSam reports an error on second try, */
                                        {
#ifdef WIN32
                                            closesocket(stationsocket);               /* something is messed up and ... */
#else
                                            close(stationsocket);
#endif
                                            if(stationtry>1)                          /* we ignore that station. */
                                            {   deletestation=TRUE;                   /* flag for deletion */
                                                ErrorMessage("ERROR => [Alert_FWsam] Could not renegotiate key! Ignoring host %s.\n",sfip_ntoa(&station->stationip));
                                            }
                                            else                            /* if we get an error on the first try, */
                                            {   if(!FWsamCheckIn(station))  /* we first try to check in again. */
                                                {   deletestation=TRUE;
                                                    ErrorMessage("ERROR => [Alert_FWsam] Password mismatch! Ignoring host %s.\n",sfip_ntoa(&station->stationip));
                                                }
                                            }
                                        }
                                        else /* an unknown status means trouble... */
                                        {   ErrorMessage("ERROR => [Alert_FWsam] Funky handshake error! Ignoring host %s.\n",sfip_ntoa(&station->stationip));
#ifdef WIN32
                                            closesocket(stationsocket);
#else
                                            close(stationsocket);
#endif
                                            deletestation=TRUE;
                                        }
                                    }
                                    else   /* if the SnortSam agent uses a different packet version, we have no choice but to ignore it. */
                                    {   ErrorMessage("ERROR => [Alert_FWsam] Protocol version error! Ignoring host %s.\n",sfip_ntoa(&station->stationip));
#ifdef WIN32
                                        closesocket(stationsocket);
#else
                                        close(stationsocket);
#endif
                                        deletestation=TRUE;
                                    }
                                }
                                else /* if the intial key failed to decrypt as well, the keys are not configured the same, and we ignore that SnortSam station. */
                                {   ErrorMessage("ERROR => [Alert_FWsam] Password mismatch! Ignoring host %s.\n",sfip_ntoa(&station->stationip));
#ifdef WIN32
                                    closesocket(stationsocket);
#else
                                    close(stationsocket);
#endif
                                    deletestation=TRUE;
                                }
                            }
                        }
                        free(encbuf); /* release of the TwoFishAlloc'ed encryption buffer */
                    }
                    if(stationtry==0 || deletestation)      /* if everything went real well, or real bad... */
                    {   if(deletestation){                  /* If it went bad, we remove the station from the list by marking the IP */
//                          station->stationip.s_addr=0;
                            station->stationip.ip32[0]=0;
                                                }
                        fwsamlist=fwsamlist->next;
                    }
                }
                else
                    fwsamlist=fwsamlist->next;
            }
        }
        else
        {
#ifdef FWSAMDEBUG
            LogMessage("DEBUG => [Alert_FWsam] Skipping repetitive block.\n");
#endif
        }
    }
}

/*  FWsamCheckOut will be called when Snort exists. It de-registeres this snort sensor
 *  from the list of sensor that the SnortSam agent keeps.
 */
void FWsamCheckOut(FWsamStation *station)
{
    FWsamPacket sampacket;
    SOCKET stationsocket;
    int i,len;
    char *encbuf,*decbuf;


    stationsocket=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(stationsocket==INVALID_SOCKET)
        FatalError("ERROR => [Alert_FWsam](FWsamCheckOut) Funky socket error (socket)!\n");
    if(bind(stationsocket,(struct sockaddr *)&(station->localsocketaddr),sizeof(struct sockaddr)))
        FatalError("ERROR => [Alert_FWsam](FWsamCheckOut) Could not bind socket!\n");

    /* let's connect to the agent */
    if(!connect(stationsocket,(struct sockaddr *)&station->stationsocketaddr,sizeof(struct sockaddr)))
    {
        LogMessage("INFO => [Alert_FWsam](FWsamCheckOut) Disconnecting from host %s.\n",sfip_ntoa(&station->stationip));
        /* now build the packet */
        station->myseqno+=station->stationseqno; /* increase my seqno */
        sampacket.endiancheck=1;
        sampacket.snortseqno[0]=(char)station->myseqno;
        sampacket.snortseqno[1]=(char)(station->myseqno>>8);
        sampacket.fwseqno[0]=(char)station->stationseqno; /* fill station seqno */
        sampacket.fwseqno[1]=(char)(station->stationseqno>>8);
        sampacket.status=FWSAM_STATUS_CHECKOUT;  /* checking out... */
        sampacket.version=FWSAM_PACKETVERSION;

#ifdef FWSAMDEBUG
            LogMessage("DEBUG => [Alert_FWsam](FWsamCheckOut) Sending CHECKOUT\n");
            LogMessage("DEBUG => [Alert_FWsam](FWsamCheckOut) Snort SeqNo:  %x\n",station->myseqno);
            LogMessage("DEBUG => [Alert_FWsam](FWsamCheckOut) Mgmt SeqNo :  %x\n",station->stationseqno);
            LogMessage("DEBUG => [Alert_FWsam](FWsamCheckOut) Status     :  %i\n",sampacket.status);

#endif

        encbuf=TwoFishAlloc(sizeof(FWsamPacket),FALSE,FALSE,station->stationfish); /* get encryption buffer */
        len=TwoFishEncrypt((char *)&sampacket,&encbuf,sizeof(FWsamPacket),FALSE,station->stationfish); /* encrypt packet with current key */

        if(send(stationsocket,encbuf,len,0)==len)
        {
            i=FWSAM_NETWAIT;
#ifdef WIN32
            ioctlsocket(stationsocket,FIONBIO,&i);  /* set non blocking and wait for  */
#else
            ioctl(stationsocket,FIONBIO,&i);        /* set non blocking and wait for  */
#endif
            while(i-- >1)
            {
                waitms(10);                 /* ...wait a maximum of 3 secs for response... */
                if(recv(stationsocket,encbuf,len,0)==len) /* ... for the status packet */
                    i=0;
            }

            if(i) /* if we got the packet */
            {
                decbuf=(char *)&sampacket;
                len=TwoFishDecrypt(encbuf,&decbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,FALSE,station->stationfish);

                if(len!=sizeof(FWsamPacket)) /* invalid decryption */
                {   strcpy(station->stationkey,station->initialkey); /* try initial key */
                    TwoFishDestroy(station->stationfish);            /* toss this fish */
                    station->stationfish=TwoFishInit(station->stationkey); /* re-initialze TwoFish with initial key */
                    len=TwoFishDecrypt(encbuf,&decbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,FALSE,station->stationfish); /* and try to decrypt again */
                    LogMessage("INFO => [Alert_FWsam](FWsamCheckOut) Had to use initial key!\n");
                }
                if(len==sizeof(FWsamPacket)) /* valid decryption */
                {   if(sampacket.version!=FWSAM_PACKETVERSION) /* but don't really care since we are on the way out */
                        ErrorMessage("WARNING => [Alert_FWsam](FWsamCheckOut) Protocol version error! What the hell, we're quitting anyway! :)\n");
                }
                else
                    ErrorMessage("WARNING => [Alert_FWsam](FWsamCheckOut) Password mismatch! What the hell, we're quitting anyway! :)\n");
            }
        }
        free(encbuf); /* release TwoFishAlloc'ed buffer */
    }
    else
        LogMessage("WARNING => [Alert_FWsam] Could not connect to host %s for CheckOut. What the hell, we're quitting anyway! :)\n",sfip_ntoa(&station->stationip));
#ifdef WIN32
    closesocket(stationsocket);
#else
    close(stationsocket);
#endif
}



/*   FWSamFree: Disconnects all FW-1 management stations,
 *   closes sockets, and frees the structures.
 */
void FWsamFree(FWsamList *list)
{
    FWsamList *next;

    while(list) /* Free pointer list for rule type */
    {
        next=list->next;
        free(list);
        list=next;
    }
    list=FWsamStationList;

    while(list) /* Free global pointer list and stations */
    {
        next=list->next;
        if (list->station)
        {
            if(list->station->stationip.ip32[0])
            //if(list->station->stationip.s_addr)
                FWsamCheckOut(list->station); /* Send a Check-Out to SnortSam, */

            TwoFishDestroy(list->station->stationfish); /* toss the fish, */
            free(list->station); /* free station, */
        }
        free(list); /* free pointer, */
        list=next; /* and move to next. */
    }
    FWsamStationList=NULL;
    if(FWsamOptionField)
        free(FWsamOptionField);
}

void AlertFWsamCleanExitFunc(int signal, void *arg)
{
    FWsamList *fwsamlist;

#ifdef FWSAMDEBUG
    LogMessage("DEBUG => [Alert_FWsam](AlertFWsamCleanExitFunc) Exiting...\n");
#endif

    fwsamlist=(FWsamList *)arg;
    FWsamFree(fwsamlist); /* Free all elements */
}

void AlertFWsamRestartFunc(int signal, void *arg)
{
    FWsamList *fwsamlist;

#ifdef FWSAMDEBUG
    LogMessage("DEBUG => [Alert_FWsam](AlertFWsamRestartFunc) Restarting...\n");
#endif

    fwsamlist=(FWsamList *)arg;
    FWsamFree(fwsamlist); /* Free all elements */
}

/*  This routine registers this Snort sensor with SnortSam.
 *  It will also change the encryption key based on some variables.
 */
int FWsamCheckIn(FWsamStation *station)
{
    int i,len,stationok=TRUE;
    FWsamPacket sampacket;
    char *encbuf,*decbuf;
    SOCKET stationsocket;


    /* create a socket for the station */
    stationsocket=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);

    if(stationsocket==INVALID_SOCKET)
        FatalError("ERROR => [Alert_FWsam](FWsamCheckIn) Funky socket error (socket)!\n");
    if(bind(stationsocket,(struct sockaddr *)&(station->localsocketaddr),sizeof(struct sockaddr)))
        FatalError("ERROR => [Alert_FWsam](FWsamCheckIn) Could not bind socket!\n");

    i=TRUE;
    /* let's connect to the agent */
    if(connect(stationsocket,(struct sockaddr *)&station->stationsocketaddr,sizeof(struct sockaddr)))
        LogMessage("WARNING => [Alert_FWsam](FWsamCheckIn) Could not connect to host %s. Will try later.\n",sfip_ntoa(&station->stationip));
    else
    {
        LogMessage("INFO => [Alert_FWsam](FWsamCheckIn) Connected to host %s.\n",sfip_ntoa(&station->stationip));
        /* now build the packet */
        sampacket.endiancheck=1;
        sampacket.snortseqno[0]=(char)station->myseqno; /* fill my sequence number number */
        sampacket.snortseqno[1]=(char)(station->myseqno>>8); /* fill my sequence number number */
        sampacket.status=FWSAM_STATUS_CHECKIN; /* let's check in */
        sampacket.version=FWSAM_PACKETVERSION; /* set the packet version */
        memcpy(sampacket.duration,station->mykeymod,4);  /* we'll send SnortSam our key modifier in the duration slot */
                                               /* (the checkin packet is just the plain initial key) */
#ifdef FWSAMDEBUG
            LogMessage("DEBUG => [Alert_FWsam](FWsamCheckIn) Sending CheckIn\n");
            LogMessage("DEBUG => [Alert_FWsam](FWsamCheckIn) Snort SeqNo:  %x\n",station->myseqno);
            LogMessage("DEBUG => [Alert_FWsam](FWsamCheckIn) Mode       :  %i\n",sampacket.status);
            LogMessage("DEBUG => [Alert_FWsam](FWsamCheckIn) Version    :  %i\n",sampacket.version);
#endif
        encbuf=TwoFishAlloc(sizeof(FWsamPacket),FALSE,FALSE,station->stationfish); /* get buffer for encryption */
        len=TwoFishEncrypt((char *)&sampacket,&encbuf,sizeof(FWsamPacket),FALSE,station->stationfish); /* encrypt with initial key */
        if(send(stationsocket,encbuf,len,0)!=len) /* weird...could not send */
            LogMessage("WARNING => [Alert_FWsam](FWsamCheckIn) Could not send to host %s. Will try again later.\n",sfip_ntoa(&station->stationip));
        else
        {
            i=FWSAM_NETWAIT;
#ifdef WIN32
            ioctlsocket(stationsocket,FIONBIO,&i);  /* set non blocking and wait for  */
#else
            ioctl(stationsocket,FIONBIO,&i);        /* set non blocking and wait for  */
#endif
            while(i-- >1)
            {
                waitms(10); /* wait a maximum of 3 secs for response */
                if(recv(stationsocket,encbuf,len,0)==len)
                    i=0;
            }
            if(!i) /* time up? */
                LogMessage("WARNING => [Alert_FWsam](FWsamCheckIn) Did not receive response from host %s. Will try again later.\n",sfip_ntoa(&station->stationip));
            else
            {
                decbuf=(char *)&sampacket; /* got status packet */
                len=TwoFishDecrypt(encbuf,&decbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,FALSE,station->stationfish); /* try to decrypt with initial key */
                if(len==sizeof(FWsamPacket)) /* valid decryption */
                {
#ifdef FWSAMDEBUG
                    LogMessage("DEBUG => [Alert_FWsam](FWsamCheckIn) Received %s\n",sampacket.status==FWSAM_STATUS_OK?"OK":
                                                               sampacket.status==FWSAM_STATUS_NEWKEY?"NEWKEY":
                                                               sampacket.status==FWSAM_STATUS_RESYNC?"RESYNC":
                                                               sampacket.status==FWSAM_STATUS_HOLD?"HOLD":"ERROR");
                    LogMessage("DEBUG => [Alert_FWsam](FWsamCheckIn) Snort SeqNo:  %x\n",sampacket.snortseqno[0]|(sampacket.snortseqno[1]<<8));
                    LogMessage("DEBUG => [Alert_FWsam](FWsamCheckIn) Mgmt SeqNo :  %x\n",sampacket.fwseqno[0]|(sampacket.fwseqno[1]<<8));
                    LogMessage("DEBUG => [Alert_FWsam](FWsamCheckIn) Status     :  %i\n",sampacket.status);
                    LogMessage("DEBUG => [Alert_FWsam](FWsamCheckIn) Version    :  %i\n",sampacket.version);
#endif
                    if(sampacket.version==FWSAM_PACKETVERSION) /* master speaks my language */
                    {
                        if(sampacket.status==FWSAM_STATUS_OK || sampacket.status==FWSAM_STATUS_NEWKEY || sampacket.status==FWSAM_STATUS_RESYNC)
                        {
                            station->stationseqno=sampacket.fwseqno[0]|(sampacket.fwseqno[1]<<8); /* get stations seqno */
                            station->lastcontact=(unsigned long)time(NULL);

                            if(sampacket.status==FWSAM_STATUS_NEWKEY || sampacket.status==FWSAM_STATUS_RESYNC)  /* generate new keys */
                            {
                                memcpy(station->fwkeymod,sampacket.duration,4); /* note the key modifier */
                                FWsamNewStationKey(station,&sampacket); /* and generate new TwoFish keys (with key modifiers) */
#ifdef FWSAMDEBUG
                LogMessage("DEBUG => [Alert_FWsam](FWsamCheckIn) Generated new encryption key...\n");
#endif
                            }
                        }
                        else /* weird, got a strange status back */
                        {
                            ErrorMessage("ERROR => [Alert_FWsam](FWsamCheckIn) Funky handshake error! Ignoring host %s.\n",sfip_ntoa(&station->stationip));
                            stationok=FALSE;
                        }
                    }
                    else /* packet version does not match */
                    {
                        ErrorMessage("ERROR =>[Alert_FWsam](FWsamCheckIn) Protocol version error! Ignoring host %s.\n",sfip_ntoa(&station->stationip));
                        stationok=FALSE;
                    }
                }
                else /* key does not match */
                {
                    ErrorMessage("ERROR => [Alert_FWsam](FWsamCheckIn) Password mismatch! Ignoring host %s.\n",sfip_ntoa(&station->stationip));
                    stationok=FALSE;
                }
            }
        }
        free(encbuf); /* release TwoFishAlloc'ed buffer */
    }
#ifdef WIN32
    closesocket(stationsocket);
#else
    close(stationsocket);
#endif
    return stationok;
}
#undef FWSAMDEBUG

