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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include <time.h>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* !WIN32 */
#include <errno.h>
#include <signal.h>

#include "log.h"
#include "rules.h"
#include "util.h"
#include "debug.h"

#include "barnyard2.h"


char *data_dump_buffer;     /* printout buffer for PrintNetData */
int data_dump_buffer_size = 0;/* size of printout buffer */
int dump_size;              /* amount of data to print */

extern uint16_t event_id;

void AllocDumpBuf();


/***************** LOG ASCII ROUTINES *******************/

#ifndef NO_NON_ETHER_DECODER
#ifndef SUP_IP6
static unsigned char ezero[6];  /* crap for ARP */
#endif
#endif

/*
 * Function: PrintNetData(FILE *, u_char *,int)
 *
 * Purpose: Do a side by side dump of a buffer, hex dump of buffer bytes on
 *          the left, decoded ASCII on the right.
 *
 * Arguments: fp => ptr to stream to print to
 *            start => pointer to buffer data
 *            len => length of data buffer
 *
 * Returns: void function
 */
void PrintNetData(FILE * fp, const u_char * start, const int len)
{
    char *end;          /* ptr to buffer end */
    int i;          /* counter */
    int j;          /* counter */
    int dbuf_size;      /* data buffer size */
    int done;           /* flag */
    char *data;         /* index pointer */
    char *frame_ptr;        /* we use 66 byte frames for a printed line */
    char *d_ptr;        /* data pointer into the frame */
    char *c_ptr;        /* char pointer into the frame */
    char conv[] = "0123456789ABCDEF";   /* xlation lookup table */

    /* initialization */
    done = 0;

   /* zero, print a <CR> and get out */
    if(!len)
    {
        fputc('\n', fp);
        return;
    }

    if(start == NULL)
    {
        printf("Got NULL ptr in PrintNetData()\n");
        return;
    }
   
    end = (char*) (start + (len - 1));    /* set the end of buffer ptr */

    if(len > IP_MAXPACKET)
    {
        if (BcLogVerbose())
        {
            printf("Got bogus buffer length (%d) for PrintNetData, defaulting to 16 bytes!\n", len);
        }

        if (BcVerboseByteDump())
        {
            dbuf_size = (FRAME_SIZE + 8) + (FRAME_SIZE + 8) + 1;
        }
        else
        {
            dbuf_size = FRAME_SIZE + FRAME_SIZE + 1;
        }

        /* dbuf_size = 66 + 67; */
        end =  (char*) (start + 15);
    }
    else
    {
        if (BcVerboseByteDump())
        {
            /* figure out how big the printout data buffer has to be */
            dbuf_size = ((len / 16) * (FRAME_SIZE + 8)) + (FRAME_SIZE + 8) + 1;
        }
        else
        {
            /* figure out how big the printout data buffer has to be */
            dbuf_size = ((len / 16) * FRAME_SIZE) + FRAME_SIZE + 1;
        }

        /* dbuf_size = ((len / 16) * 66) + 67; */
    }

    /* generate the buffer */
    if (data_dump_buffer == NULL)
    {
        AllocDumpBuf();
    }

    if (data_dump_buffer == NULL)
        FatalError("Failed allocating %X bytes to data_dump_buffer!\n", data_dump_buffer_size);

    /* clean it out */
    memset(data_dump_buffer, 0x20, dbuf_size);

    /* set the byte buffer pointer to step thru the data buffer */
    data = (char*) start;

    /* set the frame pointer to the start of the printout buffer */
    frame_ptr = data_dump_buffer;

    /* initialize counters and frame index pointers */
    i = 0;
    j = 0;

    /* loop thru the whole buffer */
    while(!done)
    {
        if (BcVerboseByteDump())
        {
            d_ptr = frame_ptr + 8;
            c_ptr = (frame_ptr + 8 + C_OFFSET);
            SnortSnprintf(frame_ptr,
                          (data_dump_buffer + data_dump_buffer_size) - frame_ptr,
                          "0x%04X: ", j);
            j += 16;
        }
        else
        {
            d_ptr = frame_ptr;
            c_ptr = (frame_ptr + C_OFFSET);
        }

        /* process 16 bytes per frame */
        for(i = 0; i < 16; i++)
        {
            /*
             * look up the ASCII value of the first nybble of the current
             * data buffer
             */
            *d_ptr = conv[((*data & 0xFF) >> 4)];
            d_ptr++;

            /* look up the second nybble */
            *d_ptr = conv[((*data & 0xFF) & 0x0F)];
            d_ptr++;

            /* put a space in between */
            *d_ptr = 0x20;
            d_ptr++;

            /* print out the char equivalent */
            if(*data > 0x1F && *data < 0x7F)
                *c_ptr = (char) (*data & 0xFF);
            else
                *c_ptr = 0x2E;

            c_ptr++;

            /* increment the pointer or finish up */
            if(data < end)
                data++;
            else
            {
                *c_ptr = '\n';
                c_ptr++;
                *c_ptr = '\n';
                c_ptr++;
                *c_ptr = 0;

                dump_size = (int) (c_ptr - data_dump_buffer);
                fwrite(data_dump_buffer, dump_size, 1, fp);

                //ClearDumpBuf();
                return;
            }
        }

        *c_ptr = '\n';
        if (BcVerboseByteDump())
        {
            frame_ptr += (FRAME_SIZE + 8);
        }
        else
        {
            frame_ptr += FRAME_SIZE;
        }
    }

    //ClearDumpBuf();
}



/*
 * Function: PrintCharData(FILE *, char *,int)
 *
 * Purpose: Dump the ASCII data from a packet
 *          the left, decoded ASCII on the right.
 *
 * Arguments: fp => ptr to stream to print to
 *            data => pointer to buffer data
 *            data_len => length of data buffer
 *
 * Returns: void function
 */
void PrintCharData(FILE * fp, char *data, int data_len)
{
    int bytes_processed;    /* count of bytes in the data buffer
                 * processed so far */
    int linecount = 0;      /* number of lines in this dump */
    char *index;        /* index pointer into the data buffer */
    char *ddb_ptr;      /* index pointer into the data_dump_buffer */
    int size;

    /* if there's no data, return */
    if(data == NULL)
    {
        return;
    }

    /* setup the pointers and counters */
    bytes_processed = data_len;
    index = data;

    /* allocate a buffer to print the data to */
    //data_dump_buffer = (char *) calloc(data_len + (data_len >> 6) + 2, sizeof(char));
    if (data_dump_buffer == NULL)
    {
        AllocDumpBuf();
    }

    size = (data_len + (data_len >> 6) + 2) * sizeof(char);

    /* Based on data_len < 65535, this should never happen, but check just in
     * case sizeof(char) is big or something. */
    if (data_dump_buffer_size < size)
    {
        data_dump_buffer_size = size;
        ClearDumpBuf();

        /* Reallocate for a bigger size. */
        AllocDumpBuf();
    }

    if (data_dump_buffer == NULL)
        FatalError("Failed allocating %X bytes to data_dump_buffer!\n", data_dump_buffer_size);

    /* clean it out */
    memset(data_dump_buffer, 0x20, size);

    ddb_ptr = data_dump_buffer;

    /* loop thru the bytes in the data buffer */
    while(bytes_processed)
    {
        if(*index > 0x1F && *index < 0x7F)
        {
            *ddb_ptr = *index;
        }
        else
        {
            *ddb_ptr = '.';
        }

        if(++linecount == 64)
        {
            ddb_ptr++;
            *ddb_ptr = '\n';
            linecount = 0;
        }
        ddb_ptr++;
        index++;
        bytes_processed--;
    }

    /* slam a \n on the back */
    ddb_ptr++;
    *ddb_ptr = '\n';
    ddb_ptr++;

    /* setup the globals */

    dump_size = (int) (ddb_ptr - data_dump_buffer);
    fwrite(data_dump_buffer, dump_size, 1, fp);

    //ClearDumpBuf();
}



/*
 * Function: PrintIPPkt(FILE *, int, Packet *)
 *
 * Purpose: Dump the packet to the stream pointer
 *
 * Arguments: fp => pointer to print data to
 *            type => packet protocol
 *            p => pointer to decoded packet struct
 *
 * Returns: void function
 */
void PrintIPPkt(FILE * fp, int type, Packet * p)
{
    char timestamp[TIMEBUF_SIZE];

    if (p->packet_flags & PKT_LOGGED)
        return;

    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "PrintIPPkt type = %d\n", type););

    memset((char *) timestamp, 0, TIMEBUF_SIZE); /* bzero() deprecated, replaced with memset */
    ts_print((struct timeval *) & p->pkth->ts, timestamp);

    /* dump the timestamp */
    fwrite(timestamp, strlen(timestamp), 1, fp);

    /* dump the ethernet header if we're doing that sort of thing */
    if(BcOutputDataLink())
    {
        Print2ndHeader(fp, p);
    }
#ifdef MPLS
    if(p->mpls)
    {
        PrintMPLSHeader(fp, p);
    }
#endif
    /* etc */
    PrintIPHeader(fp, p);

    /* if this isn't a fragment, print the other header info */
    if(!p->frag_flag)
    {
        switch(GET_IPH_PROTO(p))
        {
            case IPPROTO_TCP:
                if(p->tcph != NULL)

                {
                    PrintTCPHeader(fp, p);
                }
                else
                {
#ifdef SUP_IP6
                    PrintNetData(fp, (u_char *) 
                                        (u_char *)p->iph + (GET_IPH_HLEN(p) << 2),
                                        GET_IP_PAYLEN(p));
#else
                    PrintNetData(fp, (u_char *) 
                                        ((u_char *)p->iph + (IP_HLEN(p->iph) << 2)), 
                                        (p->actual_ip_len - (IP_HLEN(p->iph) << 2)));
#endif
                }

                break;

            case IPPROTO_UDP:
                if(p->udph != NULL)
                {
                    PrintUDPHeader(fp, p);
                }
                else
                {
#ifdef SUP_IP6
                    PrintNetData(fp, (u_char *) 
                                        (u_char *)p->iph + (GET_IPH_HLEN(p) << 2),
                                        GET_IP_PAYLEN(p));
#else
                    PrintNetData(fp, (u_char *) 
                                        ((u_char *)p->iph + (IP_HLEN(p->iph) << 2)), 
                                        (p->actual_ip_len - (IP_HLEN(p->iph) << 2)));
#endif
                }

                break;

            case IPPROTO_ICMP:
                if(p->icmph != NULL)
                {
                    PrintICMPHeader(fp, p);
                }
                else
                {
/*
           printf("p->iph: %p\n", p->iph);
           printf("p->icmph: %p\n", p->icmph);
           printf("p->iph->ip_hlen: %d\n", (IP_HLEN(p->iph) << 2));
           printf("p->iph->ip_len: %d\n", p->iph->ip_len);
 */
#ifdef SUP_IP6
                    PrintNetData(fp, (u_char *) 
                        ((u_char *)p->iph + (GET_IPH_HLEN(p) << 2)),
                        GET_IP_PAYLEN(p));
#else
                    PrintNetData(fp, (u_char *) 
                        ((u_char *) p->iph + (IP_HLEN(p->iph) << 2)), 
                        (ntohs(p->iph->ip_len) - (IP_HLEN(p->iph) << 2)));
#endif
                }

                break;

            default:
                break;
        }
    }
    /* dump the application layer data */
    if (BcOutputAppData() && !BcVerboseByteDump())
    {
        if (BcOutputCharData())
            PrintCharData(fp, (char*) p->data, p->dsize);
        else
            PrintNetData(fp, p->data, p->dsize);
    }
    else if (BcVerboseByteDump())
    {
        PrintNetData(fp, p->pkt, p->pkth->caplen);
    }

    fprintf(fp, "=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+"
            "=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n\n");

    p->packet_flags |= PKT_LOGGED;
}



/****************************************************************************
 *
 * Function: OpenAlertFile(char *)
 *
 * Purpose: Set up the file pointer/file for alerting
 *
 * Arguments: filearg => the filename to open
 *
 * Returns: file handle
 *
 ***************************************************************************/
FILE *OpenAlertFile(const char *filearg)
{
    char filename[STD_BUF+1];
    FILE *file;
    char suffix[5];     /* filename suffix */
#ifdef WIN32
    SnortStrncpy(suffix, ".ids", sizeof(suffix));
#else
    suffix[0] = '\0';
#endif

    if(filearg == NULL)
    {
        if(!BcDaemonMode())
            SnortSnprintf(filename, STD_BUF, "%s/alert%s", barnyard2_conf->log_dir, suffix);
        else
            SnortSnprintf(filename, STD_BUF, "%s/%s", barnyard2_conf->log_dir, 
                    DEFAULT_DAEMON_ALERT_FILE);
    }
    else
    {
        SnortSnprintf(filename, STD_BUF, "%s", filearg);
    }

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Opening alert file: %s\n", filename););

    if((file = fopen(filename, "a")) == NULL)
    {
        FatalError("OpenAlertFile() => fopen() alert file %s: %s\n",
                   filename, strerror(errno));
    }
#ifdef WIN32
    /* Do not buffer in WIN32 */
    setvbuf(file, (char *) NULL, _IONBF, (size_t) 0);
#else
    setvbuf(file, (char *) NULL, _IOLBF, (size_t) 0);
#endif

    return file;
}

/****************************************************************************
 *
 * Function: RollAlertFile(char *)
 *
 * Purpose: rename existing alert file with by appending time to name
 *
 * Arguments: filearg => the filename to rename (same as for OpenAlertFile())
 *
 * Returns: 0=success, else errno
 *
 ***************************************************************************/
int RollAlertFile(const char *filearg)
{
    char oldname[STD_BUF+1];
    char newname[STD_BUF+1];
    char suffix[5];     /* filename suffix */
    time_t now = time(NULL);

#ifdef WIN32
    SnortStrncpy(suffix, ".ids", sizeof(suffix));
#else
    suffix[0] = '\0';
#endif

    if(filearg == NULL)
    {
        if(!BcDaemonMode())
            SnortSnprintf(oldname, STD_BUF, "%s/alert%s", barnyard2_conf->log_dir, suffix);
        else
            SnortSnprintf(oldname, STD_BUF, "%s/%s", barnyard2_conf->log_dir, 
                    DEFAULT_DAEMON_ALERT_FILE);
    }
    else
    {
        SnortSnprintf(oldname, STD_BUF, "%s", filearg);
    }
    SnortSnprintf(newname, sizeof(newname)-1, "%s.%lu", oldname, now);
    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Rolling alert file: %s\n", newname););

    if ( rename(oldname, newname) )
    {
        FatalError("RollAlertFile() => rename(%s, %s) = %s\n",
                   oldname, newname, strerror(errno));
    }
    return errno;
}


/*
 *
 * Function: AllocDumpBuf()
 *
 * Purpose: Allocate the buffer that PrintNetData() uses
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void AllocDumpBuf(void)
{
    if (data_dump_buffer_size == 0)
    {
        if (BcVerboseByteDump())
        {
            data_dump_buffer_size = (((IP_MAXPACKET+1)/16) * (FRAME_SIZE + 8)) + (FRAME_SIZE + 8) + 1;
        }
        else
        {
            data_dump_buffer_size = ((IP_MAXPACKET+1)/16) * FRAME_SIZE + FRAME_SIZE + 1;
        }
    }
    data_dump_buffer = (char *)calloc( 1,data_dump_buffer_size );

    /* make sure it got allocated properly */
    if(data_dump_buffer == NULL)
    {
        FatalError("AllocDumpBuf(): Failed allocating %X bytes!\n", data_dump_buffer_size);
    }
}

/*
 *
 * Function: ClearDumpBuf()
 *
 * Purpose: Clear out the buffer that PrintNetData() generates
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void ClearDumpBuf(void)
{
    if(data_dump_buffer)
        free(data_dump_buffer);
    else
        return;

    data_dump_buffer = NULL;

    dump_size  = 0;
}

/****************************************************************************
 *
 * Function: NoAlert(Packet *, char *)
 *
 * Purpose: Don't alert at all
 *
 * Arguments: p => pointer to the packet data struct
 *            msg => the message to not print in the alert
 *
 * Returns: void function
 *
 ***************************************************************************/
void NoAlert(Packet * p, char *msg, void *arg, void *event)
{
    return;
}


/****************************************************************************
 *
 * Function: NoLog(Packet *)
 *
 * Purpose: Don't log anything
 *
 * Arguments: p => packet to not log
 *
 * Returns: void function
 *
 ***************************************************************************/
void NoLog(Packet * p, char *msg, void *arg, void *event)
{
    return;
}

/****************************************************************************
 *
 * Function: Print2ndHeader(FILE *, Packet p)
 *
 * Purpose: Print2ndHeader -- prints second layber  header info.
 *
 * Arguments: fp => file stream to print to
 *
 * Returns: void function
 *
 ***************************************************************************/


void Print2ndHeader(FILE * fp, Packet * p)
{
	int	datalink = 0;

    switch(datalink) 
    {
        case DLT_EN10MB:        /* Ethernet */
            if(p && p->eh)
                PrintEthHeader(fp, p);
            break;
#ifndef NO_NON_ETHER_DECODER
#ifdef DLT_IEEE802_11
        case DLT_IEEE802_11:
            if(p && p->wifih)
                PrintWifiHeader(fp, p);
            break;
#endif     
        case DLT_IEEE802:                /* Token Ring */
            if(p && p->trh)
                PrintTrHeader(fp, p);
            break;    
#ifdef DLT_LINUX_SLL        
        case DLT_LINUX_SLL:
            if (p && p->sllh)
                PrintSLLHeader(fp, p);  /* Linux cooked sockets */
            break;
#endif
#endif  // NO_NON_ETHER_DECODER
        default:
            if (BcLogVerbose())
            {
                ErrorMessage("Datalink %i type 2nd layer display is not "
                             "supported\n", datalink);   
            }
    }
}



#ifndef NO_NON_ETHER_DECODER
/****************************************************************************
 *
 * Function: PrintTrHeader(FILE *, Packet p)
 &
 * Purpose: Print the packet TokenRing header to the specified stream
 *
 * Arguments: fp => file stream to print to
 *
 * Returns: void function
 ***************************************************************************/

void PrintTrHeader(FILE * fp, Packet * p)
{

    fprintf(fp, "%X:%X:%X:%X:%X:%X -> ", p->trh->saddr[0],
            p->trh->saddr[1], p->trh->saddr[2], p->trh->saddr[3],
            p->trh->saddr[4], p->trh->saddr[5]);
    fprintf(fp, "%X:%X:%X:%X:%X:%X\n", p->trh->daddr[0],
            p->trh->daddr[1], p->trh->daddr[2], p->trh->daddr[3],
            p->trh->daddr[4], p->trh->daddr[5]);

    fprintf(fp, "access control:0x%X frame control:0x%X\n", p->trh->ac,
            p->trh->fc);
    if(!p->trhllc)
        return;
    fprintf(fp, "DSAP: 0x%X SSAP 0x%X protoID: %X%X%X Ethertype: %X\n",
            p->trhllc->dsap, p->trhllc->ssap, p->trhllc->protid[0],
            p->trhllc->protid[1], p->trhllc->protid[2], p->trhllc->ethertype);
    if(p->trhmr)
    {
        fprintf(fp, "RIF structure is present:\n");
        fprintf(fp, "bcast: 0x%X length: 0x%X direction: 0x%X largest"
                "fr. size: 0x%X res: 0x%X\n",
                TRH_MR_BCAST(p->trhmr), TRH_MR_LEN(p->trhmr),
        TRH_MR_DIR(p->trhmr), TRH_MR_LF(p->trhmr),
                TRH_MR_RES(p->trhmr));
        fprintf(fp, "rseg -> %X:%X:%X:%X:%X:%X:%X:%X\n",
                p->trhmr->rseg[0], p->trhmr->rseg[1], p->trhmr->rseg[2],
                p->trhmr->rseg[3], p->trhmr->rseg[4], p->trhmr->rseg[5],
                p->trhmr->rseg[6], p->trhmr->rseg[7]);
    }
}
#endif  // NO_NON_ETHER_DECODER


/****************************************************************************
 *
 * Function: PrintEthHeader(FILE *)
 *
 * Purpose: Print the packet Ethernet header to the specified stream
 *
 * Arguments: fp => file stream to print to
 *
 * Returns: void function
 *
 ***************************************************************************/
void PrintEthHeader(FILE * fp, Packet * p)
{
    /* src addr */
    fprintf(fp, "%X:%X:%X:%X:%X:%X -> ", p->eh->ether_src[0],
            p->eh->ether_src[1], p->eh->ether_src[2], p->eh->ether_src[3],
            p->eh->ether_src[4], p->eh->ether_src[5]);

    /* dest addr */
    fprintf(fp, "%X:%X:%X:%X:%X:%X ", p->eh->ether_dst[0],
            p->eh->ether_dst[1], p->eh->ether_dst[2], p->eh->ether_dst[3],
            p->eh->ether_dst[4], p->eh->ether_dst[5]);

    /* protocol and pkt size */
    fprintf(fp, "type:0x%X len:0x%X\n", ntohs(p->eh->ether_type), p->pkth->caplen);
}

#ifdef MPLS
void PrintMPLSHeader(FILE* log, Packet* p)
{

    fprintf(log,"label:0x%05X exp:0x%X bos:0x%X ttl:0x%X\n",
            p->mplsHdr.label, p->mplsHdr.exp, p->mplsHdr.bos, p->mplsHdr.ttl);
}
#endif

#ifndef NO_NON_ETHER_DECODER
/****************************************************************************
 *
 * Function: PrintSLLHeader(FILE *)
 *
 * Purpose: Print the packet SLL (fake) header to the specified stream (piece
 * partly is borrowed from tcpdump :))
 *
 * Arguments: fp => file stream to print to
 *
 * Returns: void function
 *
 ***************************************************************************/
void PrintSLLHeader(FILE * fp, Packet * p)
{


    switch (ntohs(p->sllh->sll_pkttype)) {
        case LINUX_SLL_HOST:
            (void)fprintf(fp, "< ");
            break;
        case LINUX_SLL_BROADCAST:
            (void)fprintf(fp, "B ");
            break;
        case LINUX_SLL_MULTICAST:
            (void)fprintf(fp, "M ");
            break;
        case LINUX_SLL_OTHERHOST:
            (void)fprintf(fp, "P ");
            break;
        case LINUX_SLL_OUTGOING:
            (void)fprintf(fp, "> ");
            break;
        default:
            (void)fprintf(fp, "? ");
            break;
        }

    /* mac addr */
    fprintf(fp, "l/l len: %i l/l type: 0x%X %X:%X:%X:%X:%X:%X\n",
            htons(p->sllh->sll_halen), ntohs(p->sllh->sll_hatype),
            p->sllh->sll_addr[0], p->sllh->sll_addr[1], p->sllh->sll_addr[2],
            p->sllh->sll_addr[3], p->sllh->sll_addr[4], p->sllh->sll_addr[5]);

    /* protocol and pkt size */
    fprintf(fp, "pkt type:0x%X proto: 0x%X len:0x%X\n",
                 ntohs(p->sllh->sll_pkttype),
                 ntohs(p->sllh->sll_protocol), p->pkth->caplen);
}


void PrintArpHeader(FILE * fp, Packet * p)
{
#ifdef SUP_IP6
// XXX-IPv6 "NOT YET IMPLEMENTED - printing ARP header"
#else
    struct in_addr ip_addr;
    char timestamp[TIMEBUF_SIZE];
    const uint8_t *mac_src = NULL;
    const uint8_t *mac_dst = NULL;

    memset((struct in_addr *) &ip_addr, 0, sizeof(struct in_addr)); /* bzero() deprecated, replaced with memset() */
    memset((char *) timestamp, 0, TIMEBUF_SIZE); /* bzero() deprecated, replaced with memset() */
    ts_print((struct timeval *) & p->pkth->ts, timestamp);

    /* determine what to use as MAC src and dst */
    if (p->eh != NULL) 
    {
        mac_src = p->eh->ether_src;
        mac_dst = p->eh->ether_dst;
    } /* per table 4, 802.11 section 7.2.2 */
    else if (p->wifih != NULL && 
             (p->wifih->frame_control & WLAN_FLAG_FROMDS))
    {
        mac_src = p->wifih->addr3;
        mac_dst = p->wifih->addr2;
    }
    else if (p->wifih != NULL &&
             (p->wifih->frame_control & WLAN_FLAG_TODS))
    {
        mac_src = p->wifih->addr2;
        mac_dst = p->wifih->addr3;
    }
    else if (p->wifih != NULL)
    {
        mac_src = p->wifih->addr2;
        mac_dst = p->wifih->addr1;
    }

    /* 
     * if these are null this function will break, exit until 
     * someone writes a function for it...
     */
    if(mac_src == NULL || mac_dst == NULL)
    {
        return;
    }

    /* dump the timestamp */
    fwrite(timestamp, strlen(timestamp), 1, fp);

    if(ntohs(p->ah->ea_hdr.ar_pro) != ETHERNET_TYPE_IP)
    {
        fprintf(fp, "ARP #%d for protocol #%.4X (%d) hardware #%d (%d)\n",
                ntohs(p->ah->ea_hdr.ar_op), ntohs(p->ah->ea_hdr.ar_pro),
                p->ah->ea_hdr.ar_pln, ntohs(p->ah->ea_hdr.ar_hrd),
                p->ah->ea_hdr.ar_hln);

        return;
    }

    switch(ntohs(p->ah->ea_hdr.ar_op))
    {
        case ARPOP_REQUEST:
            bcopy((void *)p->ah->arp_tpa, (void *) &ip_addr, sizeof(ip_addr));
            fprintf(fp, "ARP who-has %s", inet_ntoa(ip_addr));

            if(memcmp((char *) ezero, (char *) p->ah->arp_tha, 6) != 0)
            {
                fprintf(fp, " (%X:%X:%X:%X:%X:%X)", p->ah->arp_tha[0],
                        p->ah->arp_tha[1], p->ah->arp_tha[2], p->ah->arp_tha[3],
                        p->ah->arp_tha[4], p->ah->arp_tha[5]);
            }
            bcopy((void *)p->ah->arp_spa, (void *) &ip_addr, sizeof(ip_addr));

            fprintf(fp, " tell %s", inet_ntoa(ip_addr));

            if(memcmp((char *) mac_src, (char *) p->ah->arp_sha, 6) != 0)
            {
                fprintf(fp, " (%X:%X:%X:%X:%X:%X)", p->ah->arp_sha[0],
                        p->ah->arp_sha[1], p->ah->arp_sha[2], p->ah->arp_sha[3],
                        p->ah->arp_sha[4], p->ah->arp_sha[5]);
            }
            break;

        case ARPOP_REPLY:
            bcopy((void *)p->ah->arp_spa, (void *) &ip_addr, sizeof(ip_addr));
            fprintf(fp, "ARP reply %s", inet_ntoa(ip_addr));

            /* print out the originating request if we're on a weirder
             * wireless protocol */            
            if(memcmp((char *) mac_src, (char *) p->ah->arp_sha, 6) != 0)
            {
                fprintf(fp, " (%X:%X:%X:%X:%X:%X)", mac_src[0],
                        mac_src[1], mac_src[2], mac_src[3],
                        mac_src[4], mac_src[5]);
            }
            fprintf(fp, " is-at %X:%X:%X:%X:%X:%X", p->ah->arp_sha[0],
                    p->ah->arp_sha[1], p->ah->arp_sha[2], p->ah->arp_sha[3],
                    p->ah->arp_sha[4], p->ah->arp_sha[5]);

            if(memcmp((char *) mac_dst, (char *) p->ah->arp_tha, 6) != 0)
            {
                fprintf(fp, " (%X:%X:%X:%X:%X:%X)", p->ah->arp_tha[0],
                        p->ah->arp_tha[1], p->ah->arp_tha[2], p->ah->arp_tha[3],
                        p->ah->arp_tha[4], p->ah->arp_tha[5]);
            }
            break;

        case ARPOP_RREQUEST:
            fprintf(fp, "RARP who-is %X:%X:%X:%X:%X:%X tell %X:%X:%X:%X:%X:%X",
                    p->ah->arp_tha[0], p->ah->arp_tha[1], p->ah->arp_tha[2],
                    p->ah->arp_tha[3], p->ah->arp_tha[4], p->ah->arp_tha[5],
                    p->ah->arp_sha[0], p->ah->arp_sha[1], p->ah->arp_sha[2],
                    p->ah->arp_sha[3], p->ah->arp_sha[4], p->ah->arp_sha[5]);

            break;

        case ARPOP_RREPLY:
            bcopy((void *)p->ah->arp_tpa, (void *) &ip_addr, sizeof(ip_addr));
            fprintf(fp, "RARP reply %X:%X:%X:%X:%X:%X at %s",
                    p->ah->arp_tha[0], p->ah->arp_tha[1], p->ah->arp_tha[2],
                    p->ah->arp_tha[3], p->ah->arp_tha[4], p->ah->arp_tha[5],
                    inet_ntoa(ip_addr));

            break;

        default:
            fprintf(fp, "Unknown operation: %d", ntohs(p->ah->ea_hdr.ar_op));
            break;
    }

    fprintf(fp, "\n\n");
#endif
}
#endif  // NO_NON_ETHER_DECODER


/****************************************************************************
 *
 * Function: PrintIPHeader(FILE *)
 *
 * Purpose: Dump the IP header info to the specified stream
 *
 * Arguments: fp => stream to print to
 *
 * Returns: void function
 *
 ***************************************************************************/
void PrintIPHeader(FILE * fp, Packet * p)
{
    if(!IPH_IS_VALID(p))
    {
        fprintf(fp, "IP header truncated\n");
        return;
    }

    if(p->frag_flag)
    {
        /* just print the straight IP header */
        fputs(inet_ntoa(GET_SRC_ADDR(p)), fp);
        fwrite(" -> ", 4, 1, fp);
        fputs(inet_ntoa(GET_DST_ADDR(p)), fp);
    }
    else
    {
        if(GET_IPH_PROTO(p) != IPPROTO_TCP && GET_IPH_PROTO(p) != IPPROTO_UDP)
        {
            /* just print the straight IP header */
            fputs(inet_ntoa(GET_SRC_ADDR(p)), fp);
            fwrite(" -> ", 4, 1, fp);
            fputs(inet_ntoa(GET_DST_ADDR(p)), fp);
        }
        else
        {
            if (!BcObfuscate())
            {
                /* print the header complete with port information */
                fputs(inet_ntoa(GET_SRC_ADDR(p)), fp);
                fprintf(fp, ":%d -> ", p->sp);
                fputs(inet_ntoa(GET_DST_ADDR(p)), fp);
                fprintf(fp, ":%d", p->dp);
            }
            else
            {
                /* print the header complete with port information */
                if(IS_IP4(p))
                    fprintf(fp, "xxx.xxx.xxx.xxx:%d -> xxx.xxx.xxx.xxx:%d", p->sp, p->dp);
                else if(IS_IP6(p))
                    fprintf(fp, "x:x:x:x::x:x:x:x:%d -> x:x:x:x:x:x:x:x:%d", p->sp, p->dp);
            }
        }
    }

    if (!BcOutputDataLink())
    {
        fputc('\n', fp);
    }
    else
    {
        fputc(' ', fp);
    }

    fprintf(fp, "%s TTL:%u TOS:0x%X ID:%u IpLen:%u DgmLen:%u",
            protocol_names[GET_IPH_PROTO(p)],
            GET_IPH_TTL(p),
            GET_IPH_TOS(p),
            IS_IP6(p) ? ntohl(GET_IPH_ID(p)) : ntohs((uint16_t)GET_IPH_ID(p)),
            GET_IPH_HLEN(p) << 2, 
            GET_IP_DGMLEN(p));

    /* print the reserved bit if it's set */
    if((uint8_t)((ntohs(GET_IPH_OFF(p)) & 0x8000) >> 15) == 1)
        fprintf(fp, " RB");

    /* printf more frags/don't frag bits */
    if((uint8_t)((ntohs(GET_IPH_OFF(p)) & 0x4000) >> 14) == 1)
        fprintf(fp, " DF");

    if((uint8_t)((ntohs(GET_IPH_OFF(p)) & 0x2000) >> 13) == 1)
        fprintf(fp, " MF");

    fputc('\n', fp);

    /* print IP options */
    if(p->ip_option_count != 0)
    {
        PrintIpOptions(fp, p);
    }

    /* print fragment info if necessary */
    if(p->frag_flag)
    {
        fprintf(fp, "Frag Offset: 0x%04X   Frag Size: 0x%04X\n",
                (p->frag_offset & 0x1FFF),
                GET_IP_PAYLEN(p));
    }
}



/****************************************************************************
 *
 * Function: PrintTCPHeader(FILE *)
 *
 * Purpose: Dump the TCP header info to the specified stream
 *
 * Arguments: fp => file stream to print data to
 *
 * Returns: void function
 *
 ***************************************************************************/
void PrintTCPHeader(FILE * fp, Packet * p)
{
    char tcpFlags[9];

    if(p->tcph == NULL)
    {
        fprintf(fp, "TCP header truncated\n");
        return;
    }
    /* print TCP flags */
    CreateTCPFlagString(p, tcpFlags);
    fwrite(tcpFlags, 8, 1, fp); /* We don't care about the NULL */

    /* print other TCP info */
    fprintf(fp, " Seq: 0x%lX  Ack: 0x%lX  Win: 0x%X  TcpLen: %d",
            (u_long) ntohl(p->tcph->th_seq),
            (u_long) ntohl(p->tcph->th_ack),
            ntohs(p->tcph->th_win), TCP_OFFSET(p->tcph) << 2);

    if((p->tcph->th_flags & TH_URG) != 0)
    {
        fprintf(fp, "  UrgPtr: 0x%X\n", (uint16_t) ntohs(p->tcph->th_urp));
    }
    else
    {
        fputc((int) '\n', fp);
    }

    /* dump the TCP options */
    if(p->tcp_option_count != 0)
    {
        PrintTcpOptions(fp, p);
    }
}

/* Input is packet and an nine-byte (including NULL) character array.  Results
 * are put into the character array.
 */
void CreateTCPFlagString(Packet * p, char *flagBuffer)
{
    /* parse TCP flags */
    *flagBuffer++ = (char) ((p->tcph->th_flags & TH_RES1) ? '1' : '*');
    *flagBuffer++ = (char) ((p->tcph->th_flags & TH_RES2) ? '2' : '*');
    *flagBuffer++ = (char) ((p->tcph->th_flags & TH_URG)  ? 'U' : '*');
    *flagBuffer++ = (char) ((p->tcph->th_flags & TH_ACK)  ? 'A' : '*');
    *flagBuffer++ = (char) ((p->tcph->th_flags & TH_PUSH) ? 'P' : '*');
    *flagBuffer++ = (char) ((p->tcph->th_flags & TH_RST)  ? 'R' : '*');
    *flagBuffer++ = (char) ((p->tcph->th_flags & TH_SYN)  ? 'S' : '*');
    *flagBuffer++ = (char) ((p->tcph->th_flags & TH_FIN)  ? 'F' : '*');
    *flagBuffer = '\0';

}


/****************************************************************************
 *
 * Function: PrintUDPHeader(FILE *)
 *
 * Purpose: Dump the UDP header to the specified file stream
 *
 * Arguments: fp => file stream
 *
 * Returns: void function
 *
 ***************************************************************************/
void PrintUDPHeader(FILE * fp, Packet * p)
{

    if(p->udph == NULL)
    {
        fprintf(fp, "UDP header truncated\n");
        return;
    }
    /* not much to do here... */
    fprintf(fp, "Len: %d\n", ntohs(p->udph->uh_len) - UDP_HEADER_LEN);
}



/****************************************************************************
 *
 * Function: PrintICMPHeader(FILE *)
 *
 * Purpose: Print ICMP header
 *
 * Arguments: fp => file stream
 *
 * Returns: void function
 *
 ***************************************************************************/
void PrintICMPHeader(FILE * fp, Packet * p)
{
#ifdef SUP_IP6
    /* 32 digits plus 7 colons and a NULL byte */
    char buf[8*4 + 7 + 1];
#endif

    if(p->icmph == NULL)
    {
        fprintf(fp, "ICMP header truncated\n");
        return;
    }

    fprintf(fp, "Type:%d  Code:%d  ", p->icmph->type, p->icmph->code);

    switch(p->icmph->type)
    {
        case ICMP_ECHOREPLY:
            fprintf(fp, "ID:%d  Seq:%d  ", ntohs(p->icmph->s_icmp_id), 
                    ntohs(p->icmph->s_icmp_seq));
            fwrite("ECHO REPLY", 10, 1, fp);
            break;

        case ICMP_DEST_UNREACH:
            fwrite("DESTINATION UNREACHABLE: ", 25, 1, fp);
            switch(p->icmph->code)
            {
                case ICMP_NET_UNREACH:
                    fwrite("NET UNREACHABLE", 15, 1, fp);
                    break;

                case ICMP_HOST_UNREACH:
                    fwrite("HOST UNREACHABLE", 16, 1, fp);
                    break;

                case ICMP_PROT_UNREACH:
                    fwrite("PROTOCOL UNREACHABLE", 20, 1, fp);
                    break;

                case ICMP_PORT_UNREACH:
                    fwrite("PORT UNREACHABLE", 16, 1, fp);
                    break;

                case ICMP_FRAG_NEEDED:
                    fprintf(fp, "FRAGMENTATION NEEDED, DF SET\n"
                            "NEXT LINK MTU: %u",
                            ntohs(p->icmph->s_icmp_nextmtu));
                    break;

                case ICMP_SR_FAILED:
                    fwrite("SOURCE ROUTE FAILED", 19, 1, fp);
                    break;

                case ICMP_NET_UNKNOWN:
                    fwrite("NET UNKNOWN", 11, 1, fp);
                    break;

                case ICMP_HOST_UNKNOWN:
                    fwrite("HOST UNKNOWN", 12, 1, fp);
                    break;

                case ICMP_HOST_ISOLATED:
                    fwrite("HOST ISOLATED", 13, 1, fp);
                    break;

                case ICMP_PKT_FILTERED_NET:
                    fwrite("ADMINISTRATIVELY PROHIBITED NETWORK FILTERED", 44, 
                            1, fp);
                    break;

                case ICMP_PKT_FILTERED_HOST:
                    fwrite("ADMINISTRATIVELY PROHIBITED HOST FILTERED", 41, 
                            1, fp);
                    break;

                case ICMP_NET_UNR_TOS:
                    fwrite("NET UNREACHABLE FOR TOS", 23, 1, fp);
                    break;

                case ICMP_HOST_UNR_TOS:
                    fwrite("HOST UNREACHABLE FOR TOS", 24, 1, fp);
                    break;

                case ICMP_PKT_FILTERED:
                    fwrite("ADMINISTRATIVELY PROHIBITED,\nPACKET FILTERED", 44,
                           1, fp);
                    break;

                case ICMP_PREC_VIOLATION:
                    fwrite("PREC VIOLATION", 14, 1, fp);
                    break;

                case ICMP_PREC_CUTOFF:
                    fwrite("PREC CUTOFF", 12, 1, fp);
                    break;

                default:
                    fwrite("UNKNOWN", 7, 1, fp);
                    break;

            }

            PrintICMPEmbeddedIP(fp, p);

            break;

        case ICMP_SOURCE_QUENCH:
            fwrite("SOURCE QUENCH", 13, 1, fp);

            PrintICMPEmbeddedIP(fp, p);

            break;

        case ICMP_REDIRECT:
            fwrite("REDIRECT", 8, 1, fp);
            switch(p->icmph->code)
            {
                case ICMP_REDIR_NET:
                    fwrite(" NET", 4, 1, fp);
                    break;

                case ICMP_REDIR_HOST:
                    fwrite(" HOST", 5, 1, fp);
                    break;

                case ICMP_REDIR_TOS_NET:
                    fwrite(" TOS NET", 8, 1, fp);
                    break;

                case ICMP_REDIR_TOS_HOST:
                    fwrite(" TOS HOST", 9, 1, fp);
                    break;
            }
             
#ifdef SUP_IP6
/* written this way since inet_ntoa was typedef'ed to use sfip_ntoa 
 * which requires sfip_t instead of inaddr's.  This call to inet_ntoa
 * is a rare case that doesn't use sfip_t's. */

// XXX-IPv6 NOT YET IMPLEMENTED - IPV6 addresses technically not supported - need to change ICMP header 
            
            sfip_raw_ntop(AF_INET, (void *)&p->icmph->s_icmp_gwaddr, buf, sizeof(buf));
            fprintf(fp, " NEW GW: %s", buf);
#else
            fprintf(fp, " NEW GW: %s", inet_ntoa(p->icmph->s_icmp_gwaddr));
#endif

            PrintICMPEmbeddedIP(fp, p);
                    
            break;

        case ICMP_ECHO:
            fprintf(fp, "ID:%d   Seq:%d  ", ntohs(p->icmph->s_icmp_id), 
                    ntohs(p->icmph->s_icmp_seq));
            fwrite("ECHO", 4, 1, fp);
            break;

        case ICMP_ROUTER_ADVERTISE:
            fprintf(fp, "ROUTER ADVERTISMENT: "
                    "Num addrs: %d Addr entry size: %d Lifetime: %u", 
                    p->icmph->s_icmp_num_addrs, p->icmph->s_icmp_wpa, 
                    ntohs(p->icmph->s_icmp_lifetime));
            break;

        case ICMP_ROUTER_SOLICIT:
            fwrite("ROUTER SOLICITATION", 19, 1, fp);
            break;

        case ICMP_TIME_EXCEEDED:
            fwrite("TTL EXCEEDED", 12, 1, fp);
            switch(p->icmph->code)
            {
                case ICMP_TIMEOUT_TRANSIT:
                    fwrite(" IN TRANSIT", 11, 1, fp);
                    break;

                case ICMP_TIMEOUT_REASSY:
                    fwrite(" TIME EXCEEDED IN FRAG REASSEMBLY", 33, 1, fp);
                    break;
            }

            PrintICMPEmbeddedIP(fp, p);

            break;

        case ICMP_PARAMETERPROB:
            fwrite("PARAMETER PROBLEM", 17, 1, fp);
            switch(p->icmph->code)
            {
                case ICMP_PARAM_BADIPHDR:
                    fprintf(fp, ": BAD IP HEADER BYTE %u",
                            p->icmph->s_icmp_pptr);
                    break;

                case ICMP_PARAM_OPTMISSING:
                    fwrite(": OPTION MISSING", 16, 1, fp);
                    break;

                case ICMP_PARAM_BAD_LENGTH:
                    fwrite(": BAD LENGTH", 12, 1, fp);
                    break;
            }

            PrintICMPEmbeddedIP(fp, p);

            break;

        case ICMP_TIMESTAMP:
            fprintf(fp, "ID: %u  Seq: %u  TIMESTAMP REQUEST", 
                    ntohs(p->icmph->s_icmp_id), ntohs(p->icmph->s_icmp_seq));
            break;

        case ICMP_TIMESTAMPREPLY:
            fprintf(fp, "ID: %u  Seq: %u  TIMESTAMP REPLY:\n"
                    "Orig: %u Rtime: %u  Ttime: %u", 
                    ntohs(p->icmph->s_icmp_id), ntohs(p->icmph->s_icmp_seq),
                    p->icmph->s_icmp_otime, p->icmph->s_icmp_rtime, 
                    p->icmph->s_icmp_ttime);
            break;

        case ICMP_INFO_REQUEST:
            fprintf(fp, "ID: %u  Seq: %u  INFO REQUEST", 
                    ntohs(p->icmph->s_icmp_id), ntohs(p->icmph->s_icmp_seq));
            break;

        case ICMP_INFO_REPLY:
            fprintf(fp, "ID: %u  Seq: %u  INFO REPLY", 
                    ntohs(p->icmph->s_icmp_id), ntohs(p->icmph->s_icmp_seq));
            break;

        case ICMP_ADDRESS:
            fprintf(fp, "ID: %u  Seq: %u  ADDRESS REQUEST", 
                    ntohs(p->icmph->s_icmp_id), ntohs(p->icmph->s_icmp_seq));
            break;

        case ICMP_ADDRESSREPLY:
            fprintf(fp, "ID: %u  Seq: %u  ADDRESS REPLY: 0x%08X", 
                    ntohs(p->icmph->s_icmp_id), ntohs(p->icmph->s_icmp_seq),
                    (u_int) ntohl(p->icmph->s_icmp_mask)); 
            break;

        default:
            fwrite("UNKNOWN", 7, 1, fp);

            break;
    }

    putc('\n', fp);

}

/****************************************************************************
 *
 * Function: PrintICMPEmbeddedIP(FILE *, Packet *)
 *
 * Purpose: Prints the original/encapsulated IP header + 64 bits of the
 *          original IP payload in an ICMP packet
 *
 * Arguments: fp => file stream
 *            p  => packet struct
 *
 * Returns: void function
 *
 ***************************************************************************/
void PrintICMPEmbeddedIP(FILE *fp, Packet *p)
{
    Packet op;
    Packet *orig_p;
    uint32_t orig_ip_hlen;

    if (fp == NULL || p == NULL)
        return;

    memset((char *) &op, 0, sizeof(Packet)); /* bzero() deprecated, replaced with memset() */
    orig_p = &op;

    orig_p->iph = p->orig_iph;
    orig_p->tcph = p->orig_tcph;
    orig_p->udph = p->orig_udph;
    orig_p->sp = p->orig_sp;
    orig_p->dp = p->orig_dp;
    orig_p->icmph = p->orig_icmph;
#ifdef SUP_IP6
    orig_p->iph_api = p->orig_iph_api;
    orig_p->ip4h = p->orig_ip4h;
    orig_p->ip6h = p->orig_ip6h;
    orig_p->family = p->orig_family;
#endif

    if(orig_p->iph != NULL)
    {
        fprintf(fp, "\n** ORIGINAL DATAGRAM DUMP:\n");
        PrintIPHeader(fp, orig_p);
        orig_ip_hlen = IP_HLEN(p->orig_iph) << 2;

        switch(GET_IPH_PROTO(orig_p))
        {
            case IPPROTO_TCP:
                if(orig_p->tcph != NULL)
                    fprintf(fp, "Seq: 0x%lX\n",
                            (u_long)ntohl(orig_p->tcph->th_seq));
                break;

            case IPPROTO_UDP:
                if(orig_p->udph != NULL)
                    fprintf(fp, "Len: %d  Csum: %d\n",
                            ntohs(orig_p->udph->uh_len) - UDP_HEADER_LEN,
                            ntohs(orig_p->udph->uh_chk));
                break;

            case IPPROTO_ICMP:
                if(orig_p->icmph != NULL)
                    PrintEmbeddedICMPHeader(fp, orig_p->icmph);
                break;

            default:
                fprintf(fp, "Protocol: 0x%X (unknown or "
                        "header truncated)", GET_IPH_PROTO(orig_p));
                break;
        }       /* switch */

        /* if more than 8 bytes of original IP payload sent */
        if (p->dsize - orig_ip_hlen > 8)
        {
            fprintf(fp, "(%d more bytes of original packet)\n",
                    p->dsize - orig_ip_hlen - 8);
        }

        fprintf(fp, "** END OF DUMP");
    }
    else
    {
        fprintf(fp, "\nORIGINAL DATAGRAM TRUNCATED");
    }
}

/****************************************************************************
 *
 * Function: PrintEmbeddedICMPHeader(FILE *, ICMPHdr *)
 *
 * Purpose: Prints the 64 bits of the original IP payload in an ICMP packet
 *          that requires it
 *
 * Arguments: fp => file stream
 *            icmph  => ICMPHdr struct pointing to original ICMP
 *
 * Returns: void function
 *
 ***************************************************************************/
void PrintEmbeddedICMPHeader(FILE *fp, const ICMPHdr *icmph)
{
    if (fp == NULL || icmph == NULL)
        return;

    fprintf(fp, "Type: %d  Code: %d  Csum: %u",
            icmph->type, icmph->code, ntohs(icmph->csum));

    switch (icmph->type)
    {
        case ICMP_DEST_UNREACH:
        case ICMP_TIME_EXCEEDED:
        case ICMP_SOURCE_QUENCH:
            break;

        case ICMP_PARAMETERPROB:
            if (icmph->code == 0)
                fprintf(fp, "  Ptr: %u", icmph->s_icmp_pptr);
            break;

        case ICMP_REDIRECT:
#ifdef SUP_IP6
// XXX-IPv6 "NOT YET IMPLEMENTED - ICMP printing"
#else
            fprintf(fp, "  New Gwy: %s", inet_ntoa(icmph->s_icmp_gwaddr));
#endif
            break;

        case ICMP_ECHO:
        case ICMP_ECHOREPLY:
        case ICMP_TIMESTAMP:
        case ICMP_TIMESTAMPREPLY:
        case ICMP_INFO_REQUEST:
        case ICMP_INFO_REPLY:
        case ICMP_ADDRESS:
        case ICMP_ADDRESSREPLY:
            fprintf(fp, "  Id: %u  SeqNo: %u", 
                    ntohs(icmph->s_icmp_id), ntohs(icmph->s_icmp_seq));
            break;

        case ICMP_ROUTER_ADVERTISE:
            fprintf(fp, "  Addrs: %u  Size: %u  Lifetime: %u",
                    icmph->s_icmp_num_addrs, icmph->s_icmp_wpa,
                    ntohs(icmph->s_icmp_lifetime));
            break;

        default:
            break;
    }

    fprintf(fp, "\n");

    return;
}

void PrintIpOptions(FILE * fp, Packet * p)
{
    int i;
    int j;
    u_long init_offset;
    u_long print_offset;

    init_offset = ftell(fp);

    if(!p->ip_option_count || p->ip_option_count > 40)
        return;

    fprintf(fp, "IP Options (%d) => ", p->ip_option_count);

    for(i = 0; i < (int) p->ip_option_count; i++)
    {
        print_offset = ftell(fp);

        if((print_offset - init_offset) > 60)
        {
            fwrite("\nIP Options => ", 15, 1, fp);
            init_offset = ftell(fp);
        }
            
        switch(p->ip_options[i].code)
        {
            case IPOPT_RR:
                fwrite("RR ", 3, 1, fp);
                break;

            case IPOPT_EOL:
                fwrite("EOL ", 4, 1, fp);
                break;

            case IPOPT_NOP:
                fwrite("NOP ", 4, 1, fp);
                break;

            case IPOPT_TS:
                fwrite("TS ", 3, 1, fp);
                break;

            case IPOPT_ESEC:
                fwrite("ESEC ", 5, 1, fp);
                break;

            case IPOPT_SECURITY:
                fwrite("SEC ", 4, 1, fp);
                break;

            case IPOPT_LSRR:
            case IPOPT_LSRR_E:
                fwrite("LSRR ", 5, 1, fp);
                break;

            case IPOPT_SATID:
                fwrite("SID ", 4, 1, fp);
                break;

            case IPOPT_SSRR:
                fwrite("SSRR ", 5, 1, fp);
                break;

            case IPOPT_RTRALT:
                fwrite("RTRALT ", 7, 1, fp);
                break;    

            default:
                fprintf(fp, "Opt %d: ", p->ip_options[i].code);

                if(p->ip_options[i].len)
                {
                    for(j = 0; j < p->ip_options[i].len; j++)
                    {
                        if (p->ip_options[i].data)
                            fprintf(fp, "%02X", p->ip_options[i].data[j]);
                        else
                            fprintf(fp, "%02X", 0);
                        
                        if((j % 2) == 0)
                            fprintf(fp, " ");
                    }
                }
                break;
        }
    }

    fwrite("\n", 1, 1, fp);
}


void PrintTcpOptions(FILE * fp, Packet * p)
{
    int i;
    int j;
    u_char tmp[5];
    u_long init_offset;
    u_long print_offset;

    init_offset = ftell(fp);

    fprintf(fp, "TCP Options (%d) => ", p->tcp_option_count);

    if(p->tcp_option_count > 40 || !p->tcp_option_count)
        return;

    for(i = 0; i < (int) p->tcp_option_count; i++)
    {
        print_offset = ftell(fp);

        if((print_offset - init_offset) > 60)
        {
            fwrite("\nTCP Options => ", 16, 1, fp);
            init_offset = ftell(fp);
        }
            
        switch(p->tcp_options[i].code)
        {
            case TCPOPT_MAXSEG:
		memset((char *) tmp, 0, 5); /* bzero() deprecated, replaced with memset() */
                fwrite("MSS: ", 5, 1, fp);
                if (p->tcp_options[i].data)
                    memcpy(tmp, p->tcp_options[i].data, 2);
                fprintf(fp, "%u ", EXTRACT_16BITS(tmp));
                break;

            case TCPOPT_EOL:
                fwrite("EOL ", 4, 1, fp);
                break;

            case TCPOPT_NOP:
                fwrite("NOP ", 4, 1, fp);
                break;

            case TCPOPT_WSCALE:
                if (p->tcp_options[i].data)
                    fprintf(fp, "WS: %u ", p->tcp_options[i].data[0]);
                else
                    fprintf(fp, "WS: %u ", 0);
                break;

            case TCPOPT_SACK:
		memset((char *) tmp, 0, 5); /* bzero() deprecated, replaced by memset() */
                if (p->tcp_options[i].data && (p->tcp_options[i].len >= 2))
                    memcpy(tmp, p->tcp_options[i].data, 2);
                fprintf(fp, "Sack: %u@", EXTRACT_16BITS(tmp));
		memset((char *) tmp, 0, 5); /* bzero() deprecated, replaced by memset() */
                if (p->tcp_options[i].data && (p->tcp_options[i].len >= 4))
                    memcpy(tmp, (p->tcp_options[i].data) + 2, 2);
                fprintf(fp, "%u ", EXTRACT_16BITS(tmp));
                break;

            case TCPOPT_SACKOK:
                fwrite("SackOK ", 7, 1, fp);
                break;

            case TCPOPT_ECHO:
		memset((char *) tmp, 0, 5); /* bzero() deprecated, replaced by memset() */
                if (p->tcp_options[i].data)
                    memcpy(tmp, p->tcp_options[i].data, 4);
                fprintf(fp, "Echo: %u ", EXTRACT_32BITS(tmp));
                break;

            case TCPOPT_ECHOREPLY:
		memset((char *) tmp, 0, 5); /* bzero() deprecated, replaced by memset() */
                if (p->tcp_options[i].data)
                    memcpy(tmp, p->tcp_options[i].data, 4);
                fprintf(fp, "Echo Rep: %u ", EXTRACT_32BITS(tmp));
                break;

            case TCPOPT_TIMESTAMP:
		memset((char *) tmp, 0, 5); /* bzero() deprecated, replaced by memset() */
                if (p->tcp_options[i].data)
                    memcpy(tmp, p->tcp_options[i].data, 4);
                fprintf(fp, "TS: %u ", EXTRACT_32BITS(tmp));
		memset((char *) tmp, 0, 5); /* bzero() deprecated, replaced by memset() */
                if (p->tcp_options[i].data)
                    memcpy(tmp, (p->tcp_options[i].data) + 4, 4);
                fprintf(fp, "%u ", EXTRACT_32BITS(tmp));
                break;

            case TCPOPT_CC:
		memset((char *) tmp, 0, 5); /* bzero() deprecated, replaced by memset() */
                if (p->tcp_options[i].data)
                    memcpy(tmp, p->tcp_options[i].data, 4);
                fprintf(fp, "CC %u ", EXTRACT_32BITS(tmp));
                break;

            case TCPOPT_CCNEW:
		memset((char *) tmp, 0, 5); /* bzero() deprecated, replaced by memset() */
                if (p->tcp_options[i].data)
                    memcpy(tmp, p->tcp_options[i].data, 4);
                fprintf(fp, "CCNEW: %u ", EXTRACT_32BITS(tmp));
                break;

            case TCPOPT_CCECHO:
		memset((char *) tmp, 0, 5); /* bzero() deprecated, replaced by memset() */
                if (p->tcp_options[i].data)
                    memcpy(tmp, p->tcp_options[i].data, 4);
                fprintf(fp, "CCECHO: %u ", EXTRACT_32BITS(tmp));
                break;

            default:
                if(p->tcp_options[i].len)
                {
                    fprintf(fp, "Opt %d (%d): ", p->tcp_options[i].code,
                            (int) p->tcp_options[i].len);

                    for(j = 0; j < p->tcp_options[i].len; j++)
                    {
                        if (p->tcp_options[i].data)
                            fprintf(fp, "%02X", p->tcp_options[i].data[j]);
                        else
                            fprintf(fp, "%02X", 0);
                        
                        if ((j + 1) % 2 == 0)
                            fprintf(fp, " ");
                    }

                    fprintf(fp, " ");
                }
                else
                {
                    fprintf(fp, "Opt %d ", p->tcp_options[i].code);
                }
                break;
        }
    }

    fwrite("\n", 1, 1, fp);
}

#ifndef NO_NON_ETHER_DECODER
/*
 * Function: PrintEapolPkt(FILE *, Packet *)
 *
 * Purpose: Dump the packet to the stream pointer
 *
 * Arguments: fp => pointer to print data to
 *            type => packet protocol
 *            p => pointer to decoded packet struct
 *
 * Returns: void function
 */
void PrintEapolPkt(FILE * fp, Packet * p)
{
  char timestamp[TIMEBUF_SIZE];
  

    memset((char *) timestamp, 0, TIMEBUF_SIZE); /* bzero() deprecated, replaced by memset() */
    ts_print((struct timeval *) & p->pkth->ts, timestamp);

    /* dump the timestamp */
    fwrite(timestamp, strlen(timestamp), 1, fp);

    /* dump the ethernet header if we're doing that sort of thing */
    if (BcOutputDataLink())
    {
        Print2ndHeader(fp, p);
    }
    PrintEapolHeader(fp, p);
    if (p->eplh->eaptype == EAPOL_TYPE_EAP) {
      PrintEAPHeader(fp, p);
    }
    else if (p->eplh->eaptype == EAPOL_TYPE_KEY) {
      PrintEapolKey(fp, p);
    }

    /* dump the application layer data */
    if(BcOutputAppData() && !BcVerboseByteDump())
    {
        if (BcOutputCharData())
            PrintCharData(fp, (char*) p->data, p->dsize);
        else
            PrintNetData(fp, p->data, p->dsize);
    }
    else if (BcVerboseByteDump())
    {
        PrintNetData(fp, p->pkt, p->pkth->caplen);
    }
    
    fprintf(fp, "=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n\n");    
}

/****************************************************************************
 *
 * Function: PrintWifiHeader(FILE *)
 *
 * Purpose: Print the packet 802.11 header to the specified stream
 *
 * Arguments: fp => file stream to print to
 *
 * Returns: void function
 *
 ***************************************************************************/
void PrintWifiHeader(FILE * fp, Packet * p)
{
  /* This assumes we are printing a data packet, could be changed
     to print other types as well */
  const u_char *da = NULL, *sa = NULL, *bssid = NULL, *ra = NULL,
    *ta = NULL;
  /* per table 4, IEEE802.11 section 7.2.2 */
  if ((p->wifih->frame_control & WLAN_FLAG_TODS) &&
      (p->wifih->frame_control & WLAN_FLAG_FROMDS)) {
    ra = p->wifih->addr1;
    ta = p->wifih->addr2;
    da = p->wifih->addr3;
    sa = p->wifih->addr4;
  }
  else if (p->wifih->frame_control & WLAN_FLAG_TODS) {
    bssid = p->wifih->addr1;
    sa = p->wifih->addr2;
    da = p->wifih->addr3;
  }
  else if (p->wifih->frame_control & WLAN_FLAG_FROMDS) {
    da = p->wifih->addr1;
    bssid = p->wifih->addr2;
    sa = p->wifih->addr3;
  }
  else {
    da = p->wifih->addr1;
    sa = p->wifih->addr2;
    bssid = p->wifih->addr3;
  }
  
  /* DO this switch to provide additional info on the type */
  switch(p->wifih->frame_control & 0x00ff)
  {
  case WLAN_TYPE_MGMT_BEACON:
    fprintf(fp, "Beacon ");
    break;
    /* management frames */
  case WLAN_TYPE_MGMT_ASREQ:
    fprintf(fp, "Assoc. Req. ");
    break;
  case WLAN_TYPE_MGMT_ASRES:
    fprintf(fp, "Assoc. Resp. ");
    break;
  case WLAN_TYPE_MGMT_REREQ:
    fprintf(fp, "Reassoc. Req. ");
    break;
  case WLAN_TYPE_MGMT_RERES:
    fprintf(fp, "Reassoc. Resp. ");
    break;
  case WLAN_TYPE_MGMT_PRREQ:
    fprintf(fp, "Probe Req. ");
    break;
  case WLAN_TYPE_MGMT_PRRES:
    fprintf(fp, "Probe Resp. ");
    break;
  case WLAN_TYPE_MGMT_ATIM:
    fprintf(fp, "ATIM ");
    break;
  case WLAN_TYPE_MGMT_DIS:
    fprintf(fp, "Dissassoc. ");
    break;
  case WLAN_TYPE_MGMT_AUTH:
    fprintf(fp, "Authent. ");
    break;
  case WLAN_TYPE_MGMT_DEAUTH:
    fprintf(fp, "Deauthent. ");
    break;
    
    /* Control frames */
  case WLAN_TYPE_CONT_PS:
  case WLAN_TYPE_CONT_RTS:
  case WLAN_TYPE_CONT_CTS:
  case WLAN_TYPE_CONT_ACK:
  case WLAN_TYPE_CONT_CFE:
  case WLAN_TYPE_CONT_CFACK:
    fprintf(fp, "Control ");
    break;
  }  
  
  if (sa != NULL) {
    fprintf(fp, "%X:%X:%X:%X:%X:%X -> ", sa[0],
        sa[1], sa[2], sa[3], sa[4], sa[5]);
  }
  else if (ta != NULL) {
    fprintf(fp, "ta: %X:%X:%X:%X:%X:%X da: ", ta[0],
        ta[1], ta[2], ta[3], ta[4], ta[5]);
  } 
  
  fprintf(fp, "%X:%X:%X:%X:%X:%X\n", da[0],
      da[1], da[2], da[3], da[4], da[5]);

  if (bssid != NULL)
  {
      fprintf(fp, "bssid: %X:%X:%X:%X:%X:%X", bssid[0],
              bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
  }
  
  if (ra != NULL) {
    fprintf(fp, " ra: %X:%X:%X:%X:%X:%X", ra[0],
        ra[1], ra[2], ra[3], ra[4], ra[5]);
  }
  fprintf(fp, " Flags:");
  if (p->wifih->frame_control & WLAN_FLAG_TODS)    fprintf(fp," ToDs");
  if (p->wifih->frame_control & WLAN_FLAG_TODS)    fprintf(fp," FrDs");
  if (p->wifih->frame_control & WLAN_FLAG_FRAG)    fprintf(fp," Frag");
  if (p->wifih->frame_control & WLAN_FLAG_RETRY)   fprintf(fp," Re");
  if (p->wifih->frame_control & WLAN_FLAG_PWRMGMT) fprintf(fp," Pwr");
  if (p->wifih->frame_control & WLAN_FLAG_MOREDAT) fprintf(fp," MD");
  if (p->wifih->frame_control & WLAN_FLAG_WEP)   fprintf(fp," Wep");
  if (p->wifih->frame_control & WLAN_FLAG_ORDER)  fprintf(fp," Ord");
  fprintf(fp, "\n");
}

/*
 * Function: PrintWifiPkt(FILE *, Packet *)
 *
 * Purpose: Dump the packet to the stream pointer
 *
 * Arguments: fp => pointer to print data to
 *            p => pointer to decoded packet struct
 *
 * Returns: void function
 */
void PrintWifiPkt(FILE * fp, Packet * p)
{
    char timestamp[TIMEBUF_SIZE];


    memset((char *) timestamp, 0, TIMEBUF_SIZE); /* bzero() deprecated, replaced by memset() */
    ts_print((struct timeval *) & p->pkth->ts, timestamp);

    /* dump the timestamp */
    fwrite(timestamp, strlen(timestamp), 1, fp);

    /* dump the ethernet header if we're doing that sort of thing */
    Print2ndHeader(fp, p);

    /* dump the application layer data */
    if (BcOutputAppData() && !BcVerboseByteDump())
    {
        if (BcOutputCharData())
            PrintCharData(fp, (char*) p->data, p->dsize);
        else
            PrintNetData(fp, p->data, p->dsize);
    }
    else if (BcVerboseByteDump())
    {
        PrintNetData(fp, p->pkt, p->pkth->caplen);
    }

    fprintf(fp, "=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+"
            "=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n\n");
}

/****************************************************************************
 *
 * Function: PrintEapolHeader(FILE *, Packet *)
 *
 * Purpose: Dump the EAPOL header info to the specified stream
 *
 * Arguments: fp => stream to print to
 *
 * Returns: void function
 *
 ***************************************************************************/
void PrintEapolHeader(FILE * fp, Packet * p)
{
    fprintf(fp, "EAPOL type: ");
    switch(p->eplh->eaptype) {
    case EAPOL_TYPE_EAP:
      fprintf(fp, "EAP");
      break;
    case EAPOL_TYPE_START:
      fprintf(fp, "Start");
      break;
    case EAPOL_TYPE_LOGOFF:
      fprintf(fp, "Logoff");
      break;
    case EAPOL_TYPE_KEY:
      fprintf(fp, "Key");
      break;
    case EAPOL_TYPE_ASF:
      fprintf(fp, "ASF Alert");
      break;
    default:
      fprintf(fp, "Unknown");
    }
    fprintf(fp, " Len: %d\n", ntohs(p->eplh->len));
}

/****************************************************************************
 *
 * Function: PrintEAPHeader(FILE *)
 *
 * Purpose: Dump the EAP header to the specified file stream
 *
 * Arguments: fp => file stream
 *
 * Returns: void function
 *
 ***************************************************************************/
void PrintEAPHeader(FILE * fp, Packet * p)
{

    if(p->eaph == NULL)
    {
        fprintf(fp, "EAP header truncated\n");
        return;
    }
    fprintf(fp, "code: ");
    switch(p->eaph->code) {
    case EAP_CODE_REQUEST:
      fprintf(fp, "Req ");
      break;
    case EAP_CODE_RESPONSE:
      fprintf(fp, "Resp");
      break;
    case EAP_CODE_SUCCESS:
      fprintf(fp, "Succ");
      break;
    case EAP_CODE_FAILURE:
      fprintf(fp, "Fail");
      break;
    }
    fprintf(fp, " id: 0x%x len: %d", p->eaph->id, ntohs(p->eaph->len));
    if (p->eaptype != NULL) {
      fprintf(fp, " type: ");
      switch(*(p->eaptype)) {
      case EAP_TYPE_IDENTITY:
    fprintf(fp, "id");
    break;
      case EAP_TYPE_NOTIFY:
    fprintf(fp, "notify");
    break;
      case EAP_TYPE_NAK:
    fprintf(fp, "nak");
    break;
      case EAP_TYPE_MD5:
    fprintf(fp, "md5");
    break;
      case EAP_TYPE_OTP:
    fprintf(fp, "otp");
    break;
      case EAP_TYPE_GTC:
    fprintf(fp, "token");
    break;
      case EAP_TYPE_TLS:
    fprintf(fp, "tls");
    break;
      default:
    fprintf(fp, "undef");
    break;
      }
    }
    fprintf(fp, "\n");
}


/****************************************************************************
 *
 * Function: PrintEapolKey(FILE *)
 *
 * Purpose: Dump the EAP header to the specified file stream
 *
 * Arguments: fp => file stream
 *
 * Returns: void function
 *
 ***************************************************************************/
void PrintEapolKey(FILE * fp, Packet * p)
{
    uint16_t length;
    
    if(p->eapolk == NULL)
    {
        fprintf(fp, "Eapol Key truncated\n");
        return;
    }
    fprintf(fp, "KEY type: ");
    if (p->eapolk->type == 1) {
      fprintf(fp, "RC4");
    }

    memcpy(&length, &p->eapolk->length, 2);
    length = ntohs(length);
    fprintf(fp, " len: %d", length);
    fprintf(fp, " index: %d ", p->eapolk->index & 0x7F);
    fprintf(fp, p->eapolk->index & 0x80 ? " unicast\n" : " broadcast\n");
    

}
#endif  // NO_NON_ETHER_DECODER

