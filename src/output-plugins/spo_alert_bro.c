/*
** Copyright (C) 2010 Seth Hall <seth@icir.org>
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

/* spo_alert_Bro 
 *
 * This module sends alerts to the Bro-IDS as Bro events using the Bro
 * communications protocol.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef BROCCOLI

#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "broccoli.h"

#include "barnyard2.h"
#include "decode.h"
#include "debug.h"
#include "map.h"
#include "mstring.h"
#include "parser.h"
#include "strlcatu.h"
#include "strlcpyu.h"
#include "plugbase.h"
#include "unified2.h"
#include "util.h"
#include "ipv6_port.h"

extern OptTreeNode *otn_tmp;

void AlertBroSetup(void);
void AlertBroInit(char *);
void AlertBro(Packet *, void *, u_int32_t, void *);
void AlertBroCleanExit(int, void *);
void AlertBroRestart(int, void *);

static BroConn *bro_conn;

/*
 * Function: AlertBroSetup()
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
void AlertBroSetup(void)
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterOutputPlugin("alert_bro", OUTPUT_TYPE_FLAG__ALERT, AlertBroInit);
    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Output plugin: Alert-Bro is setup...\n"););
}


/*
 * Function: AlertBroInit(char *)
 *
 * Purpose: Makes the connection to Bro, links the preproc function 
 *          into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
void AlertBroInit(char *args)
{
    char *host_string = args;
    
    bro_init(NULL);
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output: Alert-Bro Initialized\n"););

    if ( !(bro_conn = bro_conn_new_str(host_string,
                            BRO_CFLAG_RECONNECT | BRO_CFLAG_ALWAYS_QUEUE )) )
    {
        FatalError("Could not get Bro connection handle.\n", host_string);
    }
    bro_conn_set_class(bro_conn, "barnyard");
    LogMessage("alert_bro Connecting to Bro (%s)...", host_string);
    if ( !bro_conn_connect(bro_conn) )
    {
        FatalError("failed!\nCould not connect to Bro!\n");
    }
    LogMessage("done.\n");

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Linking Bro alert function to call list...\n"););
    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(AlertBro, OUTPUT_TYPE__ALERT, 0);
    AddFuncToCleanExitList(AlertBroCleanExit, 0);
    AddFuncToRestartList(AlertBroRestart, 0);
}

#ifdef SUP_IP6
static INLINE void map_broccoli_addr(BroAddr* a, const snort_ip_p i)
{
    if ( i->family == AF_INET )
    {
        memcpy(a->addr, BRO_IPV4_MAPPED_PREFIX, sizeof(BRO_IPV4_MAPPED_PREFIX));
        memcpy(&a->addr[3], i->ip.u6_addr32, sizeof(uint32_t));
    }
    else if ( i->family == AF_INET6 )
        memcpy(a->addr, &i->ip, sizeof(a->addr));
}
#else
static INLINE void map_broccoli_addr(BroAddr* a, const struct in_addr i)
{
    memcpy(a->addr, BRO_IPV4_MAPPED_PREFIX, sizeof(BRO_IPV4_MAPPED_PREFIX));
    memcpy(&a->addr[3], &i, sizeof(uint32_t));
}
#endif

/*
 * Function: AlertBro(Packet *)
 *
 * Arguments: p => pointer to the current packet data struct 
 *
 * Returns: void function
 *
 */
void AlertBro(Packet *p, void *event, u_int32_t event_type, void *arg)
{
    BroEvent      *ev;
    SigNode       *sn;
    ClassType     *cn;
    ReferenceNode *rn;
	
    Unified2EventCommon *uevent = (Unified2EventCommon *) event; 
    BroPort src_p;
    BroPort dst_p;
    BroAddr src_addr;
    BroAddr dst_addr;

    if ( p == NULL || event == NULL )
    {
        return;
    }

    sn = GetSigByGidSid(ntohl(uevent->generator_id),
                        ntohl(uevent->signature_id),
	                ntohl(uevent->signature_revision));
    
    if(p && IPH_IS_VALID(p))
    {
        ev = bro_event_new("Barnyard2::barnyard_alert");
        
        // First value
        BroRecord *packet_id = bro_record_new();
        src_p.port_num = dst_p.port_num = 0;
        // Broccoli's protocol handling is sort of broken at the moment
        // it segfaults when doing bro_record_add_val if not tcp, udp, or icmp
        // waiting on ticket: http://tracker.icir.org/bro/ticket/278
        src_p.port_proto = dst_p.port_proto = IPPROTO_TCP;
        if(GET_IPH_PROTO(p) != 255)
        {
            src_p.port_proto = dst_p.port_proto = GET_IPH_PROTO(p);
            if((GET_IPH_PROTO(p) == IPPROTO_ICMP) && p->icmph)
            {
                src_p.port_num = p->icmph->type;
                dst_p.port_num = p->icmph->code;
            } else {
                src_p.port_num = p->sp;
                dst_p.port_num = p->dp;
            }
        }

        map_broccoli_addr(&src_addr, GET_SRC_ADDR(p));
        bro_record_add_val(packet_id, "src_ip", BRO_TYPE_IPADDR, NULL, &src_addr);
        bro_record_add_val(packet_id, "src_p",  BRO_TYPE_PORT,   NULL, &src_p);
        map_broccoli_addr(&dst_addr, GET_DST_ADDR(p));
        bro_record_add_val(packet_id, "dst_ip", BRO_TYPE_IPADDR, NULL, &dst_addr);
        bro_record_add_val(packet_id, "dst_p",  BRO_TYPE_PORT,   NULL, &dst_p);
        bro_event_add_val(ev, BRO_TYPE_RECORD, "Barnyard2::PacketID", packet_id);
        bro_record_free(packet_id);
        
        // Second value
        BroRecord *sad = bro_record_new();
        uint64_t sensor_id_hl = ntohl(uevent->sensor_id);
        bro_record_add_val(sad, "sensor_id",          BRO_TYPE_COUNT, NULL, &sensor_id_hl);
        double ts = (double) ntohl(uevent->event_second) + (((double) ntohl(uevent->event_microsecond))/1000000);
        bro_record_add_val(sad, "ts",                 BRO_TYPE_TIME,  NULL, &ts);
        uint64_t signature_id_hl = ntohl(uevent->signature_id);
        bro_record_add_val(sad, "signature_id",       BRO_TYPE_COUNT, NULL, &signature_id_hl);
        uint64_t generator_id_hl = ntohl(uevent->generator_id);
        bro_record_add_val(sad, "generator_id",       BRO_TYPE_COUNT, NULL, &generator_id_hl);
        uint64_t signature_revision_hl = ntohl(uevent->signature_revision);
        bro_record_add_val(sad, "signature_revision", BRO_TYPE_COUNT, NULL, &signature_revision_hl);
        uint64_t classification_id_hl = ntohl(uevent->classification_id);
        bro_record_add_val(sad, "classification_id",  BRO_TYPE_COUNT, NULL, &classification_id_hl);
        BroString class_bs;
        cn = ClassTypeLookupById(barnyard2_conf, ntohl(uevent->classification_id));
        bro_string_init(&class_bs);
        if ( cn )
            bro_string_set(&class_bs, cn->name);
        bro_record_add_val(sad, "classification",     BRO_TYPE_STRING, NULL, &class_bs);
        bro_string_cleanup(&class_bs);
        uint64_t priority_id_hl = ntohl(uevent->priority_id);
        bro_record_add_val(sad, "priority_id",        BRO_TYPE_COUNT, NULL, &priority_id_hl);
        uint64_t event_id_hl = ntohl(uevent->event_id);
        bro_record_add_val(sad, "event_id",           BRO_TYPE_COUNT, NULL, &event_id_hl);
        //BroSet *ref_set = bro_set_new();
        //BroString ref_name_bs;
        //rn = sn->refs;
        //while(rn)
        //{
        //    bro_string_init(&ref_name_bs);
        //    bro_string_set(&ref_name_bs, rn->system->name);
        //    bro_set_insert(ref_set, BRO_TYPE_STRING, &ref_name_bs);
        //    bro_string_cleanup(&ref_name_bs);
        //    rn = rn->next;
        //}
        //bro_record_add_val(sad, "references", BRO_TYPE_SET, NULL, ref_set);
        //bro_set_free(ref_set);
        
        bro_event_add_val(ev, BRO_TYPE_RECORD, "Barnyard2::AlertData", sad);
        bro_record_free(sad);
        
        // Third value
        BroString msg_bs;
        bro_string_init(&msg_bs);
        bro_string_set(&msg_bs, sn->msg);
        bro_event_add_val(ev, BRO_TYPE_STRING, NULL, &msg_bs);
        bro_string_cleanup(&msg_bs);
        
        // Fourth value
        BroString contents_bs;
        bro_string_init(&contents_bs);
        bro_string_set_data(&contents_bs, (uchar *) p->data, p->dsize);
        bro_event_add_val(ev, BRO_TYPE_STRING, NULL, &contents_bs);
        bro_string_cleanup(&contents_bs);
        
        // send and free the event
        bro_event_send(bro_conn, ev);
        bro_event_free(ev);
    }
    else
    {
        // Not bothering with alerts using faked or undecodeable packets.
        LogMessage("WARNING (Bro) faked or undecodeable packet: %s\n", sn->msg);
    }
    
}

void AlertBroCleanExit(int signal, void *arg)
{
    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "AlertBroCleanExit\n"););
    int remaining=0;
    while (bro_event_queue_length(bro_conn) > 0)
        {
        remaining = bro_event_queue_flush(bro_conn);
        LogMessage("(Bro) %d events left to flush.\n", remaining);
        }
    bro_conn_delete(bro_conn);
}

void AlertBroRestart(int signal, void *arg)
{
    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "AlertBroRestartFunc\n"););
    int remaining=0;
    while (bro_event_queue_length(bro_conn) > 0)
        {
        remaining = bro_event_queue_flush(bro_conn);
        LogMessage("(Bro) %d events left to flush.\n", remaining);
        }
    if(!bro_conn_reconnect(bro_conn))
        FatalError("Could not connect to Bro!\n");
}

#endif /* BROCCOLI */
