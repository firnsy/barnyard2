/*
** Copyright (C) 2008-2013 Ian Firns (SecurixLive) <dev@securixlive.com>
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
** INCLUDES
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef ENABLE_PLUGIN_ECHIDNA

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <libwebsockets.h>
#include <curl/curl.h>
#include <json/json.h>
#include <json/json_tokener.h>
#include <openssl/sha.h>

#include "barnyard2.h"
#include "debug.h"
#include "decode.h"
#include "map.h"
#include "mstring.h"
#include "plugbase.h"
#include "strlcpyu.h"
#include "unified2.h"
#include "util.h"


typedef struct _SpoEchidnaData
{
    char *agent_name;
    u_int16_t sensor_id;
    int agent_sock;

    u_int32_t event_id;

    char *args;

    char *node_address;
    u_int16_t node_port;

    int use_ssl;



    CURL *curl;
} SpoEchidnaData;

static int session_state = 0;
struct libwebsocket_context *context;
static struct libwebsocket *wsi_echidna;

static char *node_id;
static char *session_key;
static char *session_uri;


enum echidna_protocols {
  PROTOCOL_LWS_ECHIDNA,
};

/* constants */
#define KEYWORD_NODEADDRESS   "address"
#define KEYWORD_NODEPORT      "port"
#define KEYWORD_NODENAME      "name"
#define KEYWORD_USESSL        "ssl"

#define DEFAULT_NODEADDRESS   "127.0.0.1"
#define DEFAULT_NODEPORT      6968

#define MAX_MSG_LEN       2048
#define TMP_BUFFER        128

/* output plug-in API functions */
void EchidnaInit(char *args);
void EchidnaInitFinalize(int unused, void *arg);

SpoEchidnaData *InitEchidnaData(char *);
void ParseEchidnaArgs(SpoEchidnaData *spd_data);

void EchidnaCleanExitFunc(int, void *);
void EchidnaRestartFunc(int, void *);


/* internal echidna functions */
void Echidna(Packet *, void *, u_int32_t, void *);

int EchidnaNodeConnect(SpoEchidnaData *);

char *EchidnaTimestamp(u_int32_t, u_int32_t);

int EchidnaEventIPHeaderDataAppend(json_object *, Packet *);
int EchidnaEventICMPDataAppend(json_object *, Packet *);
int EchidnaEventTCPDataAppend(json_object *, Packet *);
int EchidnaEventUDPDataAppend(json_object *, Packet *);

void EchidnaEventSubmit(SpoEchidnaData *, json_object *);



static int
callback_lws_mirror(struct libwebsocket_context *this, struct libwebsocket *wsi, enum libwebsocket_callback_reasons reason, void *user, void *in, size_t len)
{
    unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + 4096 + LWS_SEND_BUFFER_POST_PADDING];
    int l;
    json_object *json;
    char *key;
    json_object *val;
    struct lh_entry *entry;
    enum json_type type;


    switch (reason) {

      case LWS_CALLBACK_CLOSED:
          //fprintf(stderr, "echidna: LWS_CALLBACK_CLOSED\n");
          wsi_echidna = NULL;

          /* session key is invalidated */
          if( session_key != NULL )
            free(session_key);

          session_state = 0;

          break;

      case LWS_CALLBACK_CLIENT_ESTABLISHED:
          /*
           * start the ball rolling,
           * LWS_CALLBACK_CLIENT_WRITEABLE will come next service
           */
          //fprintf(stderr, "Connection established ...\n");

          libwebsocket_callback_on_writable(this, wsi);
          break;

      case LWS_CALLBACK_CLIENT_RECEIVE:
          //fprintf(stderr, "rx %d '%s'\n", (int)len, (char *)in);


          json = json_tokener_parse( in );

          /* decode the message */

          if( session_state == 0 )
          {
              for(entry = json_object_get_object(json)->head; ({ if(entry) { key = (char*)entry->k; val = (struct json_object*)entry->v; } ; entry; }); entry = entry->next )
              {
                  type = json_object_get_type(val);
                  if( strncmp( key, "node_id", 7 ) == 0 && ( type == json_type_string ) )
                  {
                      /* cleanup previous value */
                      if( node_id != NULL )
                        free(node_id);

                      node_id = SnortStrdup( json_object_get_string(val) );

                      DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "NODE ID: %s\n", node_id););
                  }
                  else if( strncmp( key, "session_key", 11 ) == 0 && ( type == json_type_string ) )
                  {
                      /* cleanup previous value */
                      if( session_key != NULL )
                        free(session_key);

                      session_key = SnortStrdup( json_object_get_string(val) );
                      DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "SESSION KEY: %s\n", session_key););
                  }
                  else if( strncmp( key, "session_uri", 11 ) == 0 && ( type == json_type_string ) )
                  {
                      /* cleanup previous value */
                      if( session_uri != NULL )
                        free(session_uri);

                      session_uri = SnortStrdup( json_object_get_string(val) );
                      DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "SESSION URI: %s\n", session_uri););
                  }
              }

              /* determine if a session is active */
              if( ( node_id != NULL ) &&
                  ( session_key != NULL ) &&
                  ( session_uri != NULL ) )
              {
                  session_state = 1;
              }
          }

          json_object_put(json);

          break;

      case LWS_CALLBACK_CLIENT_WRITEABLE:
          if( session_state == 0 )
          {
            /* send our auth request */
            l = sprintf((char *)&buf[LWS_SEND_BUFFER_PRE_PADDING], "{\"type\":\"by2_auth_request\",\"key\":\"password\"}");
            libwebsocket_write(wsi, &buf[LWS_SEND_BUFFER_PRE_PADDING], l, LWS_WRITE_TEXT);
          }

          /* get notified as soon as we can write again */
          libwebsocket_callback_on_writable(this, wsi);

          usleep(200);
          break;

      case LWS_CALLBACK_ESTABLISHED:
        //fprintf(stderr, " LWS_CALLBACK_ESTABLISHED\n");
        break;
      case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
        //fprintf(stderr, " LWS_CALLBACK_CLIENT_CONNECTION_ERROR\n");
        break;
      case LWS_CALLBACK_RECEIVE:
        //fprintf(stderr, " LWS_CALLBACK_RECEIVE\n");
        break;
      case LWS_CALLBACK_CLIENT_RECEIVE_PONG:
        //fprintf(stderr, " LWS_CALLBACK_CLIENT_RECEIVE_PONG\n");
        break;
      case LWS_CALLBACK_SERVER_WRITEABLE:
        //fprintf(stderr, " LWS_CALLBACK_SERVER_WRITEABLE\n");
        break;
      case LWS_CALLBACK_HTTP:
        //fprintf(stderr, " LWS_CALLBACK_HTTP\n");
        break;
      case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
        //fprintf(stderr, " LWS_CALLBACK_FILTER_NETWORK_CONNECTION\n");
        break;
      case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
        //fprintf(stderr, " LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION\n");
        break;
      case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS:
        //fprintf(stderr, " LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS\n");
        break;
      case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS:
        //fprintf(stderr, " LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS\n");
        break;
      case LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION:
        //fprintf(stderr, " LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION\n");
        break;
      case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
        //fprintf(stderr, " LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER\n");
        break;
      case LWS_CALLBACK_CONFIRM_EXTENSION_OKAY:
        //fprintf(stderr, " LWS_CALLBACK_CONFIRM_EXTENSION_OKAY\n");
        break;
      case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
        //fprintf(stderr, " LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED\n");
        break;

      case LWS_CALLBACK_ADD_POLL_FD:
      case LWS_CALLBACK_DEL_POLL_FD:
      case LWS_CALLBACK_SET_MODE_POLL_FD:
      case LWS_CALLBACK_CLEAR_MODE_POLL_FD:
      default:
        break;
    }

    return 0;
}


/* list of supported protocols and callbacks */
struct libwebsocket_protocols protocols[] = {
  {
    "lws-mirror-protocol",
    callback_lws_mirror,
    0,
  },
  {
    NULL,
    NULL,
    0
  }
};


/* init routine makes this processor available for dataprocessor directives */
void EchidnaSetup()
{
    /* link the preprocessor keyword to the init function in
       the preproc list */
    RegisterOutputPlugin("echidna", OUTPUT_TYPE_FLAG__ALERT, EchidnaInit);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Output: Echidna is setup\n"););
}

void EchidnaInit(char *args)
{
    SpoEchidnaData *spd_data;

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Output: Echidna initialized\n"););

    /* parse the argument list from the rules file`*/
    spd_data = InitEchidnaData(args);

    AddFuncToPostConfigList(EchidnaInitFinalize, spd_data);

    // TODO: 
//    AddFuncToIdleList(EchidnaIdle, spd_data);

    lws_set_log_level(0, NULL);
}

SpoEchidnaData *InitEchidnaData(char *args)
{
    SpoEchidnaData *data;

    /* setup the internal structures and parse any arguments */
    data = (SpoEchidnaData *)SnortAlloc(sizeof(SpoEchidnaData));

    /* store args for later parsing */
    if( args != NULL )
        data->args = SnortStrdup(args);

    return data;
}

void EchidnaInitFinalize(int unused, void *arg)
{
    SpoEchidnaData *spd_data = (SpoEchidnaData *)arg;

    if( spd_data == NULL )
        FatalError("echidna: data uninitialized\n");

    ParseEchidnaArgs(spd_data);

    /* identify the agent_name */
    if( spd_data->agent_name == NULL )
        spd_data->agent_name = SnortStrdup(GetUniqueName(PRINT_INTERFACE(barnyard2_conf->interface)));

    if( spd_data->node_address == NULL )
        spd_data->node_address = SnortStrdup(DEFAULT_NODEADDRESS);

    if( ! BcLogQuiet() )
    {
        LogMessage("echidna: host = %s\n", spd_data->node_address);
        LogMessage("echidna: port = %u\n", spd_data->node_port);
    }

    /* connect to the sensor agent (SnortAgent) */
    if( EchidnaNodeConnect(spd_data) == 0 )
    {
        /* initialise the sensor agent - get sid/eid */
        if( BcLogVerbose() )
            LogMessage("echidna: waiting for sid/eid from Node.\n");

    }
    else
        FatalError("echidna: unable to connect to agent\n");

    /* in windows, this will init the winsock stuff */
    curl_global_init(CURL_GLOBAL_ALL);

    /* set the preprocessor function into the function list */
    AddFuncToOutputList(Echidna, OUTPUT_TYPE__ALERT, spd_data);
    AddFuncToCleanExitList(EchidnaCleanExitFunc, spd_data);
    AddFuncToRestartList(EchidnaRestartFunc, spd_data);
}

void Echidna(Packet *p, void *event, u_int32_t event_type, void *arg)
{
    json_object *json;

    char *timestamp;

    char *data_msg;

    char id_hash_text[512] = {0};
    char evt_corr_id_hash_text[512] = {0};
    char ssn_corr_id_hash_text[512] = {0};

    uint8_t id_hash[SHA256_DIGEST_LENGTH];
    uint8_t evt_corr_id_hash[SHA256_DIGEST_LENGTH];
    uint8_t ssn_corr_id_hash[SHA256_DIGEST_LENGTH];

    char id_hash_hex[64];
    char evt_corr_id_hash_hex[64];
    char ssn_corr_id_hash_hex[64];

    SHA256_CTX ctx;

    char sip4[INET_ADDRSTRLEN];
    char dip4[INET_ADDRSTRLEN];
    char sip6[INET6_ADDRSTRLEN];
    char dip6[INET6_ADDRSTRLEN];
    uint16_t sport;
    uint16_t dport;

    int i;

    SpoEchidnaData *data;
    SigNode *sn = NULL;
    ClassType *cn = NULL;

    if( event == NULL || arg == NULL )
        return;

    data = (SpoEchidnaData *)arg;

    timestamp = EchidnaTimestamp(
        ntohl(((Unified2EventCommon *)event)->event_second),
        ntohl(((Unified2EventCommon *)event)->event_microsecond)
    );

    /* grab the appropriate signature and classification information */
    sn = GetSigByGidSid(
            ntohl(((Unified2EventCommon *)event)->generator_id),
            ntohl(((Unified2EventCommon *)event)->signature_id),
            ntohl(((Unified2EventCommon *)event)->signature_revision)
            );
    cn = ClassTypeLookupById(barnyard2_conf, ntohl(((Unified2EventCommon *)event)->classification_id));

    /* initialise our json object */
    json = json_object_new_object();


    json_object_object_add(json, "node_id", json_object_new_string(node_id));

    /* not yet classified */
    json_object_object_add(json, "classification", json_object_new_int(0));

    json_object_object_add(json, "meta_u2_event_id", json_object_new_int( ntohl(((Unified2EventCommon *)event)->event_id) ));

    /* IP version, addresses, ports and protocol */
    switch( event_type )
    {
        case UNIFIED2_IDS_EVENT:
        case UNIFIED2_IDS_EVENT_MPLS:
        case UNIFIED2_IDS_EVENT_VLAN:
            inet_ntop(AF_INET, &((Unified2IDSEvent*)event)->ip_source, sip4, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &((Unified2IDSEvent*)event)->ip_destination, dip4, INET_ADDRSTRLEN);
            sport = ntohs(((Unified2IDSEvent *)event)->sport_itype);
            dport = ntohs(((Unified2IDSEvent *)event)->dport_icode);

            json_object_object_add(json, "net_version", json_object_new_int( 4 ));
            json_object_object_add(json, "net_src_ip", json_object_new_string( sip4 ));
            json_object_object_add(json, "net_src_port", json_object_new_int( sport ));
            json_object_object_add(json, "net_dst_ip", json_object_new_string( dip4 ));
            json_object_object_add(json, "net_dst_port", json_object_new_int( dport ));
            json_object_object_add(json, "net_protocol", json_object_new_int(  ((Unified2IDSEvent *)event)->protocol));

            SnortSnprintfAppend(ssn_corr_id_hash_text, 512, "%s%d%s%d%d", sip4, sport, dip4, dport, ((Unified2IDSEvent *)event)->protocol);
            break;
        case UNIFIED2_IDS_EVENT_IPV6:
        case UNIFIED2_IDS_EVENT_IPV6_MPLS:
        case UNIFIED2_IDS_EVENT_IPV6_VLAN:
            inet_ntop(AF_INET6, &((Unified2IDSEventIPv6 *)event)->ip_source, sip6, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &((Unified2IDSEventIPv6 *)event)->ip_destination, dip6, INET6_ADDRSTRLEN);
            sport = ntohs(((Unified2IDSEventIPv6 *)event)->sport_itype);
            dport = ntohs(((Unified2IDSEventIPv6 *)event)->dport_icode);

            json_object_object_add(json, "net_version", json_object_new_int( 6 ));
            json_object_object_add(json, "net_src_ip", json_object_new_string( sip6 ));
            json_object_object_add(json, "net_src_port", json_object_new_int( sport ));
            json_object_object_add(json, "net_dst_ip", json_object_new_string( dip6 ));
            json_object_object_add(json, "net_dst_port", json_object_new_int( dport ));
            json_object_object_add(json, "net_protocol", json_object_new_int( ((Unified2IDSEventIPv6 *)event)->protocol ));

            SnortSnprintfAppend(ssn_corr_id_hash_text, 512, "%s%d%s%d%d", sip6, sport, dip6, dport, ((Unified2IDSEventIPv6 *)event)->protocol);
            break;
    }

    /* snort event reference time */
    json_object_object_add(json, "timestamp", json_object_new_string( timestamp ));

    SnortSnprintfAppend(id_hash_text, 512, "%s%s", ssn_corr_id_hash_text, timestamp);

    /* generator ID */
    json_object_object_add(json, "sig_type", json_object_new_int( ntohl(((Unified2EventCommon *)event)->generator_id) ));

    /* signature ID */
    json_object_object_add(json, "sig_id", json_object_new_int( ntohl(((Unified2EventCommon *)event)->signature_id) ));

    /* signature revision */
    json_object_object_add(json, "sig_revision", json_object_new_int( ntohl(((Unified2EventCommon *)event)->signature_revision) ));

    SnortSnprintfAppend(evt_corr_id_hash_text, 512, "%s%d%d%d",
        ssn_corr_id_hash_text,
        ntohl(((Unified2EventCommon *)event)->generator_id),
        ntohl(((Unified2EventCommon *)event)->signature_id),
        ntohl(((Unified2EventCommon *)event)->signature_revision)
      );

    /* signature message */
    json_object_object_add(json, "sig_message", json_object_new_string( sn->msg ));

    /* alert priority */
    json_object_object_add(json, "sig_priority", json_object_new_int( ntohl(((Unified2EventCommon *)event)->priority_id) ));

    /* alert classification */
    json_object_object_add(json, "sig_category", json_object_new_string(  cn != NULL ? cn->type : "unknown" ));

    /* IP version, addresses, ports and protocol */
    switch( event_type )
    {
        case UNIFIED2_IDS_EVENT:
        case UNIFIED2_IDS_EVENT_MPLS:
        case UNIFIED2_IDS_EVENT_VLAN:
            inet_ntop(AF_INET, &((Unified2IDSEvent*)event)->ip_source, sip4, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &((Unified2IDSEvent*)event)->ip_destination, dip4, INET_ADDRSTRLEN);

            json_object_object_add(json, "net_version", json_object_new_int( 4 ));
            json_object_object_add(json, "net_src_ip", json_object_new_string( sip4 ));
            json_object_object_add(json, "net_src_port", json_object_new_int( ntohs(((Unified2IDSEvent *)event)->sport_itype) ));
            json_object_object_add(json, "net_dst_ip", json_object_new_string( sip4 ));
            json_object_object_add(json, "net_dst_port", json_object_new_int( ntohs(((Unified2IDSEvent *)event)->dport_icode) ));
            json_object_object_add(json, "net_protocol", json_object_new_int( ((Unified2IDSEvent *)event)->protocol ));
            break;
        case UNIFIED2_IDS_EVENT_IPV6:
        case UNIFIED2_IDS_EVENT_IPV6_MPLS:
        case UNIFIED2_IDS_EVENT_IPV6_VLAN:
            inet_ntop(AF_INET6, &((Unified2IDSEventIPv6 *)event)->ip_source, sip6, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &((Unified2IDSEventIPv6 *)event)->ip_destination, dip6, INET6_ADDRSTRLEN);

            json_object_object_add(json, "net_version", json_object_new_int( 6 ));
            json_object_object_add(json, "net_src_ip", json_object_new_string( sip6 ));
            json_object_object_add(json, "net_src_port", json_object_new_int( ntohs(((Unified2IDSEventIPv6 *)event)->sport_itype) ));
            json_object_object_add(json, "net_dst_ip", json_object_new_string( sip6 ));
            json_object_object_add(json, "net_dst_port", json_object_new_int( ntohs(((Unified2IDSEventIPv6 *)event)->dport_icode) ));
            json_object_object_add(json, "net_protocol", json_object_new_int( ((Unified2IDSEventIPv6 *)event)->protocol ));
            break;
    }

    /* pull decoded info from the packet */
    if( p != NULL )
    {
        if( p->iph != NULL )
        {
            /* add IP header */
            EchidnaEventIPHeaderDataAppend(json, p);

            /* add ICMP || UDP || TCP data */
            if( ! (p->packet_flags & PKT_REBUILT_FRAG) )
            {
                switch( p->iph->ip_proto )
                {
                    case IPPROTO_ICMP:
                        EchidnaEventICMPDataAppend(json, p);
                        break;

                    case IPPROTO_TCP:
                        EchidnaEventTCPDataAppend(json, p);
                        break;

                    case IPPROTO_UDP:
                        EchidnaEventUDPDataAppend(json, p);
                        break;

                    default:
                        break;
                }
            }
        }

        /* add payload data */
        if( p->dsize )
        {
            data_msg = fasthex(p->data, p->dsize);
            if( data_msg != NULL )
            {
                json_object_object_add(json, "payload", json_object_new_string( data_msg ));
                free(data_msg);
            }
        }
    }

    /* construct id hash */
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, id_hash_text, strlen(id_hash_text));
    SHA256_Final(id_hash, &ctx);
    for( i=0; i<SHA256_DIGEST_LENGTH; i++)
    {
      sprintf(id_hash_hex+(i*2), "%02x", id_hash[i]);
    }
    json_object_object_add(json, "id", json_object_new_string(id_hash_hex));

    /* construct session correlation id hash */
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, ssn_corr_id_hash_text, strlen(ssn_corr_id_hash_text));
    SHA256_Final(ssn_corr_id_hash, &ctx);
    for( i=0; i<SHA256_DIGEST_LENGTH; i++)
    {
      sprintf(ssn_corr_id_hash_hex+(i*2), "%02x", ssn_corr_id_hash[i]);
    }

    json_object_object_add(json, "ssn_corr_id", json_object_new_string(ssn_corr_id_hash_hex));

    /* construct event correlation id hash */
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, evt_corr_id_hash_text, strlen(evt_corr_id_hash_text));
    SHA256_Final(evt_corr_id_hash, &ctx);
    for( i=0; i<SHA256_DIGEST_LENGTH; i++)
    {
      sprintf(evt_corr_id_hash_hex+(i*2), "%02x", evt_corr_id_hash[i]);
    }
    json_object_object_add(json, "evt_corr_id", json_object_new_string(evt_corr_id_hash_hex));

    /* send msg to sensor_agent */
    EchidnaEventSubmit(data, json);
    json_object_put( json );

    free(timestamp);
}

int EchidnaEventIPHeaderDataAppend(json_object *json, Packet *p)
{
    json_object_object_add(json, "ip_hdr_hlen", json_object_new_int( IP_HLEN(p->iph) ));
    json_object_object_add(json, "ip_hdr_tos", json_object_new_int( p->iph->ip_tos ));
    json_object_object_add(json, "ip_hdr_len", json_object_new_int( p->iph->ip_len ));
    json_object_object_add(json, "ip_hdr_id", json_object_new_int( p->iph->ip_id ));

#if defined(WORDS_BIGENDIAN)
    json_object_object_add(json, "ip_hdr_id", json_object_new_int( ((p->iph->ip_off & 0xe000) >> 13) ));
    json_object_object_add(json, "ip_hdr_id", json_object_new_int( htons(p->iph->ip_off & 0x1fff) ));
#else
    json_object_object_add(json, "ip_hdr_id", json_object_new_int( ((p->iph->ip_off & 0x00e0) >> 5) ));
    json_object_object_add(json, "ip_hdr_id", json_object_new_int( htons(p->iph->ip_off & 0xff1f) ));
#endif

    json_object_object_add(json, "ip_hdr_ttl", json_object_new_int( p->iph->ip_ttl) );
    json_object_object_add(json, "ip_hdr_csum", json_object_new_int( htons(p->iph->ip_csum) ));

    return 0;
}

int EchidnaEventICMPDataAppend(json_object *json, Packet *p)
{
    {
        /* ICMP checksum */
        json_object_object_add(json, "icmp_csum", json_object_new_int( ntohs(p->icmph->csum) ));

        /* Append other ICMP data if we have it */
        if( p->icmph->type == ICMP_ECHOREPLY || p->icmph->type == ICMP_ECHO ||
            p->icmph->type == ICMP_TIMESTAMP || p->icmph->type == ICMP_TIMESTAMPREPLY ||
            p->icmph->type == ICMP_INFO_REQUEST || p->icmph->type == ICMP_INFO_REPLY )
        {
            /* ICMP ID */
            json_object_object_add(json, "icmp_id", json_object_new_int( htonl(p->icmph->icmp_hun.idseq.id) ));

            /* ICMP sequence */
            json_object_object_add(json, "icmp_seq", json_object_new_int( htonl(p->icmph->icmp_hun.idseq.id) ));
        }
    }

    return 0;
}

int EchidnaEventTCPDataAppend(json_object *json, Packet *p)
{
    json_object_object_add(json, "tcp_seq", json_object_new_int( ntohl(p->tcph->th_seq) ));
    json_object_object_add(json, "tcp_ack", json_object_new_int( ntohl(p->tcph->th_ack) ));
    json_object_object_add(json, "tcp_off", json_object_new_int( TCP_OFFSET(p->tcph) ));
    json_object_object_add(json, "tcp_x2", json_object_new_int( TCP_X2(p->tcph) ));
    json_object_object_add(json, "tcp_flags", json_object_new_int( p->tcph->th_flags ));
    json_object_object_add(json, "tcp_win", json_object_new_int( ntohl(p->tcph->th_win) ));
    json_object_object_add(json, "tcp_sum", json_object_new_int( ntohl(p->tcph->th_sum) ));
    json_object_object_add(json, "tcp_urp", json_object_new_int( ntohl(p->tcph->th_urp) ));

    return 0;
}

int EchidnaEventUDPDataAppend(json_object *json, Packet *p)
{
    json_object_object_add(json, "udp_len", json_object_new_int( ntohs(p->udph->uh_len) ));
    json_object_object_add(json, "udp_chk", json_object_new_int( ntohs(p->udph->uh_chk) ));

    return 0;
}

int EchidnaNodeConnect(SpoEchidnaData *spd_data)
{
    int ws_ret = 0;
    int tries = 10;
    struct lws_context_creation_info info;

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "echidna: creating context ... \n"););

    info.port = CONTEXT_PORT_NO_LISTEN;
    info.iface = NULL;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;
    info.options = 0;

#ifndef LWS_NO_EXTENSIONS
    info.extensions = libwebsocket_get_internal_extensions();
#endif

    info.ssl_cert_filepath = NULL;
    info.ssl_private_key_filepath = NULL;
    info.ssl_ca_filepath = NULL;

    /* create the websockt context */
    context = libwebsocket_create_context(&info);

    if (context == NULL)
    {
        FatalError("echidna: unable to create websocket context.\n");
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "echidna: context created: %s %d %d %s\n",
        spd_data->node_address,
        spd_data->node_port,
        spd_data->use_ssl,
        protocols[PROTOCOL_LWS_ECHIDNA].name
    ););


    /* loop until we have a session key */
    while( exit_signal == 0 && session_state == 0 && ws_ret >= 0 )
    {
        if (wsi_echidna == NULL)
        {
            /* create a client websocket using mirror protocol */
            wsi_echidna = libwebsocket_client_connect(
                context,
                spd_data->node_address,
                spd_data->node_port,
                spd_data->use_ssl,
                "/control",
                spd_data->node_address,
                spd_data->node_address,
                protocols[PROTOCOL_LWS_ECHIDNA].name,
                -1 // latest
              );

            DEBUG_WRAP(DebugMessage(DEBUG_LOG,"echidna: websocket connection opened."););

            if ( wsi_echidna == NULL ) {
                sleep(15);
                if( BcTestMode() && --tries < 0 )
                    FatalError("echidna: failed to connect after 10 attempts.\n");
            }

        }
        else
        {
            ws_ret = libwebsocket_service(context, 1000);
            usleep(100000);
        }
    }

    return ( session_state == 1 ) ? 0 : 1;
}

size_t _curl_dummy_write(char *ptr, size_t size, size_t nmemb, void *userdata)
{
     return size * nmemb;
}

/*
 * Function: void EchidnaEventSubmit(SpoEchidnaData *spd_data, char *msg)
 *
 * Purpose: Submit the JSON event structure to the REST node.
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 *
 */
void EchidnaEventSubmit(SpoEchidnaData *spd_data, json_object *json)
{
    CURLcode res;
    char uri[2048];
    long rc = 0;

    if( spd_data->curl == NULL )
    {
        spd_data->curl = curl_easy_init();

        if( spd_data->curl )
        {
            snprintf(uri, 2048, "%s?session=%s", session_uri, session_key);

            curl_easy_setopt(spd_data->curl, CURLOPT_URL, uri);
            curl_easy_setopt(spd_data->curl, CURLOPT_WRITEFUNCTION, &_curl_dummy_write);
        }
        else
        {
            FatalError("echidna: unable to allocate a CURL structure.\n");
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "submitting: %s\n", json_object_to_json_string( json )););

    curl_easy_setopt(spd_data->curl, CURLOPT_POSTFIELDS, json_object_to_json_string( json ) );

    while( rc != 200 )
    {
        if( ( res = curl_easy_perform(spd_data->curl) ) == CURLE_OK )
        {
            curl_easy_getinfo(spd_data->curl, CURLINFO_RESPONSE_CODE, &rc);
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "RC: %lu\n", rc););

            if( rc == 403 )
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "forbidden. TODO: request new session key\n"););
                sleep(15);
            }
            else if( rc != 200 )
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res)););
                sleep(15);
            }
        }
    }
}


/*
 * Function: ParseEchidnaArgs(char *)
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
void ParseEchidnaArgs(SpoEchidnaData *spd_data)
{
    char **toks;
    int num_toks;
    int i;

    /* initialise appropariate values to defaults */
    spd_data->node_port = DEFAULT_NODEPORT;
    spd_data->use_ssl = 0;

    if( spd_data->args == NULL )
    {
        //FatalError("echidna: you must supply arguments for echidna plugin.\n");
        return;
    }

    /* parse out the args */
    toks = mSplit(spd_data->args, ", ", 31, &num_toks, '\\');

    for( i=0; i<num_toks; ++i )
    {
        char **stoks;
        int num_stoks;
        char *index = toks[i];

        while( isspace((int)*index) )
            ++index;

        stoks = mSplit(index, "=", 2, &num_stoks, 0);

        if( !strncasecmp(stoks[0], KEYWORD_NODEPORT, strlen(KEYWORD_NODEPORT)) )
        {
            if( num_stoks > 1 )
                spd_data->node_port = atoi(stoks[1]);
            else
                LogMessage("echidna: node_port error\n");
        }
        else if( !strncasecmp(stoks[0], KEYWORD_NODEADDRESS, strlen(KEYWORD_NODEADDRESS)) )
        {
            if( num_stoks > 1 && spd_data->node_address == NULL )
                spd_data->agent_name = SnortStrdup(stoks[1]);
            else
                LogMessage("echidna: node_address error\n");
        }
        else if( !strncasecmp(stoks[0], KEYWORD_NODENAME, strlen(KEYWORD_NODENAME)) )
        {
            if( num_stoks > 1 && spd_data->agent_name == NULL )
                spd_data->agent_name = SnortStrdup(stoks[1]);
            else
                LogMessage("echidna: agent_name error\n");
        }
        else
        {
            FatalError("echidna: unrecognised plugin argument \"%s\"!\n", index);
        }

        /* free your mSplit tokens */
        mSplitFree(&stoks, num_stoks);
    }

    /* free your mSplit tokens */
    mSplitFree(&toks, num_toks);
}

char *EchidnaTimestamp(u_int32_t sec, u_int32_t usec)
{
    struct tm *lt;  /* localtime */
    char *buf;
    time_t time = sec;

    buf = (char *)SnortAlloc(TMP_BUFFER * sizeof(char));

    if( BcOutputUseUtc() )
        lt = gmtime(&time);
    else
        lt = localtime(&time);

    SnortSnprintf(buf, TMP_BUFFER, "%04i-%02i-%02i %02i:%02i:%02i.%06i",
          1900 + lt->tm_year, lt->tm_mon + 1, lt->tm_mday,
          lt->tm_hour, lt->tm_min, lt->tm_sec, usec);

    return buf;
}

void EchidnaClose(void *arg)
{
    SpoEchidnaData *spd_data = (SpoEchidnaData *)arg;

    /* free allocated memory from SpoEchidnaData */
    if( spd_data != NULL )
    {
        if( spd_data->agent_name )
            free(spd_data->agent_name);

        if( spd_data->args )
            free(spd_data->args);

        if( spd_data->curl )
            curl_easy_cleanup(spd_data->curl);

        free(spd_data);
    }

    /* cleanup the websocket contexts */
    libwebsocket_context_destroy(context);

    /* clean up curl */
    curl_global_cleanup();
}

void EchidnaCleanExitFunc(int signal, void *arg)
{
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"echidna: exiting...\n"););

    EchidnaClose(arg);
}

void EchidnaRestartFunc(int signal, void *arg)
{
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"echidna: restarting...\n"););

    EchidnaClose(arg);
}

#endif /* ENABLE_OUTPUT_PLUGIN */
