/*
** Copyright (C) 2013 Eneo Tecnologia S.L.
** Author: Eugenio Perez <eupm90@gmail.com>
** Based on alert_cvs plugin.
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

/* spo_json
 *
 * Purpose: output plugin for json alerting
 *
 * Arguments: [alert_file]+[kafka://<broker>:<port>@<topic>] [http://<host>:<port>/<url>]
 *
 * Effect:
 *
 * Alerts are sended to:
 *    * kafka broker, using the port and topic given, plus to a alert file (if given).
 *    * HTTP host, using http:// ot https:// version
 *
 * Comments: Allows use of json alerts with other output plugin types.
 * See doc/README.alert_json to more details
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "parser.h"
#include "debug.h"
#include "mstring.h"
#include "util.h"
#include "log.h"
#include "map.h"
#include "unified2.h"

#include "barnyard2.h"

#include "sfutil/sf_textlog.h"
#include "rbutil/rb_numstrpair_list.h"
#include "rbutil/rb_pointers.h"
#include "rbutil/rb_unified2.h"

#ifdef HAVE_RB_MAC_VENDORS
#include "rb_mac_vendors.h"
#endif

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <math.h>
#include <sys/queue.h>

#ifdef HAVE_GEOIP
#include "GeoIP.h"
#endif // HAVE_GEOIP

#ifdef HAVE_LIBRDKAFKA
#include <librdkafka/rdkafka.h>
#endif

#ifdef HAVE_LIBRBHTTP
#include <librbhttp/librb-http.h>
#define MAX_HTTP_DEFAULT_CONECTIONS 10
#define MAX_HTTP_DEFAULT_QUEUED_MESSAGES 10000
#endif

#include <librd/rd.h>
#include <rbutil/rb_printbuf.h>


#ifdef HAVE_GEOIP
#define X_RB_GEOIP \
    _X(SRC_COUNTRY,"src_country","src_country",stringFormat,"N/A") \
    _X(DST_COUNTRY,"dst_country","dst_country",stringFormat,"N/A") \
    _X(SRC_COUNTRY_CODE,"src_country_code","src_country_code",stringFormat,"N/A") \
    _X(DST_COUNTRY_CODE,"dst_country_code","dst_country_code",stringFormat,"N/A") \
    _X(SRC_AS,"src_as","src_as",numericFormat, 0) \
    _X(DST_AS,"dst_as","dst_as",numericFormat, 0) \
    _X(SRC_AS_NAME,"src_as_name","src_as_name",stringFormat,"N/A") \
    _X(DST_AS_NAME,"dst_as_name","dst_as_name",stringFormat,"N/A")
#else
#define X_RB_GEOIP
#endif

#ifdef HAVE_RB_MAC_VENDORS
#define X_RB_MAC_VENDORS \
    _X(ETHSRC_VENDOR,"ethsrc_vendor","ethsrc_vendor",stringFormat,"-") \
    _X(ETHDST_VENDOR,"ethdst_vendor","ethdst_vendor",stringFormat,"-")
#else
#define X_RB_MAC_VENDORS
#endif

#ifdef RB_EXTRADATA
#define X_RB_EXTRADATA \
    _X(SHA256,"sha256","sha256",stringFormat,"-") \
    _X(FILE_SIZE,"file_size","file_size",stringFormat,"-") \
    _X(FILE_HOSTNAME,"file_hostname","file_hostname",stringFormat,"-") \
    _X(FILE_URI,"file_uri","file_uri",stringFormat,"-") \
    _X(EMAIL_SENDER,"email_sender","email_sender",stringFormat,"-") \
    _X(EMAIL_DESTINATIONS,"email_destinations","email_destinations",stringFormat,"-") \
    _X(FTP_USER,"ftp_user","ftp_user",stringFormat,"-")
    //_X(EMAIL_HEADERS,"email_headers","email_headers",stringFormat,"-")
#else
#define X_RB_EXTRADATA
#endif

#define DEFAULT_FILE  "alert.json"
#define DEFAULT_KAFKA_BROKER "kafka://127.0.0.1@barnyard"

#define KAFKA_PROT "kafka://"
#define HTTP_PROT  "http://"
#define HTTPS_PROT "https://"
#define FILENAME_KAFKA_SEPARATOR '+'
#define BROKER_TOPIC_SEPARATOR   '@'

#define FIELD_NAME_VALUE_SEPARATOR ": "
#define JSON_FIELDS_SEPARATOR ", "

#define X_FUNCTION_TEMPLATE \
    _X(TIMESTAMP,"timestamp","timestamp",numericFormat,"0") \
    _X(SENSOR_ID_SNORT,"sensor_id_snort","sensor_id_snort",numericFormat,"0") \
    _X(ACTION,"action","action",stringFormat,"-") \
    _X(SIG_GENERATOR,"sig_generator","sig_generator",numericFormat,"0") \
    _X(SIG_ID,"sig_id","sig_id",numericFormat,"0") \
    _X(SIG_REV,"sig_rev","rev",numericFormat,"0") \
    _X(PRIORITY,"priority","priority",stringFormat,"unknown") \
    _X(CLASSIFICATION,"classification","classification",stringFormat,"-") \
    _X(MSG,"msg","msg",stringFormat,"-") \
    X_RB_EXTRADATA \
    _X(PAYLOAD,"payload","payload",stringFormat,"-") \
    _X(PROTO,"l4_proto_name","l4_proto_name",stringFormat,"-") \
    _X(PROTO_ID,"l4_proto","l4_proto",numericFormat,"0") \
    _X(ETHSRC,"ethsrc","ethsrc",stringFormat,"-") \
    _X(ETHDST,"ethdst","ethdst",stringFormat,"-") \
    X_RB_MAC_VENDORS \
    _X(ETHTYPE,"ethtype","ethtype",numericFormat,"0") \
    _X(ARP_HW_SADDR,"arp_hw_saddr","arp_hw_saddr",stringFormat,"-") \
    _X(ARP_HW_SPROT,"arp_hw_sprot","arp_hw_sprot",stringFormat,"-") \
    _X(ARP_HW_TADDR,"arp_hw_taddr","arp_hw_taddr",stringFormat,"-") \
    _X(ARP_HW_TPROT,"arp_hw_tprot","arp_hw_tprot",stringFormat,"-") \
    _X(VLAN,"vlan","vlan",numericFormat,"0") \
    _X(VLAN_NAME,"vlan_name","vlan_name",stringFormat,"0") \
    _X(VLAN_PRIORITY,"vlan_priority","vlan_priority",numericFormat,"0") \
    _X(VLAN_DROP,"vlan_drop","vlan_drop",numericFormat,"0") \
    _X(UDPLENGTH,"udplength","udplength",numericFormat,"0") \
    _X(ETHLENGTH,"ethlen","ethlength",numericFormat,"0") \
    _X(ETHLENGTH_RANGE,"ethlength_range","ethlength_range",stringFormat,"0") \
    _X(SRCPORT,"l4_srcport","src_port",numericFormat,"0") \
    _X(SRCPORT_NAME,"l4_srcport_name","src_port_name",stringFormat,"-") \
    _X(DSTPORT,"l4_dstport","dst_port",numericFormat,"0") \
    _X(DSTPORT_NAME,"l4_dstport_name","dst_port_name",stringFormat,"-") \
    _X(SRC_TEMPLATE_ID,"src_asnum","src_asnum",numericFormat,"0") \
    _X(SRC_STR,"src","src",stringFormat,"-") \
    _X(SRC_NAME,"src_name","src_name",stringFormat,"-") \
    _X(SRC_NET,"src_net","src_net",stringFormat,"0.0.0.0/0") \
    _X(SRC_NET_NAME,"src_net_name","src_net_name",stringFormat,"0.0.0.0/0") \
    _X(DST_TEMPLATE_ID,"dst_asnum","dst_asnum",stringFormat,"0")  \
    _X(DST_NAME,"dst_name","dst_name",stringFormat,"-") \
    _X(DST_STR,"dst","dst",stringFormat,"-") \
    _X(DST_NET,"dst_net","dst_net",stringFormat,"0.0.0.0/0") \
    _X(DST_NET_NAME,"dst_net_name","dst_net_name",stringFormat,"0.0.0.0/0") \
    _X(ICMPTYPE,"icmptype","icmptype",numericFormat,"0") \
    _X(ICMPCODE,"icmpcode","icmpcode",numericFormat,"0") \
    _X(ICMPID,"icmpid","icmpid",numericFormat,"0") \
    _X(ICMPSEQ,"icmpseq","icmpseq",numericFormat,"0") \
    _X(TTL,"ttl","ttl",numericFormat,"0") \
    _X(TOS,"tos","tos",numericFormat,"0") \
    _X(ID,"id","id",numericFormat,"0") \
    _X(IPLEN,"iplen","iplen",numericFormat,"0") \
    _X(IPLEN_RANGE,"iplen_range","iplen_range",stringFormat,"0") \
    _X(DGMLEN,"dgmlen","dgmlen",numericFormat,"0") \
    _X(TCPSEQ,"tcpseq","tcpseq",numericFormat,"0") \
    _X(TCPACK,"tcpack","tcpack",numericFormat,"0") \
    _X(TCPLEN,"tcplen","tcplen",numericFormat,"0") \
    _X(TCPWINDOW,"tcpwindow","tcpwindow",numericFormat,"0") \
    _X(TCPFLAGS,"tcpflags","tcpflags",stringFormat,"-") \
    X_RB_GEOIP \
    _X(TEMPLATE_END_ID,"","",numericFormat,"0")

typedef enum{
    #define _X(a,b,c,d,e) a,
    X_FUNCTION_TEMPLATE
    #undef _X
}TEMPLATE_ID;

static const char DEFAULT_JSON0[] =
    #define _X(a,b,c,d,e) "," b
    X_FUNCTION_TEMPLATE
    #undef _X
    ;

static const char *DEFAULT_JSON = DEFAULT_JSON0+1;  // Not getting first comma

typedef enum{stringFormat,numericFormat} JsonPrintFormat;

typedef struct{
    const TEMPLATE_ID id;
    const char * templateName;
    const char * jsonName;
    const JsonPrintFormat printFormat;
    char * defaultValue;
}  AlertJSONTemplateElement;

typedef struct _TemplateElement{
    AlertJSONTemplateElement * templateElement;
    TAILQ_ENTRY(_TemplateElement) qentry;
} TemplateElement;

#define OutputTemplate TAILQ_HEAD(,_TemplateElement)
#define output_template_init TAILQ_INIT
#define output_template_append(t,elm) TAILQ_INSERT_TAIL(t,elm,qentry)
#define output_template_first(t) TAILQ_FIRST(t)
#define output_template_foreach(elm,t) TAILQ_FOREACH(elm,t,qentry)

static const uint64_t RPRINTBUF_MAGIC = 0x1ba1c1ba1c1ba1c;

typedef struct _RefcntPrintbuf {
    DEBUG_WRAP(uint64_t magic;);
    struct printbuf printbuf;
    int refcnt;
} RefcntPrintbuf;

static void DecRefcntPrintbuf(RefcntPrintbuf *rprintbuf) {
    if(rd_atomic_sub(&rprintbuf->refcnt,1) == 0) {
        /* No more users, let's free */
        free(rprintbuf->printbuf.buf);
        DEBUG_WRAP(memset(rprintbuf,0,sizeof(rprintbuf)));
        free(rprintbuf);
    }
}

typedef struct _AlertJSONData
{
    RefcntPrintbuf *curr_printbuf;
    char * jsonargs;
    OutputTemplate output_template;
    Number_str_assoc * hosts, *nets, *services, *protocols, *vlans;
    char *enrich_with;
#ifdef HAVE_GEOIP
    GeoIP *gi,*gi_org;
#ifdef SUP_IP6
    GeoIP *gi6,*gi6_org;
#endif /* SUP_IP6 */
#endif /* HAVE_GEOIP */
#ifdef HAVE_RB_MAC_VENDORS
    struct mac_vendor_database *eth_vendors_db;
#endif
#ifdef HAVE_LIBRDKAFKA
    struct {
        int                    do_poll;
        char *brokers,*topic;
        rd_kafka_t            *rk;
        rd_kafka_conf_t       *rk_conf;
        rd_kafka_topic_t      *rkt;
        rd_kafka_topic_conf_t *rkt_conf;
        pthread_t              poll_thread;
    } kafka;
#endif
#ifdef HAVE_LIBRBHTTP
    struct {
        long max_connections;
        long max_queued_messages;
        long conn_timeout;
        long req_timeout;
        long verbose;
        int                    do_poll;
        pthread_t              poll_thread;
        const char *url;
        struct rb_http_handler_s *handler;
    } http;
#endif
} AlertJSONData;

static const char *priority_name[] = {NULL, "high", "medium", "low", "very low"};

/* Remember update printElementWithTemplate if some element modified here */
static AlertJSONTemplateElement template[] = {
    #define _X(a,b,c,d,e) {a,b,c,d,e},
    X_FUNCTION_TEMPLATE
    #undef _X
};


/* list of function prototypes for this preprocessor */
static void AlertJSONInit(char *);
static AlertJSONData *AlertJSONParseArgs(char *);
static void AlertJSON(Packet *, void *, uint32_t, void *);
static void AlertJSONCleanExit(int, void *);
static void AlertRestart(int, void *);
static void RealAlertJSON(Packet*, void*, uint32_t, AlertJSONData * data);
#ifdef HAVE_LIBRDKAFKA
static void AlertJsonKafkaDelayedInit (AlertJSONData *this);
static void KafkaMsgDelivered (rd_kafka_t *rk,
               void *payload, size_t len,
               int error_code,
               void *opaque, void *msg_opaque);
#endif

/*
 * Function: SetupJSON()
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
void AlertJSONSetup(void)
{
    /* link the preprocessor keyword to the init function in
       the preproc list */
    RegisterOutputPlugin("alert_json", OUTPUT_TYPE_FLAG__ALERT, AlertJSONInit);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output plugin: alert_json is setup...\n"););
}


/*
 * Function: JSONInit(char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
static void AlertJSONInit(char *args)
{
    AlertJSONData *data;
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output: JSON Initialized\n"););
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output: Disabling SIGPIPE signal\n"););

    signal(SIGPIPE,SIG_IGN);

    /* parse the argument list from the rules file */
    data = AlertJSONParseArgs(args);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Linking JSON functions to call lists...\n"););

    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(AlertJSON, OUTPUT_TYPE__ALERT, data);
    AddFuncToCleanExitList(AlertJSONCleanExit, data);
    AddFuncToShutdownList(AlertJSONCleanExit, data);
    AddFuncToRestartList(AlertRestart, data);
}

#ifdef HAVE_LIBRDKAFKA

/* Extracted from Magnus Edenhill's kafkacat */
static rd_kafka_conf_res_t 
rdkafka_add_attr_to_config(rd_kafka_conf_t *rk_conf,rd_kafka_topic_conf_t *topic_conf,
                    const char *name,const char *val,char *errstr,size_t errstr_size){
    if (!strcmp(name, "list") ||
        !strcmp(name, "help")) {
        rd_kafka_conf_properties_show(stdout);
        exit(0);
    }

    rd_kafka_conf_res_t res = RD_KAFKA_CONF_UNKNOWN;
    /* Try "topic." prefixed properties on topic
     * conf first, and then fall through to global if
     * it didnt match a topic configuration property. */
    if (!strncmp(name, "topic.", strlen("topic.")))
        res = rd_kafka_topic_conf_set(topic_conf,
                          name+strlen("topic."),
                          val,errstr,errstr_size);

    if (res == RD_KAFKA_CONF_UNKNOWN)
        res = rd_kafka_conf_set(rk_conf, name, val,
                    errstr, errstr_size);

    return res;
}

static rd_kafka_conf_res_t 
rdkafka_add_str_to_config(rd_kafka_conf_t *rk_conf, rd_kafka_topic_conf_t *rkt_conf,
            const char *_keyval, char *errstr,size_t errstr_size){

    char *keyval = SnortStrdup(_keyval);

    const char *key = keyval;
    char *val = strchr(keyval,'=');

    if(!val){
        FatalError("alert_json: Cannot parse %s(%i): %s: "
            "rdkafka configuration does not have format rdkafka.key=value",
            file_name, file_line, _keyval);
    }

    *val = '\0';
    val++;

    const rd_kafka_conf_res_t rc = rdkafka_add_attr_to_config(rk_conf,rkt_conf,key,val,errstr,errstr_size);
    free(keyval);
    return rc;
}

#endif

/*
 * Function: ParseJSONArgs(char *)
 *
 * Purpose: Process positional args, if any.  Syntax is:
 * output alert_json: [<logpath> ["default"|<list>]]
 * list ::= <field>(,<field>)*
 * field ::= "dst"|"src"|"ttl" ...
 * name ::= sensor name
 * id  ::= number
 * Arguments: args => argument list
 *
 * Returns: New filled AlertJSONData struct.
 */
static AlertJSONData *AlertJSONParseArgs(char *args)
{
    char **toks;
    int num_toks;
    AlertJSONData *data;
    char* filename = NULL;
    int i;
    char* hostsListPath = NULL,*networksPath = NULL,*servicesPath = NULL,*protocolsPath = NULL,*vlansPath=NULL,*prioritiesPath=NULL;
    #ifdef HAVE_GEOIP
    char * geoIP_path = NULL;
    char * geoIP_org_path = NULL;
    #ifdef SUP_IP6
    char * geoIP6_path = NULL;
    char * geoIP6_org_path = NULL;
    #endif /* SUP_IP6 */
    #endif /* HAVE_GEOIP */
    #ifdef HAVE_RB_MAC_VENDORS
    char * eth_vendors_path = NULL;
    #endif

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "ParseJSONArgs: %s\n", args););
    data = (AlertJSONData *)SnortAlloc(sizeof(AlertJSONData));

    if ( !data )
    {
        FatalError("alert_json: unable to allocate memory!\n");
    }
    if ( !args ) args = "";
    toks = mSplit((char *)args, " \t", 0, &num_toks, '\\');

#ifdef HAVE_LIBRDKAFKA
    char* kafka_str      = NULL;
    data->kafka.rk_conf  = rd_kafka_conf_new();
    data->kafka.rkt_conf = rd_kafka_topic_conf_new();
#endif

#ifdef HAVE_LIBRBHTTP
    data->http.max_connections     = MAX_HTTP_DEFAULT_CONECTIONS;
    data->http.max_queued_messages = MAX_HTTP_DEFAULT_QUEUED_MESSAGES;
#endif

    for (i = 0; i < num_toks; i++)
    {
        const char* tok = toks[i];
        if ( !strncasecmp(tok, "filename=",strlen("filename=")) && !filename)
        {
            RB_IF_CLEAN(filename,filename = SnortStrdup(tok+strlen("filename=")),"%s(%i) param setted twice\n",tok,i);
        }
        else if(!strncasecmp(tok,"params=",strlen("params=")) && !data->jsonargs)
        {
            RB_IF_CLEAN(data->jsonargs,data->jsonargs = SnortStrdup(tok+strlen("params=")),"%s(%i) param setted twice\n",tok,i);
        }
        else if(!strncasecmp(tok, KAFKA_PROT,strlen(KAFKA_PROT)) && !kafka_str)
        {
#ifdef HAVE_LIBRDKAFKA
            RB_IF_CLEAN(kafka_str,kafka_str = SnortStrdup(tok),"%s(%i) param setted twice\n",tok,i);
#else
            FatalError("alert_json: This barnyard was build with no librdkafka support.");
#endif
        }
        else if(!strncasecmp(tok, HTTP_PROT,strlen(HTTP_PROT)) || !strncasecmp(tok,HTTPS_PROT,strlen(HTTP_PROT)))
        {
#ifdef HAVE_LIBRBHTTP
            RB_IF_CLEAN(data->http.url,data->http.url = SnortStrdup(tok),"%s(%i) param setted twice\n",tok,i);
#else
            FatalError("alert_json: This barnyard was build with no http support.");
#endif
        }
        else if ( !strncasecmp(tok, "default", strlen("default")) && !data->jsonargs)
        {
            RB_IF_CLEAN(data->jsonargs,data->jsonargs = SnortStrdup(DEFAULT_JSON),"%s(%i) param setted twice\n",tok,i);
        }
        else if(!strncasecmp(tok,"enrich_with=",strlen("enrich_with=")))
        {
            RB_IF_CLEAN(data->enrich_with,data->enrich_with = SnortStrdup(tok+strlen("enrich_with=")),"%s(%i) param setted twice\n",tok,i);
            if( data->enrich_with[0]!='{' )
            {
                FatalError("alert_json: enrich_with argument does not start with {");
            }
            if( data->enrich_with[strlen(data->enrich_with)-1] != '}' )
            {
                FatalError("alert_json: enrich_with argument does not end with }");
            }
            /* More convenience to enrich */
            data->enrich_with[0] = ',';
            data->enrich_with[strlen(data->enrich_with)-1] = '\0';

        }
        else if(!strncasecmp(tok,"hosts=",strlen("hosts=")))
        {
            RB_IF_CLEAN(hostsListPath, hostsListPath = SnortStrdup(tok+strlen("hosts=")),"%s(%i) param setted twice.\n",tok,i);
        }
        else if(!strncasecmp(tok,"networks=",strlen("networks=")))
        {
            RB_IF_CLEAN(networksPath,networksPath = SnortStrdup(tok+strlen("networks=")),"%s(%i) param setted twice.\n",tok,i);
        }
        else if(!strncasecmp(tok,"services=",strlen("services=")))
        {
            RB_IF_CLEAN(servicesPath, servicesPath = SnortStrdup(tok+strlen("services=")),"%s(%i) param setted twice.\n",tok,i);
        }
        else if(!strncasecmp(tok,"protocols=",strlen("protocols=")))
        {
            RB_IF_CLEAN(protocolsPath, protocolsPath = SnortStrdup(tok+strlen("protocols=")),"%s(%i) param setted twice.\n",tok,i);
        }
        else if(!strncasecmp(tok,"priorities=",strlen("priorities=")))
        {
            RB_IF_CLEAN(prioritiesPath, prioritiesPath = SnortStrdup(tok+strlen("priorities=")),"%s(%i) param setted twice.\n",tok,i);
        }
        else if(!strncasecmp(tok,"vlans=",strlen("vlans")))
        {
            RB_IF_CLEAN(vlansPath, vlansPath = SnortStrdup(tok+strlen("vlans=")),"%s(%i) param setted twice.\n",tok,i);
        }
        else if(!strncasecmp(tok,"rdkafka.",strlen("rdkafka."))){
            #if HAVE_LIBRDKAFKA
            char errstr[512];

            const rd_kafka_conf_res_t rc = rdkafka_add_str_to_config(data->kafka.rk_conf,data->kafka.rkt_conf,tok+strlen("rdkafka."),errstr,sizeof(errstr));
            if(rc != RD_KAFKA_CONF_OK){
                FatalError("alert_json: Cannot parse %s(%i): %s: %s\n",
                    file_name, file_line, tok,errstr);
            }
            #else
            FatalError("alert_json: Cannot parse %s(%i): %s: Does not have librdkafka\n",
                file_name, file_line, tok);
            #endif
        }
        else if(!strncasecmp(tok,"http.",strlen("http.")))
        {
#ifndef HAVE_LIBRBHTTP
            FatalError("alert_json: This plugin was not build using HTTP extensions");
#else
            /// @TODO use a function
            char *end=NULL;
            if(!strncmp(tok,"http.max_connections=",strlen("http.max_connections=")))
            {
                data->http.max_connections = strtol(tok+strlen("http.max_connections="),&end,0);
            }
            else if (!strncmp(tok,"http.max_queued_messages=",strlen("http.max_queued_messages=")))
            {
                data->http.max_queued_messages = strtol(tok+strlen("http.max_queued_messages="),&end,0);
            }
            else if (!strncmp(tok,"http.conn_timeout=",strlen("http.conn_timeout=")))
            {
                data->http.conn_timeout = strtol(tok+strlen("http.conn_timeout="),&end,0);
            }
            else if (!strncmp(tok,"http.req_timeout=",strlen("http.req_timeout=")))
            {
                data->http.req_timeout = strtol(tok+strlen("http.req_timeout="),&end,0);
            }
            else if (!strncmp(tok,"http.verbose=",strlen("http.verbose=")))
            {
                data->http.verbose = strtol(tok+strlen("http.verbose="),&end,0);
            }

            if(NULL == end || *end != '\0')
            {
                FatalError("alert_json: Cannot parse HTTP %s parameter: Invalid value\n",tok);
            }
#endif
        }
        else if(!strncasecmp(tok,"eth_vendors=",strlen("eth_vendors=")))
        {
            RB_IF_CLEAN(eth_vendors_path,eth_vendors_path = SnortStrdup(tok+strlen("eth_vendors=")),"%s(%i) param setted twice.\n",tok,i);
        }
        #ifdef HAVE_GEOIP
        else if(!strncasecmp(tok,"geoip=",strlen("geoip=")))
        {
            RB_IF_CLEAN(geoIP_path,geoIP_path = SnortStrdup(tok+strlen("geoip=")),"%s(%i) param setted twice.\n",tok,i);
        }
        else if(!strncasecmp(tok,"geoip_org=",strlen("geoip_org=")))
        {
            RB_IF_CLEAN(geoIP_org_path,geoIP_org_path = SnortStrdup(tok+strlen("geoip_org=")),"%s(%i) param setted twice.\n",tok,i);
        }
        #ifdef SUP_IP6
        else if(!strncasecmp(tok,"geoip6=",strlen("geoip6=")))
        {
            RB_IF_CLEAN(geoIP6_path,geoIP6_path = SnortStrdup(tok+strlen("geoip6=")),"%s(%i) param setted twice.\n",tok,i);
        }
        else if(!strncasecmp(tok,"geoip6_org=",strlen("geoip6_org=")))
        {
            RB_IF_CLEAN(geoIP6_org_path,geoIP6_org_path = SnortStrdup(tok+strlen("geoip6_org=")),"%s(%i) param setted twice.\n",tok,i);
        }
        #endif /* SUP_IP6 */
        #endif /* HAVE_GEOIP */
        #ifdef HAVE_RB_MAC_VENDORS
        else if(!strncasecmp(tok,"eth_vendors=",strlen("eth_vendors=")))
        {
            RB_IF_CLEAN(eth_vendors_path,eth_vendors_path = SnortStrdup(tok+strlen("eth_vendors=")),"%s(%i) param setted twice.\n",tok,i);
        }
        #endif
        else
        {
            FatalError("alert_json: Cannot parse %s(%i): %s\n",
            file_name, file_line, tok);
        }
    }

    /* DFEFAULT VALUES */
    if ( !data->jsonargs ) data->jsonargs = SnortStrdup(DEFAULT_JSON);
    if ( !filename ) filename = ProcessFileOption(barnyard2_conf_for_parsing, DEFAULT_FILE);
    
    /* names-str assoc */
    if(hostsListPath) FillHostsList(hostsListPath,&data->hosts,HOSTS);
    if(networksPath) FillHostsList(networksPath,&data->nets,NETWORKS);
    if(servicesPath) FillHostsList(servicesPath,&data->services,SERVICES);
    if(protocolsPath) FillHostsList(protocolsPath,&data->protocols,PROTOCOLS);
    if(vlansPath) FillHostsList(vlansPath,&data->vlans,VLANS);

    mSplitFree(&toks, num_toks);
    toks = mSplit(data->jsonargs, ",", 128, &num_toks, 0);

    output_template_init(&data->output_template);

    for(i=0;i<num_toks;++i){
        int j;
        for(j=0;;++j){
            if(template[j].id==TEMPLATE_END_ID)
                FatalError("alert_json: Cannot parse template element %s\n",toks[i]);
            if(!strcmp(template[j].templateName,toks[i])){
                TemplateElement *elm = SnortAlloc(sizeof(elm[0]));
                if (NULL != elm)
                {
                    elm->templateElement = &template[j];
                    output_template_append(&data->output_template,elm);
                }
                else
                {
                    FatalError("alert_json: Cannot allocate template element (out of memory?)\n");
                }
                break;
            }
        }
    }

    mSplitFree(&toks, num_toks);


#ifdef HAVE_GEOIP
    if(geoIP_path){
        data->gi = GeoIP_open(geoIP_path, GEOIP_MEMORY_CACHE);

        if (data->gi == NULL)
            ErrorMessage("alert_json: Error opening database %s\n",geoIP_path);
        else
            DEBUG_WRAP(DebugMessage(DEBUG_INIT, "alert_json: Success opening geoip database: %s\n", geoIP_path););
    }else{
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "alert_json: No geoip database specified.\n"););
    }

    if(geoIP_org_path)
    {
        data->gi_org = GeoIP_open(geoIP_org_path, GEOIP_MEMORY_CACHE);

        if (data->gi_org == NULL)
            ErrorMessage("alert_json: Error opening database %s\n",geoIP_org_path);
        else
            DEBUG_WRAP(DebugMessage(DEBUG_INIT, "alert_json: Success opening geoip database: %s\n", geoIP_org_path););
    }else{
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "alert_json: No geoip organization database specified.\n"););
    }

#ifdef SUP_IP6
    if(geoIP6_path){
        data->gi6 = GeoIP_open(geoIP6_path, GEOIP_MEMORY_CACHE);

        if (data->gi6 == NULL)
            ErrorMessage("alert_json: Error opening database %s\n",geoIP6_path);
        else
            DEBUG_WRAP(DebugMessage(DEBUG_INIT, "alert_json: Success opening geoip database: %s\n", geoIP6_path););
    }else{
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "alert_json: No geoip database specified.\n"););
    }

    if(geoIP6_org_path)
    {
        data->gi6_org = GeoIP_open(geoIP6_org_path, GEOIP_MEMORY_CACHE);

        if (data->gi6_org == NULL)
            ErrorMessage("alert_json: Error opening database %s\n",geoIP6_org_path);
        else
            DEBUG_WRAP(DebugMessage(DEBUG_INIT, "alert_json: Success opening geoip database: %s\n", geoIP6_org_path););
    }else{
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "alert_json: No geoip organization database specified.\n"););
    }
#endif

#endif // HAVE_GEOIP

#ifdef HAVE_RB_MAC_VENDORS
    if(eth_vendors_path)
    {
        data->eth_vendors_db = rb_new_mac_vendor_db(eth_vendors_path);
        if(NULL==data->eth_vendors_db)
        {
            FatalError("alert_json: No valid rb_mac_vendors_database given.\n");
        }
    }
#endif // HAVE_RB_MAC_VENDORS

    DEBUG_WRAP(DebugMessage(
        DEBUG_INIT, "alert_json: '%s' '%s'\n", filename, data->jsonargs
    ););

#ifdef HAVE_LIBRDKAFKA
    if(kafka_str){
        /// @TODO this should be cleaned.
        char * at_char = strchr(kafka_str,BROKER_TOPIC_SEPARATOR);
        if(at_char==NULL)
            FatalError("alert_json: No topic specified, despite the fact a kafka server was given. Use kafka://broker@topic.");
        const size_t broker_length = (at_char-(kafka_str+strlen(KAFKA_PROT)));
        data->kafka.brokers = SnortAlloc(broker_length+1);
        strncpy(data->kafka.brokers,kafka_str+strlen(KAFKA_PROT),broker_length);
        data->kafka.brokers[broker_length] = '\0';
        data->kafka.topic = SnortStrdup(at_char+1);

        /*
         * In DaemonMode(), kafka must start in another function, because, in daemon mode, Barnyard2Main will execute this 
         * function, will do a fork() and then, in the child process, will call RealAlertJSON, that will not be able to 
         * send kafka data */

        free(kafka_str);
    }
#endif

    if ( filename ) free(filename);
    if( hostsListPath ) free (hostsListPath);
    if( networksPath ) free (networksPath);
    if( servicesPath ) free (servicesPath);
    if( protocolsPath ) free (protocolsPath);
    if( prioritiesPath ) free (prioritiesPath);
    if( vlansPath ) free(vlansPath);
    #ifdef HAVE_GEOIP
    if (geoIP_path) free(geoIP_path);
    if (geoIP_org_path) free(geoIP_org_path);
    #endif


    return data;
}

#ifdef HAVE_LIBRDKAFKA
static void KafkaMsgDelivered (rd_kafka_t *rk,
               void *payload, size_t len,
               int error_code,
               void *opaque, void *msg_opaque)
{
    RefcntPrintbuf *rprintbuf = msg_opaque;
    
    DEBUG_WRAP(if(RPRINTBUF_MAGIC!=rprintbuf->magic)
        FatalError("msg_delivered: Not valid magic"));

    if (unlikely(error_code))
        ErrorMessage("rdkafka Message delivery failed: %s\n",rd_kafka_err2str(error_code));
    else if (unlikely(BcLogVerbose()))
        LogMessage("rdkafka Message delivered (%zd bytes)\n", len);

    DecRefcntPrintbuf(rprintbuf);
}

static void *KafkaPollFuncion(void *vjsonData)
{
    AlertJSONData *jsonData = vjsonData;
    while(rd_atomic_add(&jsonData->kafka.do_poll,0))
    {
        rd_kafka_poll(jsonData->kafka.rk,500);
    }

    return NULL;
}

static void AlertJsonKafkaDelayedInit (AlertJSONData *this)
{
    char errstr[256];

    if(!this->kafka.rk_conf)
        FatalError("%s called with NULL==this->rk_conf\n",
            __FUNCTION__);

    if(!this->kafka.rkt_conf)
        FatalError("%s called with NULL==this->rkt_conf\n",
            __FUNCTION__);

    rd_kafka_conf_set_dr_cb(this->kafka.rk_conf,KafkaMsgDelivered);
    this->kafka.rk = rd_kafka_new(RD_KAFKA_PRODUCER, this->kafka.rk_conf, errstr, sizeof(errstr));

    if(NULL==this->kafka.rk)
        FatalError("Failed to create new producer: %s\n",errstr);

    if (rd_kafka_brokers_add(this->kafka.rk, this->kafka.brokers) == 0) 
        FatalError("Kafka: No valid brokers specified in %s\n",this->kafka.brokers);

    this->kafka.rkt = rd_kafka_topic_new(this->kafka.rk, this->kafka.topic, this->kafka.rkt_conf);

    if(NULL==this->kafka.rkt)
        FatalError("It was not possible create a kafka topic %s\n",this->kafka.topic);

    rd_atomic_add(&this->kafka.do_poll,1);
    const int rc = pthread_create(&this->kafka.poll_thread, NULL,
                          KafkaPollFuncion, this);

    if(rc != 0)
    {
        char errbuf[512];

        strerror_r(errno,errbuf,sizeof(errbuf));
        FatalError("Couln't create kafka poll thread: %s",errbuf);
    }
}
#endif

#ifdef HAVE_LIBRBHTTP
static void HttpMsgDelivered(struct rb_http_handler_s * rb_http_handler,
                            int status_code,
                            long http_code,
                            const char * status_code_str,
                            char * buff,size_t len,
                            void * msg_opaque)
{
    RefcntPrintbuf *rprintbuf = msg_opaque;

    DEBUG_WRAP(if(RPRINTBUF_MAGIC!=rprintbuf->magic)
        FatalError("msg_delivered: Not valid magic"));

    if (unlikely(status_code))
    {
        ErrorMessage("http Message delivery failed: (%d)%s\n",status_code,status_code_str);
    }
    else if(unlikely(http_code != 200))
    {
        ErrorMessage("alert_json: HTTP server returned %ld code\n",http_code);
    }
    else if (unlikely(BcLogVerbose()))
    {
        LogMessage("http Message delivered (%zd bytes)\n", len);
    }

    DecRefcntPrintbuf(rprintbuf);
}

void *HttpPollFuncion(void *vjsonData) {
    AlertJSONData *jsonData = vjsonData;

    while(rd_atomic_add(&jsonData->http.do_poll,0))
    {
        rb_http_get_reports (jsonData->http.handler,
                              HttpMsgDelivered, 500);
    }

    return NULL;
}

static void HTTPHandlerSetLongOpt(struct rb_http_handler_s *handler, 
    const char *key,long val)
{
    char errstr[BUFSIZ];
    char valbuf[BUFSIZ];
    
    snprintf(valbuf,sizeof(valbuf),"%ld",val);

    const int rc = rb_http_handler_set_opt(handler,key,valbuf,errstr,
        sizeof(errstr));

    if(rc != 0)
    {
        FatalError("alert_json: Couldn't set option %s to %ld: %s\n",
            key, val, errstr);
    }
}

static void AlertJsonHTTPDelayedInit (AlertJSONData *this)
{

    char errstr[256];

    if(!this->http.url)
    {
        FatalError("%s called with NULL==this->http.url\n",
            __FUNCTION__);
    }

    this->http.handler = rb_http_handler_create (this->http.url, 
        errstr, sizeof(errstr));

    HTTPHandlerSetLongOpt(this->http.handler, "HTTP_MAX_TOTAL_CONNECTIONS", 
        this->http.max_connections);
    HTTPHandlerSetLongOpt(this->http.handler, "HTTP_TIMEOUT", 
        this->http.req_timeout);
    HTTPHandlerSetLongOpt(this->http.handler, "HTTP_CONNTTIMEOUT", 
        this->http.conn_timeout);
    HTTPHandlerSetLongOpt(this->http.handler, "HTTP_VERBOSE", 
        this->http.verbose);
    HTTPHandlerSetLongOpt(this->http.handler, "RB_HTTP_MAX_MESSAGES", 
        this->http.max_queued_messages);


    if(NULL==this->http.handler)
    {
        FatalError("Failed to create new HTTP producer: %s\n",errstr);
    }

    rd_atomic_add(&this->http.do_poll,1);
    const int rc = pthread_create(&this->http.poll_thread, NULL,
                          HttpPollFuncion, this);

    if(rc != 0)
    {
        char errbuf[512];

        strerror_r(errno,errbuf,sizeof(errbuf));
        FatalError("Couln't create http poll thread: %s",errbuf);
    }

}
#endif

static void AlertJSONCleanup(int signal, void *arg, const char* msg)
{
    AlertJSONData *data = (AlertJSONData *)arg;
    TemplateElement *template_element = NULL;
    /* close alert file */
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"%s\n", msg););

    if(data)
    {
#ifdef HAVE_LIBRDKAFKA
        if(data->kafka.rk)
        {
            rd_atomic_sub(&data->kafka.do_poll,1);
            const int join_rc = pthread_join(data->kafka.poll_thread,NULL);
            if(0 != join_rc)
            {
                ErrorMessage("Couldn't join poll_thread (%d)",join_rc);
            }

            while (rd_kafka_outq_len(data->kafka.rk) > 0)
            {
                rd_kafka_poll(data->kafka.rk, 100);
            }

            if(data->kafka.rkt)
            {
                // @TODO
                // rdkafka_topic_destroy(data->kafka.rkt);
            }

            rd_kafka_destroy(data->kafka.rk);
            // @TODO
            // rd_kafka_wait_destroyed();
        }
#endif

#ifdef HAVE_GEOIP
        if(data->gi)
        {
            GeoIP_delete(data->gi);
        }
        if(data->gi_org)
        {
            GeoIP_delete(data->gi_org);
        }
        if(data->gi6)
        {
            GeoIP_delete(data->gi6);
        }
        if(data->gi6_org)
        {
            GeoIP_delete(data->gi6_org);
        }
#endif // HAVE_GEOIP

        free(data->jsonargs);
        freeNumberStrAssocList(data->hosts);
        freeNumberStrAssocList(data->nets);
        freeNumberStrAssocList(data->services);
        freeNumberStrAssocList(data->protocols);
        freeNumberStrAssocList(data->vlans);
        while((template_element = output_template_first(&data->output_template)))
        {
            free(template_element);
        }

        /* free memory from SpoJSONData */
        free(data);
    }
}

static void AlertJSONCleanExit(int signal, void *arg)
{
    AlertJSONCleanup(signal, arg, "AlertJSONCleanExit");
}

static void AlertRestart(int signal, void *arg)
{
    AlertJSONCleanup(signal, arg, "AlertRestart");
}


static void AlertJSON(Packet *p, void *event, uint32_t event_type, void *arg)
{
    AlertJSONData *data = (AlertJSONData *)arg;
    RealAlertJSON(p, event, event_type, data);
}

/*
 * Function: C++ version 0.4 char* style "itoa", Written by Lukás Chmela. (Modified)
 *
 * Purpose: Fast itoa conversion. snprintf is slow.
 * 
 * Arguments:   value => Number.
 *             result => Where to save result
 *               base => Number base.
 *
 * Return: result
 * TODO: Return writed buffer lenght.
 * 
 */
char* _itoa(uint64_t value, char* result, int base, size_t bufsize) {
    // check that the base if valid
    if (base < 2 || base > 36) { *result = '\0'; return result; }

    char *ptr = result+bufsize;
    uint64_t tmp_value;

    *--ptr = '\0';
    do {
        tmp_value = value;
        value /= base;
        *--ptr = "zyxwvutsrqponmlkjihgfedcba9876543210123456789abcdefghijklmnopqrstuvwxyz" [35 + (tmp_value - value * base)];
    } while ( value );


    if (tmp_value < 0) *--ptr = '-';
    return ptr;
}

/* shortcut to used bases */
static inline char *itoa10(uint64_t value,char *result,const size_t bufsize){return _itoa(value,result,10,bufsize);}
static inline char *itoa16(uint64_t value,char *result,const size_t bufsize){
    char *ret = _itoa(value,result,16,bufsize);
    if(value < 16 && ret > result){
        ret--;
        *ret='0';
    }
    return ret;
}

static inline void printHWaddr(struct printbuf *pbuf,const uint8_t *addr,char * buf,const size_t bufLen){
    int i;
    for(i=0;i<6;++i)
    {
        if(i>0)
        {
            printbuf_memappend_fast_str(pbuf,":");
        }

        printbuf_memappend_fast_n16(pbuf,addr[i]);
    }
}

/* convert a HW vector-form given into a uint64_t */
static inline uint64_t HWADDR_vectoi(const uint8_t *vaddr)
{
    int i;
    uint64_t addr = 0;
    for(i=0;i<5;++i)
    {
        addr+=vaddr[i];
        addr<<=8;
    }
    addr+=vaddr[5];
    return addr;
}

#define SRC_REQ 0
#define DST_REQ 1

static int extract_ip_from_packet(sfip_t *ip,Packet *p,int srcdst_req)
{
    if(!(srcdst_req == SRC_REQ || srcdst_req == DST_REQ))
    {
        ErrorMessage("extract_ip_from_packet called with no valid direction.");
        return SFIP_FAILURE;
    }

    #ifdef SUP_IP6

        if(srcdst_req == SRC_REQ)
        {
            return SFIP_SUCCESS == sfip_set_ip(ip,GET_SRC_ADDR(p));
        }
        else /* srcdst_req == DST_REQ)*/
        {
            return SFIP_SUCCESS == sfip_set_ip(ip,GET_DST_ADDR(p));
        }

    #else
        uint32_t ipv4 = 0;
        if(srcdst_req == SRC_REQ)
        {
            ipv4 = GET_SRC_ADDR(p).s_addr;
        }
        else
        {
            ipv4 = GET_DST_ADDR(p).s_addr;
        }
        return sfip_set_raw(ip,&ipv4,AF_INET);
    #endif
}

static int extract_ip0(sfip_t *ip,const void *_event, uint32_t event_type, Packet *p,int srcdst_req)
{
    if(!(srcdst_req == SRC_REQ || srcdst_req == DST_REQ))
    {
        ErrorMessage("extract_ip_from_packet called with no valid direction.");
        return SFIP_FAILURE;
    }

    switch(event_type)
    {
    case UNIFIED2_PACKET:
        // Does not have information in the event -> trying to get it from the packet
        return extract_ip_from_packet(ip,p,srcdst_req);
        

    case UNIFIED2_IDS_EVENT:
    case UNIFIED2_IDS_EVENT_VLAN:
        // Share the same structure until src/dst ip included
        {
            uint32_t ipv4 = 0;
            if(srcdst_req == SRC_REQ)
            {
                ipv4 = ((Unified2IDSEvent *)_event)->ip_source;
            }
            else
            {
                ipv4 = ((Unified2IDSEvent *)_event)->ip_destination;
            }
            
            const int rc = sfip_set_raw(ip,&ipv4,AF_INET);
            if(p && rc != SFIP_SUCCESS)
                return extract_ip_from_packet(ip,p,srcdst_req);
            return rc;
        }

    case UNIFIED2_IDS_EVENT_IPV6:
    case UNIFIED2_IDS_EVENT_IPV6_VLAN:
        // Share the same structure until src/dst ip included
        {
            int rc;
            if(srcdst_req == SRC_REQ)
            {
                rc = sfip_set_raw(ip,((Unified2IDSEventIPv6 *)_event)->ip_source.s6_addr,AF_INET6);
            }
            else
            {
                rc = sfip_set_raw(ip,((Unified2IDSEventIPv6 *)_event)->ip_destination.s6_addr,AF_INET6);
            }
            if(p && rc != SFIP_SUCCESS)
                return extract_ip_from_packet(ip,p,srcdst_req);
            return rc;
        }
    default:
        return extract_ip_from_packet(ip,p,srcdst_req);
    }
}

#define extract_src_ip(ip,event,event_type,p) \
    extract_ip0(ip,event, event_type, p,SRC_REQ)
#define extract_dst_ip(ip,event,event_type,p) \
    extract_ip0(ip,event, event_type, p,DST_REQ)

static uint8_t extract_proto(const void *_event, uint32_t event_type, Packet *p)
{
    switch(event_type)
    {
    case UNIFIED2_IDS_EVENT:
    case UNIFIED2_IDS_EVENT_VLAN:
        // Share the same structure until protocol ip included
        return ((Unified2IDSEvent *)_event)->protocol;

    case UNIFIED2_IDS_EVENT_IPV6:
    case UNIFIED2_IDS_EVENT_IPV6_VLAN:
        return ((Unified2IDSEventIPv6 *)_event)->protocol;

    default: // Try to extract from the packet
        if(p && IPH_IS_VALID(p))
        {
            return GET_IPH_PROTO(p);
        }
        return 0;
    }
}

static uint16_t extract_port_from_packet(Packet *p,int srcdst_req)
{
    return ntohs(srcdst_req == SRC_REQ ? p->sp : p->dp);
}

static uint16_t extract_port0(const void *_event, uint32_t event_type, Packet *p,int srcdst_req)
{
    if(!(srcdst_req == SRC_REQ || srcdst_req == DST_REQ))
    {
        ErrorMessage("extract_port called with no valid direction.");
        return 0;
    }

    const uint8_t proto = extract_proto(_event,event_type,p);
    if(!(proto == IPPROTO_TCP || proto == IPPROTO_UDP))
    {
        return 0;
    }

    switch(event_type)
    {
    case UNIFIED2_IDS_EVENT:
    case UNIFIED2_IDS_EVENT_VLAN:
        // Share the same structure until ports included
        if(srcdst_req == SRC_REQ)
        {
            return ntohs(((Unified2IDSEvent *)_event)->sport_itype);
        }
        else
        {
            return ntohs(((Unified2IDSEvent *)_event)->dport_icode);
        }

    case UNIFIED2_IDS_EVENT_IPV6:
    case UNIFIED2_IDS_EVENT_IPV6_VLAN:
        // Share the same structure until ports included
        if(srcdst_req == SRC_REQ)
        {
            return ntohs(((Unified2IDSEventIPv6 *)_event)->sport_itype);
        }
        else
        {
            return ntohs(((Unified2IDSEventIPv6 *)_event)->dport_icode);
        }

    default: // Try to extract from the packet
        if(p && IPH_IS_VALID(p))
            return extract_port_from_packet(p,srcdst_req);
        return 0;
    }
}

#define extract_src_port(event,event_type,packet) \
    extract_port0(event,event_type,packet,SRC_REQ)
#define extract_dst_port(event,event_type,packet) \
    extract_port0(event,event_type,packet,DST_REQ)

static uint16_t extract_icmp_type(const void *_event, uint32_t event_type, Packet *p, int *okp)
{
    const uint8_t proto = extract_proto(_event,event_type,p);
    if(!(proto == IPPROTO_ICMP))
    {
        if(okp)
            *okp = 0;
        return 0;
    }

    if(okp)
        *okp = 1;
    switch(event_type)
    {
    case UNIFIED2_IDS_EVENT:
    case UNIFIED2_IDS_EVENT_VLAN:
        // Share the same structure until ports included
        return ntohs(((Unified2IDSEvent *)_event)->sport_itype);

    case UNIFIED2_IDS_EVENT_IPV6:
    case UNIFIED2_IDS_EVENT_IPV6_VLAN:
        // Share the same structure until ports included
        return ntohs(((Unified2IDSEventIPv6 *)_event)->sport_itype);

    default: // Try to extract from the packet
        if(p && IPH_IS_VALID(p) && p->icmph)
            return p->icmph->type;
        return 0;
    }
}

static uint16_t extract_icmp_code(const void *_event, uint32_t event_type, Packet *p, int *okp)
{
    const uint8_t proto = extract_proto(_event,event_type,p);
    if(!(proto == IPPROTO_ICMP))
    {
        if(okp)
            *okp = 0;
        return 0;
    }

    if(okp)
        *okp = 1;
    switch(event_type)
    {
    case UNIFIED2_IDS_EVENT:
    case UNIFIED2_IDS_EVENT_VLAN:
        // Share the same structure until ports included
        return ntohs(((Unified2IDSEvent *)_event)->dport_icode);

    case UNIFIED2_IDS_EVENT_IPV6:
    case UNIFIED2_IDS_EVENT_IPV6_VLAN:
        // Share the same structure until ports included
        return ntohs(((Unified2IDSEventIPv6 *)_event)->dport_icode);

    default: // Try to extract from the packet
        if(p && IPH_IS_VALID(p) && p->icmph)
            return p->icmph->code;
        return 0;
    }
}

static uint16_t extract_vlan_id(const void *_event, uint32_t event_type, Packet *p, int *okp)
{
    switch(event_type)
    {
    case UNIFIED2_IDS_EVENT_VLAN:
        // Share the same structure until ports included
        if(okp)
            *okp = 1;
        return ntohs(((Unified2IDSEvent *)_event)->vlanId);
    case UNIFIED2_IDS_EVENT_IPV6_VLAN:
        // Share the same structure until ports included
        if(okp)
            *okp = 1;
        return ntohs(((Unified2IDSEventIPv6 *)_event)->vlanId);

    case UNIFIED2_IDS_EVENT:
    case UNIFIED2_IDS_EVENT_IPV6:
    default: // Try to extract from the packet
        if(p && IPH_IS_VALID(p) && p->vh)
        {
            if(okp)
                *okp = 1;
            return VTH_VLAN(p->vh);
        }
        if(okp)
            okp = 0;
        return 0;
    }
}

#ifdef HAVE_GEOIP
#define RETURN_COUNTRY_CODE 0
#define RETURN_COUNTRY_LONG 1
static const char *extract_country0(AlertJSONData *jsonData,const sfip_t *ip, int format)
{
    const char *country_name = NULL;

    if(NULL == ip)
    {
        ErrorMessage("extract_country called with ip==NULL");
        return NULL;
    }

    if(!(format == RETURN_COUNTRY_CODE || format == RETURN_COUNTRY_LONG))
    {
        ErrorMessage("extract_country called with unknown format");
        return NULL;
    }

    if(sfip_family(ip) == AF_INET && jsonData->gi)
    {
        if(format == RETURN_COUNTRY_CODE)
            country_name = GeoIP_country_code_by_ipnum(jsonData->gi,ntohl(ip->ip32[0]));
        else
            country_name = GeoIP_country_name_by_ipnum(jsonData->gi,ntohl(ip->ip32[0]));
    }
#ifdef SUP_IP6
    else if(sfip_family(ip) == AF_INET6 && jsonData->gi6)
    {
        geoipv6_t ipv6;
        memcpy(ipv6.s6_addr, ip->ip8, sizeof(ipv6.s6_addr));
        if(format == RETURN_COUNTRY_CODE)
            country_name = GeoIP_country_code_by_ipnum_v6(jsonData->gi6,ipv6);
        else
            country_name = GeoIP_country_name_by_ipnum_v6(jsonData->gi6,ipv6);
    }
#endif

    return country_name;
}

#define extract_country(jsonData,ip)      extract_country0(jsonData,ip,RETURN_COUNTRY_LONG)
#define extract_country_code(jsonData,ip) extract_country0(jsonData,ip,RETURN_COUNTRY_CODE)

static char *extract_AS(AlertJSONData *jsonData,const sfip_t *ip)
{
    char *as = NULL;

    if(NULL == ip)
    {
        ErrorMessage("extract_AS called with ip==NULL");
        return NULL;
    }

    if(sfip_family(ip) == AF_INET && jsonData->gi_org)
    {
        as = GeoIP_name_by_ipnum(jsonData->gi_org,ntohl(ip->ip32[0]));
    }
#ifdef SUP_IP6
    else if(sfip_family(ip) == AF_INET6 && jsonData->gi6_org)
    {
        geoipv6_t ipv6;
        memcpy(ipv6.s6_addr, ip->ip8, sizeof(ipv6.s6_addr));
        as = GeoIP_name_by_ipnum_v6(jsonData->gi6_org,ipv6);
    }
#endif

    return as;
}

#endif

#ifdef RB_EXTRADATA
static int printElementExtraDataBlob(AlertJSONTemplateElement *templateElement, 
    struct printbuf *printbuf, Unified2ExtraData *U2ExtraData)
{
    uint32_t    event_info;     /* type in Unified2 Event */
    const char  *str;
    int         len;

    event_info = ntohl(U2ExtraData->type);

    switch (templateElement->id)
    {
        case SHA256:
            if (event_info == EVENT_INFO_FILE_SHA256)
            {
                const uint8_t *sha_str = (uint8_t *)(U2ExtraData+1);
                len = (int) (ntohl(U2ExtraData->blob_length) - sizeof(U2ExtraData->data_type) - sizeof(U2ExtraData->blob_length));

                uint16_t i;
                char buf[sizeof "00"];
                const size_t bufLen = sizeof buf;
                if(sha_str && len>0)
                    for(i=0; i<len; ++i)
                        printbuf_memappend_fast_str(printbuf, itoa16(sha_str[i],buf,bufLen));
                else
                    printbuf_memappend_fast_str(printbuf, templateElement->defaultValue);
            }
            break;
        case FILE_SIZE:
            if (event_info == EVENT_INFO_FILE_SIZE)
            {
                str = (char *)(U2ExtraData+1);
                len = (int) (ntohl(U2ExtraData->blob_length) - sizeof(U2ExtraData->data_type) - sizeof(U2ExtraData->blob_length));
                printbuf_memappend_fast(printbuf, str, len);
            }
            break;
        case FILE_URI:
            if (event_info == EVENT_INFO_FILE_NAME)
            {
                str = (char *)(U2ExtraData+1);
                len = (int) (ntohl(U2ExtraData->blob_length) - sizeof(U2ExtraData->data_type) - sizeof(U2ExtraData->blob_length));
                printbuf_memappend_fast(printbuf, str, len);
            }
            break;
        case FILE_HOSTNAME:
            if (event_info == EVENT_INFO_FILE_HOSTNAME)
            {
                str = (char *)(U2ExtraData+1);
                len = (int) (ntohl(U2ExtraData->blob_length) - sizeof(U2ExtraData->data_type) - sizeof(U2ExtraData->blob_length));
                printbuf_memappend_fast(printbuf, str, len);
            }
            break;
        case EMAIL_SENDER:
            if (event_info == EVENT_INFO_FILE_MAILFROM)
            {
                str = (char *)(U2ExtraData+1);
                len = (int) (ntohl(U2ExtraData->blob_length) - sizeof(U2ExtraData->data_type) - sizeof(U2ExtraData->blob_length));
                printbuf_memappend_fast(printbuf, str, len);
            }
            break;
        case EMAIL_DESTINATIONS:
            if (event_info == EVENT_INFO_FILE_RCPTTO)
            {
                str = (char *)(U2ExtraData+1);
                len = (int) (ntohl(U2ExtraData->blob_length) - sizeof(U2ExtraData->data_type) - sizeof(U2ExtraData->blob_length));
                printbuf_memappend_fast(printbuf, str, len);
            }
            break;

        case FTP_USER:
            if (event_info == EVENT_INFO_FTP_USER)
            {
                str = (char *)(U2ExtraData+1);
                len = (int) (ntohl(U2ExtraData->blob_length) - sizeof(U2ExtraData->data_type) - sizeof(U2ExtraData->blob_length));
                printbuf_memappend_fast(printbuf, str, len);
            }
            break;


        /*
        case EMAIL_HEADERS:
            if (event_info == EVENT_INFO_FILE_MAILHEADERS)
            {
                str = (char *)(U2ExtraData+1);
                len = (int) (ntohl(U2ExtraData->blob_length) - sizeof(U2ExtraData->data_type) - sizeof(U2ExtraData->blob_length));
                printbuf_memappend_fast(printbuf, str, len);
            }
            break;
        */
        default:
            LogMessage("WARNING: printElementExtraDataBlob(): JSON Element ID inconsistent (%d)\n", templateElement->id);
            break;
    }

    return 0;
}

static int printElementExtraData(void *event, uint32_t event_type, 
    AlertJSONTemplateElement *templateElement, struct printbuf *printbuf)
{
    uint32_t                event_data_type;        /* datatype in Unified2 Event*/
    ExtraDataRecordNode     *edrnCurrent = NULL;
    Unified2ExtraData       *U2ExtraData;
    ExtraDataRecordCache    *extra_data_cache;

    switch (event_type)
    {
        case UNIFIED2_IDS_EVENT:
            extra_data_cache = &(((Unified2IDSEvent_legacy_WithPED *)(event))->extra_data_cache);
            break;
        case UNIFIED2_IDS_EVENT_MPLS:
        case UNIFIED2_IDS_EVENT_VLAN:
            extra_data_cache = &(((Unified2IDSEvent_WithPED *)(event))->extra_data_cache);
            break;
        case UNIFIED2_IDS_EVENT_IPV6:
            extra_data_cache = &(((Unified2IDSEventIPv6_legacy_WithPED *)(event))->extra_data_cache);
            break;
        case UNIFIED2_IDS_EVENT_IPV6_MPLS:
        case UNIFIED2_IDS_EVENT_IPV6_VLAN:
            extra_data_cache = &(((Unified2IDSEventIPv6_WithPED *)(event))->extra_data_cache);
            break;
        default:
            extra_data_cache = NULL;
            LogMessage("WARNING: printElementExtraData(): event_type inconsistent (%d)\n", event_type);
            break;
    }

    if (extra_data_cache == NULL)
        return 0;

    TAILQ_FOREACH(edrnCurrent, extra_data_cache, entry)
    {
        U2ExtraData = (Unified2ExtraData *)(((Unified2ExtraDataHdr *)edrnCurrent->data)+1);
        event_data_type = ntohl(U2ExtraData->data_type);

        if (event_data_type == EVENT_DATA_TYPE_BLOB)
            printElementExtraDataBlob(templateElement, printbuf, U2ExtraData);
    }

    return 0;
}
#endif

/*
 * Function: PrintElementWithTemplate(Packet *, char *, FILE *, char *, numargs const int)
 *
 * Purpose: Write a user defined JSON element.
 *
 * Arguments:               p => packet. (could be NULL)
 *                      event => event that cause the alarm.
 *                 event_type => event type.
 *                   jsonData => main plugin data.
 *            templateElement => template element with format.
 * Returns: 0 if nothing writed to jsonData. !=0 otherwise.
 *
 */
static int printElementWithTemplate(Packet *p, void *event, uint32_t event_type, 
        AlertJSONData *jsonData, AlertJSONTemplateElement *templateElement,
        struct printbuf *printbuf)
{
    SigNode *sn;
    char tcpFlags[9];
    char buf[sizeof "0000:0000:0000:0000:0000:0000:0000:0000"];
    const size_t bufLen = sizeof buf;
    const char * str_aux=NULL;

    sfip_t ip;
    sfip_clear(&ip);
    const int initial_buffer_pos = printbuf->bpos;

    /* Avoid repeated code */
    switch(templateElement->id){
        case SRC_TEMPLATE_ID:
        case SRC_STR:
        case SRC_NAME:
        case SRC_NET:
        case SRC_NET_NAME:
#ifdef HAVE_GEOIP
        case SRC_COUNTRY:
        case SRC_COUNTRY_CODE:
        case SRC_AS:
        case SRC_AS_NAME:
#endif
            extract_src_ip(&ip,event,event_type,p);
            break;

        case DST_TEMPLATE_ID:
        case DST_STR:
        case DST_NAME:
        case DST_NET:
        case DST_NET_NAME:
#ifdef HAVE_GEOIP
        case DST_COUNTRY:
        case DST_COUNTRY_CODE:
        case DST_AS:
        case DST_AS_NAME:
#endif
            extract_dst_ip(&ip,event,event_type,p);
            break;

        default:
            break;
    };

    #ifdef DEBUG
    if(NULL==templateElement) FatalError("TemplateElement was not setted (File %s line %d)\n.",__FILE__,__LINE__);
    #endif
    switch(templateElement->id){
        case TIMESTAMP:
            printbuf_memappend_fast_str(printbuf,itoa10(ntohl(((Unified2EventCommon *)event)->event_second), buf, bufLen));
            break;
        case SENSOR_ID_SNORT:
            printbuf_memappend_fast_str(printbuf,event?itoa10(ntohl(((Unified2EventCommon *)event)->sensor_id),buf, bufLen):templateElement->defaultValue);
            break;
        case ACTION:
            if((str_aux = actionOfEvent(event,event_type)))
                printbuf_memappend_fast_str(printbuf,str_aux);
            break;
        case SIG_GENERATOR:
            if(event != NULL)
                printbuf_memappend_fast_str(printbuf,itoa10(ntohl(((Unified2EventCommon *)event)->generator_id),buf,bufLen));
            break;
        case SIG_ID:
            if(event != NULL)
                printbuf_memappend_fast_str(printbuf,itoa10(ntohl(((Unified2EventCommon *)event)->signature_id),buf,bufLen));
            break;
        case SIG_REV:
            if(event != NULL)
                printbuf_memappend_fast_str(printbuf,itoa10(ntohl(((Unified2EventCommon *)event)->signature_revision),buf,bufLen));
            break;
        case PRIORITY:
            if(event != NULL){
                const int priority_id = ntohl(((Unified2EventCommon *)event)->priority_id);
                const char *prio_name = NULL;
                if(priority_id < sizeof(priority_name)/sizeof(priority_name[0])) 
                    prio_name = priority_name[priority_id];
                printbuf_memappend_fast_str(printbuf,prio_name ? prio_name : templateElement->defaultValue);
            }
            break;
        case CLASSIFICATION:
            if(event != NULL)
            {
                uint32_t classification_id = ntohl(((Unified2EventCommon *)event)->classification_id);
                const ClassType *cn = ClassTypeLookupById(barnyard2_conf, classification_id);
                printbuf_memappend_fast_str(printbuf,cn?cn->name:templateElement->defaultValue);
            }else{ /* Always log something */
                printbuf_memappend_fast_str(printbuf, templateElement->defaultValue);
            }
            break;
        case MSG:
            if ( event != NULL )
            {
                sn = GetSigByGidSid(ntohl(((Unified2EventCommon *)event)->generator_id),
                    ntohl(((Unified2EventCommon *)event)->signature_id),
                    ntohl(((Unified2EventCommon *)event)->signature_revision));

                if (sn != NULL)
                {
                    //const int msglen = strlen(sn->msg);
                    printbuf_memappend_fast_str(printbuf,sn->msg);
                }
            }
            break;
#ifdef RB_EXTRADATA
        case SHA256:
        case FILE_SIZE:
        case FILE_URI:
        case FILE_HOSTNAME:
        case EMAIL_SENDER:
        case EMAIL_DESTINATIONS:
        case FTP_USER:
        //case EMAIL_HEADERS:
            if (event != NULL)
                printElementExtraData(event, event_type, templateElement, printbuf);
            break;
#endif
        case PAYLOAD:
            {
                /* Sending packet payload (Packet->data) inside kafka message, instead of
                   raw packet data (Packet->pkt). See Packet structure in decode.h file.
                   Please take into account that snort.log.<timestamp> files contains
                   the raw packet data, not packet payload, so they won't match. */
                uint16_t i;
                if(p &&  p->dsize>0){
                    for(i=0;i<p->dsize;++i)
                        printbuf_memappend_fast_str(printbuf, itoa16(p->data[i],buf,bufLen));
                }else{
                    printbuf_memappend_fast_str(printbuf, templateElement->defaultValue);
                }
            }
            break;

        case PROTO:
            {
                const uint16_t proto = extract_proto(event,event_type,p);
                Number_str_assoc * service_name_asoc = SearchNumberStr(proto,jsonData->protocols);
                if(service_name_asoc){
                    printbuf_memappend_fast_str(printbuf,service_name_asoc->human_readable_str);
                    break;
                }
            }
            /* don't break! Print, at least, proto_id*/
        case PROTO_ID:
            {
                const uint16_t proto = extract_proto(event,event_type,p);
                printbuf_memappend_fast_str(printbuf,itoa10(proto,buf,bufLen));
            }

            break;

        case ETHSRC:
            if(p && p->eh)
                printHWaddr(printbuf, p->eh->ether_src, buf,bufLen);
            break;

        case ETHDST:
            if(p && p->eh)
                printHWaddr(printbuf,p->eh->ether_dst,buf,bufLen);
            break;

#ifdef HAVE_RB_MAC_VENDORS
        case ETHSRC_VENDOR:
            if(p && p->eh && jsonData->eth_vendors_db)
            {
                const char * vendor = rb_find_mac_vendor(HWADDR_vectoi(p->eh->ether_src),jsonData->eth_vendors_db);
                if(vendor)
                    printbuf_memappend_fast_str(printbuf,vendor);
            }
            break;
        case ETHDST_VENDOR:
            if(p && p->eh && jsonData->eth_vendors_db)
            {
                const char * vendor = rb_find_mac_vendor(HWADDR_vectoi(p->eh->ether_dst),jsonData->eth_vendors_db);
                if(vendor)
                    printbuf_memappend_fast_str(printbuf,vendor);
            }
            break;
#endif

        case ARP_HW_SADDR:
            if(p && p->ah)
                printHWaddr(printbuf,p->ah->arp_sha,buf,bufLen);
            break;
        case ARP_HW_SPROT:
            if(p && p->ah)
            {
                printbuf_memappend_fast_str(printbuf, "0x");
                printbuf_memappend_fast_str(printbuf, itoa16(p->ah->arp_spa[0],buf,bufLen));
                printbuf_memappend_fast_str(printbuf, itoa16(p->ah->arp_spa[1],buf,bufLen));
                printbuf_memappend_fast_str(printbuf, itoa16(p->ah->arp_spa[2],buf,bufLen));
                printbuf_memappend_fast_str(printbuf, itoa16(p->ah->arp_spa[3],buf,bufLen));
            }
            break;
        case ARP_HW_TADDR:
            if(p && p->ah)
                printHWaddr(printbuf,p->ah->arp_tha,buf,bufLen);
            break;
        case ARP_HW_TPROT:
            if(p && p->ah)
            {
                printbuf_memappend_fast_str(printbuf, "0x");
                printbuf_memappend_fast_str(printbuf, itoa16(p->ah->arp_tpa[0],buf,bufLen));
                printbuf_memappend_fast_str(printbuf, itoa16(p->ah->arp_tpa[1],buf,bufLen));
                printbuf_memappend_fast_str(printbuf, itoa16(p->ah->arp_tpa[2],buf,bufLen));
                printbuf_memappend_fast_str(printbuf, itoa16(p->ah->arp_tpa[3],buf,bufLen));
            }
            break;

        case ETHTYPE:
            if(p && p->eh)
            {
                printbuf_memappend_fast_str(printbuf, itoa10(ntohs(p->eh->ether_type),buf,bufLen));
            }
            break;

        case UDPLENGTH:
            if(p && p->udph){
                printbuf_memappend_fast_str(printbuf, itoa10(ntohs(p->udph->uh_len),buf,bufLen));
            }
            break;
        case ETHLENGTH:
            if(p && p->eh){
                printbuf_memappend_fast_str(printbuf, itoa10(p->pkth->len,buf,bufLen));
            }
            break;

        case ETHLENGTH_RANGE:
            if(p && p->eh){
                if(p->pkth->len==0)
                    printbuf_memappend_fast_str(printbuf, "0");
                if(p->pkth->len<=64)
                    printbuf_memappend_fast_str(printbuf, "(0-64]");
                else if(p->pkth->len<=128)
                    printbuf_memappend_fast_str(printbuf, "(64-128]");
                else if(p->pkth->len<=256)
                    printbuf_memappend_fast_str(printbuf, "(128-256]");
                else if(p->pkth->len<=512)
                    printbuf_memappend_fast_str(printbuf, "(256-512]");
                else if(p->pkth->len<=768)
                    printbuf_memappend_fast_str(printbuf, "(512-768]");
                else if(p->pkth->len<=1024)
                    printbuf_memappend_fast_str(printbuf, "(768-1024]");
                else if(p->pkth->len<=1280)
                    printbuf_memappend_fast_str(printbuf, "(1024-1280]");
                else if(p->pkth->len<=1514)
                    printbuf_memappend_fast_str(printbuf, "(1280-1514]");
                else if(p->pkth->len<=2048)
                    printbuf_memappend_fast_str(printbuf, "(1514-2048]");
                else if(p->pkth->len<=4096)
                    printbuf_memappend_fast_str(printbuf, "(2048-4096]");
                else if(p->pkth->len<=8192)
                    printbuf_memappend_fast_str(printbuf, "(4096-8192]");
                else if(p->pkth->len<=16384)
                    printbuf_memappend_fast_str(printbuf, "(8192-16384]");
                else if(p->pkth->len<=32768)
                    printbuf_memappend_fast_str(printbuf, "(16384-32768]");
                else
                    printbuf_memappend_fast_str(printbuf, ">32768");
            }
            break;

        case VLAN_PRIORITY:
            if(p && p->vh)
                printbuf_memappend_fast_str(printbuf,itoa10(VTH_PRIORITY(p->vh),buf,bufLen));
            break;
        case VLAN_DROP:
            if(p && p->vh)
                printbuf_memappend_fast_str(printbuf,itoa10(VTH_CFI(p->vh),buf,bufLen));
            break;
        case VLAN:
            {
                int ok;
                const uint16_t vlan = extract_vlan_id(event, event_type, p, &ok);
                if(ok)
                    printbuf_memappend_fast_str(printbuf,itoa10(vlan,buf,bufLen));
            }
            break;
        case VLAN_NAME:
            {
                int ok;
                const uint16_t vlan = extract_vlan_id(event, event_type, p, &ok);
                if(ok)
                {
                    const Number_str_assoc * vlan_str = SearchNumberStr(vlan,jsonData->vlans);
                    if(vlan_str)
                        printbuf_memappend_fast_str(printbuf,vlan_str->human_readable_str);
                    else
                        printbuf_memappend_fast_str(printbuf,itoa10(vlan,buf,bufLen));
                }
            }
            break;

        case SRCPORT_NAME:
        case DSTPORT_NAME:
            {
                const uint16_t port = templateElement->id==SRCPORT_NAME? 
                    extract_src_port(event, event_type, p)
                    :extract_dst_port(event, event_type, p);
                Number_str_assoc * service_name_asoc = SearchNumberStr(port,jsonData->services);

                if(port!=0)
                {
                    if(service_name_asoc)
                        printbuf_memappend_fast_str(printbuf,service_name_asoc->human_readable_str);
                    else /* Log port number */
                        printbuf_memappend_fast_str(printbuf,itoa10(port,buf,bufLen));
                }
            }
            break;

        case SRCPORT:
        case DSTPORT:
            {
                const uint16_t port = templateElement->id==SRCPORT? 
                    extract_src_port(event, event_type, p)
                    :extract_dst_port(event, event_type, p);

                if(port!=0)
                    printbuf_memappend_fast_str(printbuf,itoa10(port,buf,bufLen));
            }
            break;

        case SRC_TEMPLATE_ID:
        case DST_TEMPLATE_ID:
            /*if(sfip_family(&ip)==AF_INET){ // buggy sfip_family macro...*/
            if(ip.family==AF_INET)
            {
                printbuf_memappend_fast_str(printbuf,itoa10(*ip.ip32, buf,bufLen));
            }
            /* doesn't make very sense print so large number. If you want, make me know. */
            break;
        case SRC_STR:
        case DST_STR:
            {
                printbuf_memappend_fast_str(printbuf,sfip_to_str(&ip));
            }
            break;
        case SRC_NAME:
        case DST_NAME:
            {
                Number_str_assoc * ip_str_node = SearchIpStr(ip,jsonData->hosts,HOSTS);
                const char * ip_name = ip_str_node ? ip_str_node->human_readable_str : sfip_to_str(&ip);
                printbuf_memappend_fast_str(printbuf,ip_name);
            }
            break;
        case SRC_NET:
        case DST_NET:
            {
                Number_str_assoc *ip_net = SearchIpStr(ip,jsonData->nets,NETWORKS);
                if(ip_net)
                    printbuf_memappend_fast_str(printbuf,ip_net->number_as_str);
            }
            break;
        case SRC_NET_NAME:
        case DST_NET_NAME:
            {
                Number_str_assoc *ip_net = SearchIpStr(ip,jsonData->nets,NETWORKS);
                if(ip_net)
                    printbuf_memappend_fast_str(printbuf,ip_net->human_readable_str);
            }
            break;

#ifdef HAVE_GEOIP
        case SRC_COUNTRY:
        case DST_COUNTRY:
            {
                const char * country_name = extract_country(jsonData,&ip);
                if(country_name)
                    printbuf_memappend_fast_str(printbuf,country_name);
            }
            break;

        case SRC_COUNTRY_CODE:
        case DST_COUNTRY_CODE:
            if(jsonData->gi){
                const char * country_code = extract_country_code(jsonData,&ip);
                if(country_code)
                    printbuf_memappend_fast_str(printbuf,country_code);
            }
            break;

        case SRC_AS:
        case DST_AS:
            {
                char *as_name = extract_AS(jsonData,&ip);
                if(as_name)
                {
                    const char *space = strchr(as_name,' ');
                    if(space)
                        printbuf_memappend_fast(printbuf,as_name+2,space - &as_name[2]);
                    free(as_name);
                }
            }
            break;

        case SRC_AS_NAME:
        case DST_AS_NAME:
            {
                char *as_name = extract_AS(jsonData,&ip);
                if(as_name)
                {
                    const char * space = strchr(as_name,' ');
                    if(space)
                        printbuf_memappend_fast_str(printbuf,space+1);
                    free(as_name);
                }
            }
            break;

#endif /* HAVE_GEOIP */

        case ICMPTYPE:
            {
                int ok;
                const uint16_t itype = extract_icmp_type(event,event_type,p,&ok);
                if(ok)
                    printbuf_memappend_fast_str(printbuf, itoa10(itype,buf,bufLen));
            }
            break;
        case ICMPCODE:
            {
                int ok;
                const uint16_t icode = extract_icmp_code(event,event_type,p,&ok);
                if(ok)
                    printbuf_memappend_fast_str(printbuf, itoa10(icode,buf,bufLen));
            }
            break;
        case ICMPID:
            if(p && p->icmph)
                printbuf_memappend_fast_str(printbuf, itoa10(ntohs(p->icmph->s_icmp_id),buf,bufLen));
            break;
        case ICMPSEQ:
            if(p && p->icmph){
                /* Doesn't work because "%d" arbitrary
                    PrintJSONFieldName(kafka,JSON_ICMPSEQ_NAME);
                    KafkaLog_Print(kafka, "%d",ntohs(p->icmph->s_icmp_seq));
                */
                printbuf_memappend_fast_str(printbuf,itoa10(ntohs(p->icmph->s_icmp_seq),buf,bufLen));
            }
            break;
        case TTL:
            if(p && IPH_IS_VALID(p))
                printbuf_memappend_fast_str(printbuf,itoa10(GET_IPH_TTL(p),buf,bufLen));
            break;

        case TOS: 
            if(p && IPH_IS_VALID(p))
                printbuf_memappend_fast_str(printbuf,itoa10(GET_IPH_TOS(p),buf,bufLen));
            break;
        case ID:
            if(p && IPH_IS_VALID(p))
                printbuf_memappend_fast_str(printbuf,itoa10(IS_IP6(p) ? ntohl(GET_IPH_ID(p)) : ntohs((u_int16_t)GET_IPH_ID(p)),buf,bufLen));
            break;
        case IPLEN:
            if(p && IPH_IS_VALID(p))
                printbuf_memappend_fast_str(printbuf,itoa10(ntohs(GET_IPH_LEN(p)),buf,bufLen));
            break;
        case IPLEN_RANGE:
            if(p && IPH_IS_VALID(p))
            {
                const double log2_len = log2(ntohs(GET_IPH_LEN(p)));
                const unsigned int lower_limit = pow(2.0,floor(log2_len));
                const unsigned int upper_limit = pow(2.0,ceil(log2_len));
                //printf("log2_len: %0lf; floor: %0lf; ceil: %0lf; low_limit: %0lf; upper_limit:%0lf\n",
                //    log2_len,floor(log2_len),ceil(log2_len),pow(floor(log2_len),2.0),pow(ceil(log2_len),2));
                sprintbuf(printbuf,"[%u-%u)",lower_limit,upper_limit);
                //printf(kafka,"[%lf-%lf)\n",lower_limit,upper_limit);
            }
            break;
        case DGMLEN:
            if(p && IPH_IS_VALID(p)){
                // XXX might cause a bug when IPv6 is printed?
                printbuf_memappend_fast_str(printbuf, itoa10(ntohs(GET_IPH_LEN(p)),buf,bufLen));
            }
            break;

        case TCPSEQ:
            if(p && p->tcph){
                // KafkaLog_Print(kafka, "lX%0x",(u_long) ntohl(p->tcph->th_ack)); // hex format
                printbuf_memappend_fast_str(printbuf,itoa10(ntohl(p->tcph->th_seq),buf,bufLen));
            }
            break;
        case TCPACK:
            if(p && p->tcph){
                // KafkaLog_Print(kafka, "0x%lX",(u_long) ntohl(p->tcph->th_ack));
                printbuf_memappend_fast_str(printbuf,itoa10(ntohl(p->tcph->th_ack),buf,bufLen));
            }
            break;
        case TCPLEN:
            if(p && p->tcph){
                printbuf_memappend_fast_str(printbuf, itoa10(TCP_OFFSET(p->tcph) << 2,buf,bufLen));
            }
            break;
        case TCPWINDOW:
            if(p && p->tcph){
                //KafkaLog_Print(kafka, "0x%X",ntohs(p->tcph->th_win));  // hex format
                printbuf_memappend_fast_str(printbuf,itoa10(ntohs(p->tcph->th_win),buf,bufLen));
            }
            break;
        case TCPFLAGS:
            if(p && p->tcph)
            {
                CreateTCPFlagString(p, tcpFlags);
                printbuf_memappend_fast_str(printbuf, tcpFlags);
            }
            break;

        default:
            FatalError("Template %s(%d) not found\n",templateElement->templateName,templateElement->id);
            break;
    };

    return printbuf->bpos-initial_buffer_pos; /* if we have write something */
}

/*
 * Function: RealAlertJSON(Packet *, char *, FILE *, char *, numargs const int)
 *
 * Purpose: Write a user defined JSON message
 *
 * Arguments:         p => packet. (could be NULL)
 *                event => event.
 *           event_type => event type
 *            json_data => plugin main data
 * Returns: void function
 *
 */
static void RealAlertJSON(Packet * p, void *event, uint32_t event_type, AlertJSONData * jsonData)
{
    TemplateElement * iter;

    RefcntPrintbuf *rprintbuf = calloc(1,sizeof(*rprintbuf));
    if(NULL == rprintbuf) {
        ErrorMessage("alert_json, (%s:%d): Couldn't allocate (out of memory?)",__FUNCTION__,__LINE__);
        return;
    }

    printbuf_new(&rprintbuf->printbuf);
    struct printbuf *printbuf = &rprintbuf->printbuf;

    // if(p == NULL)
    //     return;

    if(event == NULL)
    {
        ErrorMessage("Lonely packet detected. Please consider increase the cache size.");
        return;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Logging JSON Alert data\n"););
    printbuf_memappend_fast_str(printbuf,"{");
    output_template_foreach(iter,&jsonData->output_template)
    {
        const int initial_pos = printbuf->bpos;
        if (iter!=output_template_first(&jsonData->output_template))
        {
            printbuf_memappend_fast_str(printbuf,JSON_FIELDS_SEPARATOR);
        }

        printbuf_memappend_fast_str(printbuf,"\"");
        printbuf_memappend_fast_str(printbuf,iter->templateElement->jsonName);
        printbuf_memappend_fast_str(printbuf,"\":");

        if(iter->templateElement->printFormat==stringFormat)
            printbuf_memappend_fast_str(printbuf,"\"");
        const int writed = printElementWithTemplate(p,event,event_type,jsonData,iter->templateElement,printbuf);
        if(iter->templateElement->printFormat==stringFormat)
            printbuf_memappend_fast_str(printbuf,"\"");

        if(0==writed)
        {
            rprintbuf->printbuf.bpos = initial_pos;
        }
    }

    if(jsonData->enrich_with)
    {
        printbuf_memappend_fast_str(printbuf,jsonData->enrich_with);
    }

    printbuf_memappend_fast_str(printbuf,"}");
    // Just for debug
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"[alert_json]: %s",printbuf->buf););

    rprintbuf->refcnt = 1;

#ifdef HAVE_LIBRDKAFKA
    if(unlikely(NULL == jsonData->kafka.rk && NULL != jsonData->kafka.brokers))
    {
        /* Still not initialized */
        AlertJsonKafkaDelayedInit(jsonData);
    }

    if(jsonData->kafka.rkt)
    {
        const int produce_rc = rd_kafka_produce(jsonData->kafka.rkt, RD_KAFKA_PARTITION_UA,
                 /* Free/copy flags */
                 0,
                 /* Payload and length */
                 printbuf->buf, printbuf->bpos,
                 /* Optional key and its length */
                 NULL, 0,
                 /* Message opaque, provided in
                  * delivery report callback as
                  * msg_opaque. */
                 rprintbuf);

        if(produce_rc < 0)
        {
            ErrorMessage("alert_json: Failed to produce kafka message: %s",
                rd_kafka_err2str(rd_kafka_errno2err(errno)));
            DecRefcntPrintbuf(rprintbuf);
        }
    }
#endif

#ifdef HAVE_LIBRBHTTP
    if(unlikely(NULL == jsonData->http.handler && NULL != jsonData->http.url))
    {
        /* Still not initialized */
        AlertJsonHTTPDelayedInit(jsonData);
    }

    if(NULL != jsonData->http.handler)
    {
        char err[BUFSIZ];

        const int rc = rb_http_produce (jsonData->http.handler,
            printbuf->buf,printbuf->bpos, 0 /* No flags */,err,sizeof(err),
            rprintbuf);

        if(rc != 0)
        {
            ErrorMessage("alert_json: Failed to produce HTTP message: %s",
                err);
            DecRefcntPrintbuf(rprintbuf);
        }
    }
#endif
}
