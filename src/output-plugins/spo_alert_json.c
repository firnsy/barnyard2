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
 * Arguments: [alert_file]+kafka://<broker>:<port>@<topic>
 *
 * Effect:
 *
 * Alerts are sended to a kafka broker, using the port and topic given, plus to a alert file (if given).
 *
 * Comments: Allows use of json alerts with other output plugin types.
 * See doc/README.alert_json to more details
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* !WIN32 */

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "mstring.h"
#include "util.h"
#include "log.h"
#include "map.h"
#include "unified2.h"

#include "barnyard2.h"

#include "sfutil/sf_textlog.h"
#include "rbutil/rb_kafka.h"
#include "rbutil/rb_numstrpair_list.h"
#include "rbutil/rb_pointers.h"
#include "rbutil/rb_unified2.h"
#include "errno.h"
#include "signal.h"
#include "log_text.h"

#ifdef HAVE_RB_MAC_VENDORS
#include "rb_mac_vendors.h"
#endif

#ifdef HAVE_GEOIP
#include "GeoIP.h"
#endif // HAVE_GEOIP

#ifdef HAVE_LIBRD
#include "librd/rd.h"
#endif

#include "math.h"


// Send object_name or not.
// Note: Always including ,sensor_name,domain_name,group_name,src_net_name,src_as_name,dst_net_name,dst_as_name
//#define SEND_NAMES

#define DEFAULT_JSON_0 "timestamp,sensor_id,type,sensor_name,sensor_ip,domain_name,group_name,group_id,sig_generator,sig_id,sig_rev,priority,classification,action,msg,payload,l4_proto,src,src_net,src_net_name,src_as,src_as_name,dst,dst_net,dst_net_name,dst_as,dst_as_name,l4_srcport,l4_dstport,ethsrc,ethdst,ethlen,ethlength_range,arp_hw_saddr,arp_hw_sprot,arp_hw_taddr,arp_hw_tprot,vlan,vlan_priority,vlan_drop,tcpflags,tcpseq,tcpack,tcplen,tcpwindow,ttl,tos,id,dgmlen,iplen,iplen_range,icmptype,icmpcode,icmpid,icmpseq"

#ifdef HAVE_GEOIP
#define DEFAULT_JSON_1 DEFAULT_JSON_0 ",src_country,dst_country,src_country_code,dst_country_code" /* link with previous string */
#else
#define DEFAULT_JSON_1 DEFAULT_JSON_0
#endif

#ifdef HAVE_RB_MAC_VENDORS
#define DEFAULT_JSON_2 DEFAULT_JSON_1 ",ethsrc_vendor,ethdst_vendor"
#else
#define DEFAULT_JSON_2 DEFAULT_JSON_1
#endif

#ifdef SEND_NAMES
#define DEFAULT_JSON DEFAULT_JSON_2 ",l4_proto_name,src_name,dst_name,l4_srcport_name,l4_dstport_name,vlan_name"
#else
#define DEFAULT_JSON DEFAULT_JSON_2
#endif

#define DEFAULT_FILE  "alert.json"
#define DEFAULT_KAFKA_BROKER "kafka://127.0.0.1@barnyard"
#define DEFAULT_LIMIT (128*M_BYTES)
#define LOG_BUFFER    (30*K_BYTES)

#define KAFKA_PROT "kafka://"
//#define KAFKA_TOPIC "rb_ips"
#define FILENAME_KAFKA_SEPARATOR '+'
#define BROKER_TOPIC_SEPARATOR   '@'

#define FIELD_NAME_VALUE_SEPARATOR ": "
#define JSON_FIELDS_SEPARATOR ", "

/* If you change some of this, remember to change printElementWithTemplate too */
typedef enum{
    TIMESTAMP,
    SENSOR_ID_SNORT,
    SENSOR_ID,
    SENSOR_NAME,
    SENSOR_IP,
    DOMAIN_ID,
    DOMAIN_NAME,
    GROUP_ID,
    GROUP_NAME,
    TYPE,
    SIG_GENERATOR,
    SIG_ID,
    SIG_REV,
    PRIORITY,
    ACTION,
    CLASSIFICATION,
    MSG,
    PAYLOAD,
    PROTO,
    PROTO_ID,
    ETHSRC,
    ETHDST,
#ifdef HAVE_RB_MAC_VENDORS
    ETHSRC_VENDOR,
    ETHDST_VENDOR,
#endif
    ETHTYPE,
    VLAN, /* See vlan header */
    VLAN_NAME,
    VLAN_PRIORITY,
    VLAN_DROP,
    ARP_HW_SADDR, /* Sender ARP Hardware Address */
    ARP_HW_SPROT, /* Sender ARP Hardware Protocol */
    ARP_HW_TADDR, /* Destination ARP Hardware Address */
    ARP_HW_TPROT, /* Destination ARP Hardware Protocol */
    UDPLENGTH,
    ETHLENGTH,
    ETHLENGTH_RANGE,
    TRHEADER,
    SRCPORT,
    DSTPORT,
    SRCPORT_NAME,
    DSTPORT_NAME,
    SRC_TEMPLATE_ID,
    SRC_STR,
    SRC_NAME,
    SRC_NET,
    SRC_NET_NAME,
    DST_TEMPLATE_ID,
    DST_NAME,
    DST_STR,
    DST_NET,
    DST_NET_NAME,
    ICMPTYPE,
    ICMPCODE,
    ICMPID,
    ICMPSEQ,
    TTL,
    TOS,
    ID,
    IPLEN,
    IPLEN_RANGE,
    DGMLEN,
    TCPSEQ,
    TCPACK,
    TCPLEN,
    TCPWINDOW,
    TCPFLAGS,

#ifdef HAVE_GEOIP
    SRC_COUNTRY,
    DST_COUNTRY,
    SRC_COUNTRY_CODE,
    DST_COUNTRY_CODE,
    SRC_AS,
    DST_AS,
    SRC_AS_NAME,
    DST_AS_NAME,
#endif // HAVE_GEOIP

    TEMPLATE_END_ID
}TEMPLATE_ID;

typedef enum{stringFormat,numericFormat} JsonPrintFormat;

typedef struct{
    const TEMPLATE_ID id;
    const char * templateName;
    const char * jsonName;
    const JsonPrintFormat printFormat;
    char * defaultValue;
}  AlertJSONTemplateElement;

typedef struct _TemplateElementsList{
    AlertJSONTemplateElement * templateElement;
    struct _TemplateElementsList * next;
} TemplateElementsList;

typedef struct _AlertJSONConfig{
    char *type;
    struct _AlertJSONConfig *next;
} AlertJSONConfig;

typedef struct _AlertJSONData
{
    KafkaLog * kafka;
    char * jsonargs;
    TemplateElementsList * outputTemplate;
    AlertJSONConfig *config;
    Number_str_assoc * hosts, *nets, *services, *protocols, *vlans;
    uint32_t sensor_id,domain_id,group_id;
    char * sensor_name, *sensor_type,*domain,*sensor_ip,*group_name;
#ifdef HAVE_GEOIP
    GeoIP *gi,*gi_org;
#ifdef SUP_IP6
    GeoIP *gi6,*gi6_org;
#endif /* SUP_IP6 */
#endif /* HAVE_GEOIP */
#ifdef HAVE_RB_MAC_VENDORS
    struct mac_vendor_database *eth_vendors_db;
#endif
} AlertJSONData;

static const char *priority_name[] = {NULL, "high", "medium", "low", "very low"};

/* Remember update printElementWithTemplate if some element modified here */
static AlertJSONTemplateElement template[] = {
    {TIMESTAMP,"timestamp","timestamp",numericFormat,"0"},
    {SENSOR_ID_SNORT,"sensor_id_snort","sensor_id_snort",numericFormat,"0"},
    {SENSOR_ID,"sensor_id","sensor_id",numericFormat,"0"},
    {SENSOR_IP,"sensor_ip","sensor_ip",stringFormat,"0"},
    {SENSOR_NAME,"sensor_name","sensor_name",stringFormat,"-"},
    {DOMAIN_NAME,"domain_name","domain_name",stringFormat,"-"},
 /*   {DOMAIN_ID,"domain_id","domain_id",numericFormat,"-"}, */
    {GROUP_NAME,"group_name","group_name",stringFormat,"-"},
    {GROUP_ID,"group_id","group_id",numericFormat,"-"},
    {TYPE,"type","type",stringFormat,"-"},
    {ACTION,"action","action",stringFormat,"-"},
    {SIG_GENERATOR,"sig_generator","sig_generator",numericFormat,"0"},
    {SIG_ID,"sig_id","sig_id",numericFormat,"0"},
    {SIG_REV,"sig_rev","rev",numericFormat,"0"},
    {PRIORITY,"priority","priority",stringFormat,"unknown"},
    {CLASSIFICATION,"classification","classification",stringFormat,"-"},
    {MSG,"msg","msg",stringFormat,"-"},
    {PAYLOAD,"payload","payload",stringFormat,"-"},
    {PROTO,"l4_proto_name","l4_proto_name",stringFormat,"-"},
    {PROTO_ID,"l4_proto","l4_proto",numericFormat,"0"},
    {ETHSRC,"ethsrc","ethsrc",stringFormat,"-"},
    {ETHDST,"ethdst","ethdst",stringFormat,"-"},
#ifdef HAVE_RB_MAC_VENDORS
    {ETHSRC_VENDOR,"ethsrc_vendor","ethsrc_vendor",stringFormat,"-"},
    {ETHDST_VENDOR,"ethdst_vendor","ethdst_vendor",stringFormat,"-"},
#endif
    {ETHTYPE,"ethtype","ethtype",numericFormat,"0"},
    {ARP_HW_SADDR,"arp_hw_saddr","arp_hw_saddr",stringFormat,"-"},
    {ARP_HW_SPROT,"arp_hw_sprot","arp_hw_sprot",stringFormat,"-"},
    {ARP_HW_TADDR,"arp_hw_taddr","arp_hw_taddr",stringFormat,"-"},
    {ARP_HW_TPROT,"arp_hw_tprot","arp_hw_tprot",stringFormat,"-"},
    {VLAN,"vlan","vlan",numericFormat,"0"},
    {VLAN_NAME,"vlan_name","vlan_name",stringFormat,"0"},
    {VLAN_PRIORITY,"vlan_priority","vlan_priority",numericFormat,"0"},
    {VLAN_DROP,"vlan_drop","vlan_drop",numericFormat,"0"},
    {UDPLENGTH,"udplength","udplength",numericFormat,"0"},
    {ETHLENGTH,"ethlen","ethlength",numericFormat,"0"},
    {ETHLENGTH_RANGE,"ethlength_range","ethlength_range",stringFormat,"0"},
    {TRHEADER,"trheader","trheader",stringFormat,"-"},
    {SRCPORT,"l4_srcport","src_port",numericFormat,"0"},
    {SRCPORT_NAME,"l4_srcport_name","src_port_name",stringFormat,"-"},
    {DSTPORT,"l4_dstport","dst_port",numericFormat,"0"},
    {DSTPORT_NAME,"l4_dstport_name","dst_port_name",stringFormat,"-"},
    {SRC_TEMPLATE_ID,"src_asnum","src_asnum",numericFormat,"0"}, 
    {SRC_STR,"src","src",stringFormat,"-"},
    {SRC_NAME,"src_name","src_name",stringFormat,"-"},
    {SRC_NET,"src_net","src_net",stringFormat,"0.0.0.0/0"},
    {SRC_NET_NAME,"src_net_name","src_net_name",stringFormat,"0.0.0.0/0"},
    {DST_TEMPLATE_ID,"dst_asnum","dst_asnum",stringFormat,"0"}, 
    {DST_NAME,"dst_name","dst_name",stringFormat,"-"},
    {DST_STR,"dst","dst",stringFormat,"-"},
    {DST_NET,"dst_net","dst_net",stringFormat,"0.0.0.0/0"},
    {DST_NET_NAME,"dst_net_name","dst_net_name",stringFormat,"0.0.0.0/0"},
    {ICMPTYPE,"icmptype","icmptype",numericFormat,"0"},
    {ICMPCODE,"icmpcode","icmpcode",numericFormat,"0"},
    {ICMPID,"icmpid","icmpid",numericFormat,"0"},
    {ICMPSEQ,"icmpseq","icmpseq",numericFormat,"0"},
    {TTL,"ttl","ttl",numericFormat,"0"},
    {TOS,"tos","tos",numericFormat,"0"},
    {ID,"id","id",numericFormat,"0"},
    {IPLEN,"iplen","iplen",numericFormat,"0"},
    {IPLEN_RANGE,"iplen_range","iplen_range",stringFormat,"0"},
    {DGMLEN,"dgmlen","dgmlen",numericFormat,"0"},
    {TCPSEQ,"tcpseq","tcpseq",numericFormat,"0"},
    {TCPACK,"tcpack","tcpack",numericFormat,"0"},
    {TCPLEN,"tcplen","tcplen",numericFormat,"0"},
    {TCPWINDOW,"tcpwindow","tcpwindow",numericFormat,"0"},
    {TCPFLAGS,"tcpflags","tcpflags",stringFormat,"-"},
    #ifdef HAVE_GEOIP
    {SRC_COUNTRY,"src_country","src_country",stringFormat,"N/A"},
    {DST_COUNTRY,"dst_country","dst_country",stringFormat,"N/A"},
    {SRC_COUNTRY_CODE,"src_country_code","src_country_code",stringFormat,"N/A"},
    {DST_COUNTRY_CODE,"dst_country_code","dst_country_code",stringFormat,"N/A"},
    {SRC_AS,"src_as","src_as",numericFormat, 0},
    {DST_AS,"dst_as","dst_as",numericFormat, 0},
    {SRC_AS_NAME,"src_as_name","src_as_name",stringFormat,"N/A"},
    {DST_AS_NAME,"dst_as_name","dst_as_name",stringFormat,"N/A"},
    #endif /* HAVE_GEOIP */
    {TEMPLATE_END_ID,"","",numericFormat,"0"}
};

/* list of function prototypes for this preprocessor */
static void AlertJSONInit(char *);
static AlertJSONData *AlertJSONParseArgs(char *);
static void AlertJSON(Packet *, void *, uint32_t, void *);
static void AlertJSONCleanExit(int, void *);
static void AlertRestart(int, void *);
static void RealAlertJSON(Packet*, void*, uint32_t, AlertJSONData * data);

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

    char *keyval = strdup(_keyval);

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
 * output alert_json: [<logpath> ["default"|<list> [sensor_name=name] [sensor_id=id]]
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
    char* kafka_str = NULL;
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
    #ifdef HAVE_LIBRDKAFKA
    rd_kafka_conf_t       *rk_conf  = rd_kafka_conf_new();
    rd_kafka_topic_conf_t *rkt_conf = rd_kafka_topic_conf_new();
    #endif

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "ParseJSONArgs: %s\n", args););
    data = (AlertJSONData *)SnortAlloc(sizeof(AlertJSONData));

    if ( !data )
    {
        FatalError("alert_json: unable to allocate memory!\n");
    }
    if ( !args ) args = "";
    toks = mSplit((char *)args, " \t", 0, &num_toks, '\\');

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
            RB_IF_CLEAN(kafka_str,kafka_str = SnortStrdup(tok),"%s(%i) param setted twice\n",tok,i);
        }
        else if ( !strncasecmp(tok, "default", strlen("default")) && !data->jsonargs)
        {
            RB_IF_CLEAN(data->jsonargs,data->jsonargs = SnortStrdup(DEFAULT_JSON),"%s(%i) param setted twice\n",tok,i);
        }
        else if(!strncasecmp(tok,"sensor_name=",strlen("sensor_name=")) && !data->sensor_name)
        {
			RB_IF_CLEAN(data->sensor_name,data->sensor_name = SnortStrdup(tok+strlen("sensor_name=")),"%s(%i) param setted twice\n",tok,i);
		}
        else if(!strncasecmp(tok,"sensor_id=",strlen("sensor_id=")))
        {
            data->sensor_id = atol(tok + strlen("sensor_id="));
        }
        else if(!strncasecmp(tok,"sensor_ip=",strlen("sensor_ip=")))
        {
            data->sensor_ip = strdup(tok + strlen("sensor_ip="));
        }
        else if(!strncasecmp(tok,"group_id=",strlen("group_id=")))
        {
	        data->group_id = atol(tok + strlen("group_id="));
        }
        else if(!strncasecmp(tok,"group_name=",strlen("group_name=")))
        {
            data->group_name = strdup(tok + strlen("group_name="));
        }
        else if(!strncasecmp(tok,"sensor_type=",strlen("sensor_type=")))
        {
            RB_IF_CLEAN(data->sensor_type,data->sensor_type = SnortStrdup(tok + strlen("sensor_type=")),"%s(%i) param setted twice.\n",tok,i);
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

            const rd_kafka_conf_res_t rc = rdkafka_add_str_to_config(rk_conf,rkt_conf,tok+strlen("rdkafka."),errstr,sizeof(errstr));
            if(rc != RD_KAFKA_CONF_OK){
                FatalError("alert_json: Cannot parse %s(%i): %s: %s\n",
                    file_name, file_line, tok,errstr);
            }
            #else
            FatalError("alert_json: Cannot parse %s(%i): %s: Does not have librdkafka\n",
                file_name, file_line, tok);
            #endif
        }
        else if(!strncasecmp(tok,"eth_vendors=",strlen("eth_vendors=")))
        {
            RB_IF_CLEAN(eth_vendors_path,eth_vendors_path = SnortStrdup(tok+strlen("eth_vendors=")),"%s(%i) param setted twice.\n",tok,i);
        }
        else if(!strncasecmp(tok,"domain_name=",strlen("domain_name=")))
        {
            RB_IF_CLEAN(data->domain, data->domain = SnortStrdup(tok+strlen("domain_name=")),"%s(%i) param setted twice.\n",tok,i);
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
    if ( !data->sensor_name ) data->sensor_name = SnortStrdup("-");
    if ( !filename ) filename = ProcessFileOption(barnyard2_conf_for_parsing, DEFAULT_FILE);
    if ( !kafka_str ) kafka_str = SnortStrdup(DEFAULT_KAFKA_BROKER);
    
    /* names-str assoc */
    if(hostsListPath) FillHostsList(hostsListPath,&data->hosts,HOSTS);
    if(networksPath) FillHostsList(networksPath,&data->nets,NETWORKS);
    if(servicesPath) FillHostsList(servicesPath,&data->services,SERVICES);
    if(protocolsPath) FillHostsList(protocolsPath,&data->protocols,PROTOCOLS);
    if(vlansPath) FillHostsList(vlansPath,&data->vlans,VLANS);

    mSplitFree(&toks, num_toks);
    toks = mSplit(data->jsonargs, ",", 128, &num_toks, 0);

    for(i=0;i<num_toks;++i){
        int j;
        for(j=0;;++j){
            if(template[j].id==TEMPLATE_END_ID)
                FatalError("alert_json: Cannot parse template element %s\n",toks[i]);
            if(!strcmp(template[j].templateName,toks[i])){
                TemplateElementsList ** templateIterator = &data->outputTemplate;
                while(*templateIterator!=NULL) templateIterator=&(*templateIterator)->next;
                *templateIterator = SnortAlloc(sizeof(TemplateElementsList));
                (*templateIterator)->templateElement = &template[j];
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

    if(kafka_str){
        char * at_char = strchr(kafka_str,BROKER_TOPIC_SEPARATOR);
        if(at_char==NULL)
            FatalError("alert_json: No topic specified, despite the fact a kafka server was given. Use kafka://broker@topic.");
        const size_t broker_length = (at_char-(kafka_str+strlen(KAFKA_PROT)));
        char * kafka_server = malloc(sizeof(char)*(broker_length+1));
        strncpy(kafka_server,kafka_str+strlen(KAFKA_PROT),broker_length);
        kafka_server[broker_length] = '\0';

        /*
         * In DaemonMode(), kafka must start in another function, because, in daemon mode, Barnyard2Main will execute this 
         * function, will do a fork() and then, in the child process, will call RealAlertJSON, that will not be able to 
         * send kafka data*/
        data->kafka = KafkaLog_Init (kafka_server, LOG_BUFFER, at_char+1, kafka_str?NULL:filename
            #ifdef HAVE_LIBRDKAFKA
            ,rk_conf,rkt_conf
            #endif
        );
    }
    if ( filename ) free(filename);
    if( kafka_str ) free (kafka_str);
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

static void AlertJSONCleanup(int signal, void *arg, const char* msg)
{
    AlertJSONData *data = (AlertJSONData *)arg;
    TemplateElementsList *iter,*aux;
    /* close alert file */
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"%s\n", msg););

    if(data)
    {
        if(data->kafka)
            KafkaLog_Term(data->kafka);
        free(data->jsonargs);
        free(data->sensor_name);
        free(data->sensor_ip);
        free(data->sensor_type);
        free(data->group_name);
        free(data->domain);
        freeNumberStrAssocList(data->hosts);
        freeNumberStrAssocList(data->nets);
        freeNumberStrAssocList(data->services);
        freeNumberStrAssocList(data->protocols);
        freeNumberStrAssocList(data->vlans);
        for(iter=data->outputTemplate;iter;iter=aux){
            aux = iter->next;
            free(iter);
        }


        #ifdef HAVE_GEOIP
        if(data->gi) GeoIP_delete(data->gi);
        if(data->gi_org) GeoIP_delete(data->gi_org);
        #endif // GWO_IP
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
static inline char *itoa16(uint64_t value,char *result,const size_t bufsize){return _itoa(value,result,16,bufsize);}
static inline void printHWaddr(KafkaLog *kafka,const uint8_t *addr,char * buf,const size_t bufLen){
    int i;
    for(i=0;i<6;++i){
        if(i>0)
            KafkaLog_Putc(kafka,':');
        if(addr[i]<0x10)
            KafkaLog_Putc(kafka,'0');
        KafkaLog_Puts(kafka, itoa16(addr[i],buf,bufLen));
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
static int printElementWithTemplate(Packet *p, void *event, uint32_t event_type, AlertJSONData *jsonData, AlertJSONTemplateElement *templateElement){
    SigNode *sn;
    char tcpFlags[9];
    char buf[sizeof "0000:0000:0000:0000:0000:0000:0000:0000"];
    const size_t bufLen = sizeof buf;
    const char * str_aux=NULL;
    KafkaLog * kafka = jsonData->kafka;

    sfip_t ip;
    sfip_clear(&ip);
    const int initial_buffer_pos = KafkaLog_Tell(jsonData->kafka);

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
            KafkaLog_Puts(kafka,itoa10(ntohl(((Unified2EventCommon *)event)->event_second), buf, bufLen));
            break;
        case SENSOR_ID_SNORT:
            KafkaLog_Puts(kafka,event?itoa10(ntohl(((Unified2EventCommon *)event)->sensor_id),buf, bufLen):templateElement->defaultValue);
            break;
        case SENSOR_ID:
            KafkaLog_Puts(kafka,itoa10(jsonData->sensor_id,buf,bufLen));
            break;
        case SENSOR_IP:
            if(jsonData->sensor_ip) KafkaLog_Puts(kafka,jsonData->sensor_ip);
            break;
        case SENSOR_NAME:
            KafkaLog_Puts(kafka,jsonData->sensor_name);
            break;
        case DOMAIN_NAME:
            if(jsonData->domain) KafkaLog_Puts(kafka,jsonData->domain);
            break;
        case DOMAIN_ID:
            KafkaLog_Puts(kafka,itoa10(jsonData->domain_id,buf,bufLen));
            break;
        case GROUP_NAME:
            if(jsonData->group_name) KafkaLog_Puts(kafka,jsonData->group_name);
            break;
        case GROUP_ID:
            KafkaLog_Puts(kafka,itoa10(jsonData->group_id,buf,bufLen));
            break;
        case TYPE:
            if(jsonData->sensor_type) KafkaLog_Puts(kafka,jsonData->sensor_type);
            break;
        case ACTION:
            if((str_aux = actionOfEvent(event,event_type)))
                KafkaLog_Puts(kafka,str_aux);
            break;
        case SIG_GENERATOR:
            if(event != NULL)
                KafkaLog_Puts(kafka,itoa10(ntohl(((Unified2EventCommon *)event)->generator_id),buf,bufLen));
            break;
        case SIG_ID:
            if(event != NULL)
                KafkaLog_Puts(kafka,itoa10(ntohl(((Unified2EventCommon *)event)->signature_id),buf,bufLen));
            break;
        case SIG_REV:
            if(event != NULL)
                KafkaLog_Puts(kafka,itoa10(ntohl(((Unified2EventCommon *)event)->signature_revision),buf,bufLen));
            break;
        case PRIORITY:
            if(event != NULL){
                const int priority_id = ntohl(((Unified2EventCommon *)event)->priority_id);
                const char *prio_name = NULL;
                if(priority_id < sizeof(priority_name)/sizeof(priority_name[0])) 
                    prio_name = priority_name[priority_id];
                KafkaLog_Puts(kafka,prio_name ? prio_name : templateElement->defaultValue);
            }
            break;
        case CLASSIFICATION:
            if(event != NULL)
            {
                uint32_t classification_id = ntohl(((Unified2EventCommon *)event)->classification_id);
                const ClassType *cn = ClassTypeLookupById(barnyard2_conf, classification_id);
                KafkaLog_Puts(kafka,cn?cn->name:templateElement->defaultValue);
            }else{ /* Always log something */
                KafkaLog_Puts(kafka, templateElement->defaultValue);
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
                    KafkaLog_Puts(kafka,sn->msg);
                }
            }
            break;
        case PAYLOAD:
            {
                /* Sending packet payload (Packet->data) inside kafka message, instead of
                   raw packet data (Packet->pkt). See Packet structure in decode.h file.
                   Please take into account that snort.log.<timestamp> files contains
                   the raw packet data, not packet payload, so they won't match. */
                uint16_t i;
                if(p &&  p->dsize>0){
                    for(i=0;i<p->dsize;++i)
                        KafkaLog_Puts(kafka, itoa16(p->data[i],buf,bufLen));
                }else{
                    KafkaLog_Puts(kafka, templateElement->defaultValue);
                }
            }
            break;

        case PROTO:
            {
                const uint16_t proto = extract_proto(event,event_type,p);
                Number_str_assoc * service_name_asoc = SearchNumberStr(proto,jsonData->protocols);
                if(service_name_asoc){
                    KafkaLog_Puts(kafka,service_name_asoc->human_readable_str);
                    break;
                }
            }
            /* don't break! Print, at least, proto_id*/
        case PROTO_ID:
            {
                const uint16_t proto = extract_proto(event,event_type,p);
                KafkaLog_Puts(kafka,itoa10(proto,buf,bufLen));
            }

            break;

        case ETHSRC:
            if(p && p->eh)
                printHWaddr(kafka, p->eh->ether_src, buf,bufLen);
            break;

        case ETHDST:
            if(p && p->eh)
                printHWaddr(kafka,p->eh->ether_dst,buf,bufLen);
            break;

#ifdef HAVE_RB_MAC_VENDORS
        case ETHSRC_VENDOR:
            if(p && p->eh && jsonData->eth_vendors_db)
            {
                const char * vendor = rb_find_mac_vendor(HWADDR_vectoi(p->eh->ether_src),jsonData->eth_vendors_db);
                if(vendor)
                    KafkaLog_Puts(kafka,vendor);
            }
            break;
        case ETHDST_VENDOR:
            if(p && p->eh && jsonData->eth_vendors_db)
            {
                const char * vendor = rb_find_mac_vendor(HWADDR_vectoi(p->eh->ether_dst),jsonData->eth_vendors_db);
                if(vendor)
                    KafkaLog_Puts(kafka,vendor);
            }
            break;
#endif

        case ARP_HW_SADDR:
            if(p && p->ah)
                printHWaddr(kafka,p->ah->arp_sha,buf,bufLen);
            break;
        case ARP_HW_SPROT:
            if(p && p->ah)
            {
                KafkaLog_Puts(kafka, "0x");
                KafkaLog_Puts(kafka, itoa16(p->ah->arp_spa[0],buf,bufLen));
                KafkaLog_Puts(kafka, itoa16(p->ah->arp_spa[1],buf,bufLen));
                KafkaLog_Puts(kafka, itoa16(p->ah->arp_spa[2],buf,bufLen));
                KafkaLog_Puts(kafka, itoa16(p->ah->arp_spa[3],buf,bufLen));
            }
            break;
        case ARP_HW_TADDR:
            if(p && p->ah)
                printHWaddr(kafka,p->ah->arp_tha,buf,bufLen);
            break;
        case ARP_HW_TPROT:
            if(p && p->ah)
            {
                KafkaLog_Puts(kafka, "0x");
                KafkaLog_Puts(kafka, itoa16(p->ah->arp_tpa[0],buf,bufLen));
                KafkaLog_Puts(kafka, itoa16(p->ah->arp_tpa[1],buf,bufLen));
                KafkaLog_Puts(kafka, itoa16(p->ah->arp_tpa[2],buf,bufLen));
                KafkaLog_Puts(kafka, itoa16(p->ah->arp_tpa[3],buf,bufLen));
            }
            break;

        case ETHTYPE:
            if(p && p->eh)
            {
                KafkaLog_Puts(kafka, itoa10(ntohs(p->eh->ether_type),buf,bufLen));
            }
            break;

        case UDPLENGTH:
            if(p && p->udph){
                KafkaLog_Puts(kafka, itoa10(ntohs(p->udph->uh_len),buf,bufLen));
            }
            break;
        case ETHLENGTH:
            if(p && p->eh){
                KafkaLog_Puts(kafka, itoa10(p->pkth->len,buf,bufLen));
            }
            break;

        case ETHLENGTH_RANGE:
            if(p && p->eh){
                if(p->pkth->len==0)
                    KafkaLog_Puts(kafka, "0");
                if(p->pkth->len<=64)
                    KafkaLog_Puts(kafka, "(0-64]");
                else if(p->pkth->len<=128)
                    KafkaLog_Puts(kafka, "(64-128]");
                else if(p->pkth->len<=256)
                    KafkaLog_Puts(kafka, "(128-256]");
                else if(p->pkth->len<=512)
                    KafkaLog_Puts(kafka, "(256-512]");
                else if(p->pkth->len<=768)
                    KafkaLog_Puts(kafka, "(512-768]");
                else if(p->pkth->len<=1024)
                    KafkaLog_Puts(kafka, "(768-1024]");
                else if(p->pkth->len<=1280)
                    KafkaLog_Puts(kafka, "(1024-1280]");
                else if(p->pkth->len<=1514)
                    KafkaLog_Puts(kafka, "(1280-1514]");
                else if(p->pkth->len<=2048)
                    KafkaLog_Puts(kafka, "(1514-2048]");
                else if(p->pkth->len<=4096)
                    KafkaLog_Puts(kafka, "(2048-4096]");
                else if(p->pkth->len<=8192)
                    KafkaLog_Puts(kafka, "(4096-8192]");
                else if(p->pkth->len<=16384)
                    KafkaLog_Puts(kafka, "(8192-16384]");
                else if(p->pkth->len<=32768)
                    KafkaLog_Puts(kafka, "(16384-32768]");
                else
                    KafkaLog_Puts(kafka, ">32768");
            }
            break;

        case VLAN_PRIORITY:
            if(p && p->vh)
                KafkaLog_Puts(kafka,itoa10(VTH_PRIORITY(p->vh),buf,bufLen));
            break;
        case VLAN_DROP:
            if(p && p->vh)
                KafkaLog_Puts(kafka,itoa10(VTH_CFI(p->vh),buf,bufLen));
            break;
        case VLAN:
            {
                int ok;
                const uint16_t vlan = extract_vlan_id(event, event_type, p, &ok);
                if(ok)
                    KafkaLog_Puts(kafka,itoa10(vlan,buf,bufLen));
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
                        KafkaLog_Puts(kafka,vlan_str->human_readable_str);
                    else
                        KafkaLog_Puts(kafka,itoa10(vlan,buf,bufLen));
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
                        KafkaLog_Puts(kafka,service_name_asoc->human_readable_str);
                    else /* Log port number */
                        KafkaLog_Puts(kafka,itoa10(port,buf,bufLen));
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
                    KafkaLog_Puts(kafka,itoa10(port,buf,bufLen));
            }
            break;

        case SRC_TEMPLATE_ID:
        case DST_TEMPLATE_ID:
            /*if(sfip_family(&ip)==AF_INET){ // buggy sfip_family macro...*/
            if(ip.family==AF_INET)
            {
                KafkaLog_Puts(kafka,itoa10(*ip.ip32, buf,bufLen));
            }
            /* doesn't make very sense print so large number. If you want, make me know. */
            break;
        case SRC_STR:
        case DST_STR:
            {
                KafkaLog_Puts(kafka,sfip_to_str(&ip));
            }
            break;
        case SRC_NAME:
        case DST_NAME:
            {
                Number_str_assoc * ip_str_node = SearchIpStr(ip,jsonData->hosts,HOSTS);
                const char * ip_name = ip_str_node ? ip_str_node->human_readable_str : sfip_to_str(&ip);
                KafkaLog_Puts(kafka,ip_name);
            }
            break;
        case SRC_NET:
        case DST_NET:
            {
                Number_str_assoc *ip_net = SearchIpStr(ip,jsonData->nets,NETWORKS);
                if(ip_net)
                    KafkaLog_Puts(kafka,ip_net->number_as_str);
            }
            break;
        case SRC_NET_NAME:
        case DST_NET_NAME:
            {
                Number_str_assoc *ip_net = SearchIpStr(ip,jsonData->nets,NETWORKS);
                if(ip_net)
                    KafkaLog_Puts(kafka,ip_net->human_readable_str);
            }
            break;

#ifdef HAVE_GEOIP
        case SRC_COUNTRY:
        case DST_COUNTRY:
            {
                const char * country_name = extract_country(jsonData,&ip);
                if(country_name)
                    KafkaLog_Puts(kafka,country_name);
            }
            break;

        case SRC_COUNTRY_CODE:
        case DST_COUNTRY_CODE:
            if(jsonData->gi){
                const char * country_code = extract_country_code(jsonData,&ip);
                if(country_code)
                    KafkaLog_Puts(kafka,country_code);
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
                        KafkaLog_Write(kafka,as_name+2,space - &as_name[2]);
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
                        KafkaLog_Puts(kafka,space+1);
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
                    KafkaLog_Puts(kafka, itoa10(itype,buf,bufLen));
            }
            break;
        case ICMPCODE:
            {
                int ok;
                const uint16_t icode = extract_icmp_code(event,event_type,p,&ok);
                if(ok)
                    KafkaLog_Puts(kafka, itoa10(icode,buf,bufLen));
            }
            break;
        case ICMPID:
            if(p && p->icmph)
                KafkaLog_Puts(kafka, itoa10(ntohs(p->icmph->s_icmp_id),buf,bufLen));
            break;
        case ICMPSEQ:
            if(p && p->icmph){
                /* Doesn't work because "%d" arbitrary
                    PrintJSONFieldName(kafka,JSON_ICMPSEQ_NAME);
                    KafkaLog_Print(kafka, "%d",ntohs(p->icmph->s_icmp_seq));
                */
                KafkaLog_Puts(kafka,itoa10(ntohs(p->icmph->s_icmp_seq),buf,bufLen));
            }
            break;
        case TTL:
            if(p && IPH_IS_VALID(p))
                KafkaLog_Puts(kafka,itoa10(GET_IPH_TTL(p),buf,bufLen));
            break;

        case TOS: 
            if(p && IPH_IS_VALID(p))
                KafkaLog_Puts(kafka,itoa10(GET_IPH_TOS(p),buf,bufLen));
            break;
        case ID:
            if(p && IPH_IS_VALID(p))
                KafkaLog_Puts(kafka,itoa10(IS_IP6(p) ? ntohl(GET_IPH_ID(p)) : ntohs((u_int16_t)GET_IPH_ID(p)),buf,bufLen));
            break;
        case IPLEN:
            if(p && IPH_IS_VALID(p))
                KafkaLog_Puts(kafka,itoa10(ntohs(GET_IPH_LEN(p)),buf,bufLen));
            break;
        case IPLEN_RANGE:
            if(p && IPH_IS_VALID(p))
            {
                const double log2_len = log2(ntohs(GET_IPH_LEN(p)));
                const unsigned int lower_limit = pow(2.0,floor(log2_len));
                const unsigned int upper_limit = pow(2.0,ceil(log2_len));
                //printf("log2_len: %0lf; floor: %0lf; ceil: %0lf; low_limit: %0lf; upper_limit:%0lf\n",
                //    log2_len,floor(log2_len),ceil(log2_len),pow(floor(log2_len),2.0),pow(ceil(log2_len),2));
                KafkaLog_Print(kafka,"[%u-%u)",lower_limit,upper_limit);
                //printf(kafka,"[%lf-%lf)\n",lower_limit,upper_limit);
            }
            break;
        case DGMLEN:
            if(p && IPH_IS_VALID(p)){
                // XXX might cause a bug when IPv6 is printed?
                KafkaLog_Puts(kafka, itoa10(ntohs(GET_IPH_LEN(p)),buf,bufLen));
            }
            break;

        case TCPSEQ:
            if(p && p->tcph){
                // KafkaLog_Print(kafka, "lX%0x",(u_long) ntohl(p->tcph->th_ack)); // hex format
                KafkaLog_Puts(kafka,itoa10(ntohl(p->tcph->th_seq),buf,bufLen));
            }
            break;
        case TCPACK:
            if(p && p->tcph){
                // KafkaLog_Print(kafka, "0x%lX",(u_long) ntohl(p->tcph->th_ack));
                KafkaLog_Puts(kafka,itoa10(ntohl(p->tcph->th_ack),buf,bufLen));
            }
            break;
        case TCPLEN:
            if(p && p->tcph){
                KafkaLog_Puts(kafka, itoa10(TCP_OFFSET(p->tcph) << 2,buf,bufLen));
            }
            break;
        case TCPWINDOW:
            if(p && p->tcph){
                //KafkaLog_Print(kafka, "0x%X",ntohs(p->tcph->th_win));  // hex format
                KafkaLog_Puts(kafka,itoa10(ntohs(p->tcph->th_win),buf,bufLen));
            }
            break;
        case TCPFLAGS:
            if(p && p->tcph)
            {
                CreateTCPFlagString(p, tcpFlags);
                KafkaLog_Puts(kafka, tcpFlags);
            }
            break;

        default:
            FatalError("Template %s(%d) not found\n",templateElement->templateName,templateElement->id);
            break;
    };

    return KafkaLog_Tell(kafka)-initial_buffer_pos; /* if we have write something */
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
    TemplateElementsList * iter;

    KafkaLog * kafka = jsonData->kafka;

    // if(p == NULL)
    //     return;

    if(event == NULL)
    {
        ErrorMessage("Lonely packet detected. Please consider increase the cache size.");
        return;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Logging JSON Alert data\n"););
    KafkaLog_Putc(kafka,'{');
    for(iter=jsonData->outputTemplate;iter;iter=iter->next){
        const int initial_pos = KafkaLog_Tell(kafka);
        if(iter!=jsonData->outputTemplate)
            KafkaLog_Puts(kafka,JSON_FIELDS_SEPARATOR);

        KafkaLog_Putc(kafka,'"');
        KafkaLog_Puts(kafka,iter->templateElement->jsonName);
        KafkaLog_Puts(kafka,"\":");

        if(iter->templateElement->printFormat==stringFormat)
            KafkaLog_Putc(kafka,'"');
        const int writed = printElementWithTemplate(p,event,event_type,jsonData,iter->templateElement);
        if(iter->templateElement->printFormat==stringFormat)
            KafkaLog_Putc(kafka,'"');

        if(0==writed){
            #ifdef HAVE_LIBRDKAFKA
            kafka->pos = initial_pos; // Revert the insertion of empty element */
            #endif
            
            if(kafka->textLog) 
                kafka->textLog->pos = initial_pos;
        }
    }

    KafkaLog_Putc(kafka,'}');
    // Just for debug
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"[KAFKA]: %s",kafka->buf););
    KafkaLog_Flush(kafka);
}

