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
#include "errno.h"
#include "signal.h"
#include "log_text.h"

#ifdef HAVE_GEOIP
#include "GeoIP.h"
#endif // HAVE_GEOIP


#define DEFAULT_JSON "timestamp,sensor_id,sensor_id_snort,type,sensor_name,domain,domain_id,sig_generator,sig_id,sig_rev,priority,classification,msg,payload,proto,proto_id,src,src_str,src_name,src_net,src_net_name,dst_name,dst_str,dst_net,dst_net_name,src_country,dst_country,src_country_code,dst_country_code,srcport,dst,dstport,ethsrc,ethdst,ethlen,arp_hw_saddr,arp_hw_sprot,arp_hw_taddr,arp_hw_tprot,vlan,vlan_name,vlan_priority,vlan_drop,tcpflags,tcpseq,tcpack,tcplen,tcpwindow,ttl,tos,id,dgmlen,iplen,icmptype,icmpcode,icmpid,icmpseq"

#define DEFAULT_FILE  "alert.json"
#define DEFAULT_KAFKA_BROKER "kafka://127.0.0.1@barnyard"
#define DEFAULT_LIMIT (128*M_BYTES)
#define LOG_BUFFER    (30*K_BYTES)

#define KAFKA_PROT "kafka://"
//#define KAFKA_TOPIC "rb_ips"
#define KAFKA_PARTITION 0
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
    DOMAIN,
    DOMAIN_ID,
    TYPE,
    SIG_GENERATOR,
    SIG_ID,
    SIG_REV,
    PRIORITY,
    CLASSIFICATION,
    MSG,
    PAYLOAD,
    PROTO,
    PROTO_ID,
    ETHSRC,
    ETHDST,
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
    uint32_t sensor_id,domain_id;
    char * sensor_name, *sensor_type,*domain;
#ifdef HAVE_GEOIP
    GeoIP *gi;
#endif
} AlertJSONData;

/* Remember update printElementWithTemplate if some element modified here */
static AlertJSONTemplateElement template[] = {
    {TIMESTAMP,"timestamp","timestamp",numericFormat,"0"},
    {SENSOR_ID_SNORT,"sensor_id_snort","sensor_id_snort",numericFormat,"0"},
    {SENSOR_ID,"sensor_id","sensor_id",numericFormat,"0"},
    {SENSOR_NAME,"sensor_name","sensor_name",stringFormat,"-"},
    {DOMAIN,"domain","domain",stringFormat,"-"},
    {DOMAIN_ID,"domain_id","domain_id",numericFormat,"-"},
    {TYPE,"type","type",stringFormat,"-"},
    {SIG_GENERATOR,"sig_generator","sig_generator",numericFormat,"0"},
    {SIG_ID,"sig_id","sig_id",numericFormat,"0"},
    {SIG_REV,"sig_rev","rev",numericFormat,"0"},
    {PRIORITY,"priority","priority",numericFormat,"0"},
    {CLASSIFICATION,"classification","classification",stringFormat,"-"},
    {MSG,"msg","msg",stringFormat,"-"},
    {PAYLOAD,"payload","payload",stringFormat,"-"},
    {PROTO,"proto","proto",stringFormat,"-"},
    {PROTO_ID,"proto_id","proto_id",numericFormat,"0"},
    {ETHSRC,"ethsrc","ethsrc",stringFormat,"-"},
    {ETHDST,"ethdst","ethdst",stringFormat,"-"},
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
    {TRHEADER,"trheader","trheader",stringFormat,"-"},
    {SRCPORT,"srcport","srcport",numericFormat,"0"},
    {SRCPORT_NAME,"srcport_name","srcport_name",stringFormat,"-"},
    {DSTPORT,"dstport","dstport",numericFormat,"0"},
    {DSTPORT_NAME,"dstport_name","dstport_name",stringFormat,"-"},
    {SRC_TEMPLATE_ID,"src","src",numericFormat,"0"}, 
    {SRC_STR,"src_str","src_str",stringFormat,"-"},
    {SRC_NAME,"src_name","src_name",stringFormat,"-"},
    {SRC_NET,"src_net","src_net",stringFormat,"0.0.0.0/0"},
    {SRC_NET_NAME,"src_net_name","src_net_name",stringFormat,"0.0.0.0/0"},
    {DST_TEMPLATE_ID,"dst","dst",numericFormat,"0"}, 
    {DST_NAME,"dst_name","dst_name",stringFormat,"-"},
    {DST_STR,"dst_str","dst_str",stringFormat,"-"},
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
    char* hostsListPath = NULL,*networksPath = NULL,*servicesPath = NULL,*protocolsPath = NULL,*vlansPath=NULL;
    #ifdef HAVE_GEOIP
    char * geoIP_path = NULL;
    #endif
    int start_partition=KAFKA_PARTITION,end_partition=KAFKA_PARTITION;

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
        else if(!strncasecmp(tok,"vlans=",strlen("vlans")))
        {
            RB_IF_CLEAN(vlansPath, vlansPath = SnortStrdup(tok+strlen("vlans=")),"%s(%i) param setted twice.\n",tok,i);
        }
        else if(!strncasecmp(tok,"start_partition=",strlen("start_partition=")))
        {
            start_partition = end_partition = atol(tok+strlen("start_partition="));
        }
        else if(!strncasecmp(tok,"end_partition=",strlen("end_partition=")))
        {
            end_partition = atol(tok+strlen("end_partition="));
        }
        else if(!strncasecmp(tok,"domain=",strlen("domain=")))
        {
            RB_IF_CLEAN(data->domain, data->domain = SnortStrdup(tok+strlen("domain=")),"%s(%i) param setted twice.\n",tok,i);
        }
        else if(!strncasecmp(tok,"domain_id=",strlen("domain_id=")))
        {
            data->domain_id = atol(tok+strlen("domain_id="));
        }
        #ifdef HAVE_GEOIP
        else if(!strncasecmp(tok,"geoip=",strlen("geoip=")))
        {
            RB_IF_CLEAN(geoIP_path,geoIP_path = SnortStrdup(tok+strlen("geoip=")),"%s(%i) param setted twice.\n",tok,i);
        }
        #endif // HAVE_GEOIP
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
            FatalError("alert_json: Error opening database %s\n",geoIP_path);
        else
            DEBUG_WRAP(DebugMessage(DEBUG_INIT, "alert_json: Success opening geoip database: %s\n", geoIP_path););
    }else{
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "alert_json: No geoip database specified.\n"););
    }

#endif // HAVE_GEOIP

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

        data->kafka = KafkaLog_Init(kafka_server,LOG_BUFFER, at_char+1,
            start_partition,end_partition,BcDaemonMode()?0:1,filename==kafka_str?NULL:filename);
        free(kafka_server);
    }
    if ( filename ) free(filename);
    if( kafka_str ) free (kafka_str);
    if( hostsListPath ) free (hostsListPath);
    if( networksPath ) free (networksPath);
    if( servicesPath ) free (servicesPath);
    if( protocolsPath ) free (protocolsPath);
    if( vlansPath ) free(vlansPath);
    #ifdef HAVE_GEOIP
    if (geoIP_path) free(geoIP_path);
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
        GeoIP_delete(data->gi);
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
        KafkaLog_Puts(kafka, itoa16(addr[i],buf,bufLen));
    }
}

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
static int printElementWithTemplate(Packet * p, void *event, uint32_t event_type, AlertJSONData *jsonData, AlertJSONTemplateElement *templateElement){
    SigNode *sn;
    char tcpFlags[9];
  /*char buf[sizeof "ff:ff:ff:ff:ff:ff:255.255.255.255"];*/
    char buf[sizeof "0000:0000:0000:0000:0000:0000:0000:0000"];
    const size_t bufLen = sizeof buf;
    KafkaLog * kafka = jsonData->kafka;
    sfip_t ip;
    const int initial_buffer_pos = KafkaLog_Tell(jsonData->kafka);
#ifdef HAVE_GEOIP
    geoipv6_t ipv6;
#endif

    /* Avoid repeated code */
    if(IPH_IS_VALID(p)){
        switch(templateElement->id){
            case SRC_TEMPLATE_ID:
            case SRC_STR:
            case SRC_NAME:
            case SRC_NET:
            case SRC_NET_NAME:
#ifdef HAVE_GEOIP
            case SRC_COUNTRY:
            case SRC_COUNTRY_CODE:
#endif
#ifdef SUP_IP6
                sfip_set_ip(&ip,GET_SRC_ADDR(p));
#else
                {
                    int ipv4 = ntohl(GET_SRC_ADDR(p).s_addr);
                    sfip_set_raw(&ip,&ipv4,AF_INET);
                }
#endif
                break;

            case DST_TEMPLATE_ID:
            case DST_STR:
            case DST_NAME:
            case DST_NET:
            case DST_NET_NAME:
#ifdef HAVE_GEOIP
            case DST_COUNTRY:
            case DST_COUNTRY_CODE:
#endif
#ifdef SUP_IP6
                sfip_set_ip(&ip,GET_DST_ADDR(p));
#else
                {
                    int ipv4 = ntohl(GET_DST_ADDR(p).s_addr);
                    sfip_set_raw(&ip,&ipv4,AF_INET);
                }
#endif
                break;
            default:
                break;
        };

#ifdef HAVE_GEOIP
        if(IPH_IS_VALID(p) && ip.family == AF_INET6){
            switch(templateElement->id){
                case SRC_COUNTRY:
                case SRC_COUNTRY_CODE:
                case DST_COUNTRY:
                case DST_COUNTRY_CODE:
                    memcpy(ipv6.s6_addr, ip.ip8, sizeof(ipv6.s6_addr));
                    break;
                default:
                    break;
            };
        }
#endif
    }

    #ifdef DEBUG
    if(NULL==templateElement) FatalError("TemplateElement was not setted (File %s line %d)\n.",__FILE__,__LINE__);
    #endif
    switch(templateElement->id){
        case TIMESTAMP:
            KafkaLog_Puts(kafka,itoa10(p->pkth->ts.tv_sec, buf, bufLen));
            break;
        case SENSOR_ID_SNORT:
            KafkaLog_Puts(kafka,event?itoa10(ntohl(((Unified2EventCommon *)event)->sensor_id),buf, bufLen):templateElement->defaultValue);
            break;
        case SENSOR_ID:
            KafkaLog_Puts(kafka,itoa10(jsonData->sensor_id,buf,bufLen));
            break;
        case SENSOR_NAME:
            KafkaLog_Puts(kafka,jsonData->sensor_name);
            break;
        case DOMAIN:
            if(jsonData->domain) KafkaLog_Puts(kafka,jsonData->domain);
            break;
        case DOMAIN_ID:
            KafkaLog_Puts(kafka,itoa10(jsonData->domain_id,buf,bufLen));
            break;
        case TYPE:
            if(jsonData->sensor_type) KafkaLog_Puts(kafka,jsonData->sensor_type);
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
            KafkaLog_Puts(kafka,event? itoa10(ntohl(((Unified2EventCommon *)event)->priority_id),buf,bufLen): templateElement->defaultValue);
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
            if(IPH_IS_VALID(p)){
                Number_str_assoc * service_name_asoc = SearchNumberStr(GET_IPH_PROTO(p),jsonData->protocols);
                if(service_name_asoc){
                    KafkaLog_Puts(kafka,service_name_asoc->human_readable_str);
                    break;
                } // Else: print PROTO_ID
            }
            /* don't break! */
        case PROTO_ID:
            KafkaLog_Puts(kafka,itoa10(IPH_IS_VALID(p)?GET_IPH_PROTO(p):0,buf,bufLen));
            break;

        case ETHSRC:
            if(p->eh)
                printHWaddr(kafka, p->eh->ether_src, buf,bufLen);
            break;

        case ETHDST:
            if(p->eh)
                printHWaddr(kafka,p->eh->ether_dst,buf,bufLen);
            break;

        case ARP_HW_SADDR:
            if(p->ah)
                printHWaddr(kafka,p->ah->arp_sha,buf,bufLen);
            break;
        case ARP_HW_SPROT:
            if(p->ah)
            {
                KafkaLog_Puts(kafka, "0x");
                KafkaLog_Puts(kafka, itoa16(p->ah->arp_spa[0],buf,bufLen));
                KafkaLog_Puts(kafka, itoa16(p->ah->arp_spa[1],buf,bufLen));
                KafkaLog_Puts(kafka, itoa16(p->ah->arp_spa[2],buf,bufLen));
                KafkaLog_Puts(kafka, itoa16(p->ah->arp_spa[3],buf,bufLen));
            }
            break;
        case ARP_HW_TADDR:
            if(p->ah)
                printHWaddr(kafka,p->ah->arp_tha,buf,bufLen);
            break;
        case ARP_HW_TPROT:
            if(p->ah)
            {
                KafkaLog_Puts(kafka, "0x");
                KafkaLog_Puts(kafka, itoa16(p->ah->arp_tpa[0],buf,bufLen));
                KafkaLog_Puts(kafka, itoa16(p->ah->arp_tpa[1],buf,bufLen));
                KafkaLog_Puts(kafka, itoa16(p->ah->arp_tpa[2],buf,bufLen));
                KafkaLog_Puts(kafka, itoa16(p->ah->arp_tpa[3],buf,bufLen));
            }
            break;

        case ETHTYPE:
            if(p->eh)
            {
                KafkaLog_Puts(kafka, itoa10(ntohs(p->eh->ether_type),buf,bufLen));
            }
            break;

        case UDPLENGTH:
            if(p->udph){
                KafkaLog_Puts(kafka, itoa10(ntohs(p->udph->uh_len),buf,bufLen));
            }
            break;
        case ETHLENGTH:
            if(p->eh){
                KafkaLog_Puts(kafka, itoa10(p->pkth->len,buf,bufLen));
            }
            break;

        case VLAN_PRIORITY:
            if(p->vh)
                KafkaLog_Puts(kafka,itoa10(VTH_PRIORITY(p->vh),buf,bufLen));
            break;
        case VLAN_DROP:
            if(p->vh)
                KafkaLog_Puts(kafka,itoa10(VTH_CFI(p->vh),buf,bufLen));
            break;
        case VLAN:
            if(p->vh)
                KafkaLog_Puts(kafka,itoa10(VTH_VLAN(p->vh),buf,bufLen));
            break;
        case VLAN_NAME:
            if(p->vh){
                Number_str_assoc * service_name_asoc = SearchNumberStr(VTH_VLAN(p->vh),jsonData->vlans);
                if(service_name_asoc)
                    KafkaLog_Puts(kafka,service_name_asoc->human_readable_str);
                else
                    KafkaLog_Puts(kafka,itoa10(VTH_VLAN(p->vh),buf,bufLen));
            }
            break;

        case SRCPORT_NAME:
        case DSTPORT_NAME:
            if(IPH_IS_VALID(p))
            {
                switch(GET_IPH_PROTO(p))
                {
                    case IPPROTO_UDP:
                    case IPPROTO_TCP:
                    {
                        const uint16_t port = templateElement->id==SRCPORT_NAME? p->sp:p->dp;
                        Number_str_assoc * service_name_asoc = SearchNumberStr(port,jsonData->services);
                        if(service_name_asoc)
                            KafkaLog_Puts(kafka,service_name_asoc->human_readable_str);
                        else /* Log port number */
                            KafkaLog_Puts(kafka,itoa10(templateElement->id==SRCPORT_NAME? p->sp:p->dp,buf,bufLen));
                    }
                    break;
                };
            }
        case SRCPORT:
        case DSTPORT:
            if(IPH_IS_VALID(p))
            {
                switch(GET_IPH_PROTO(p))
                {
                    case IPPROTO_UDP:
                    case IPPROTO_TCP:
                        KafkaLog_Puts(kafka,itoa10(templateElement->id==SRCPORT? p->sp:p->dp,buf,bufLen));
                        break;
                    default: /* Always log something */
                        KafkaLog_Puts(kafka,templateElement->defaultValue);
                        break;
                }
            }else{ /* Always Log something */
                KafkaLog_Puts(kafka,templateElement->defaultValue);
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
                Number_str_assoc * ip_net = SearchIpStr(ip,jsonData->nets,NETWORKS);
                KafkaLog_Puts(kafka,ip_net?ip_net->number_as_str:templateElement->defaultValue);
            }
            break;
        case SRC_NET_NAME:
        case DST_NET_NAME:
            {
                Number_str_assoc * ip_net = SearchIpStr(ip,jsonData->nets,NETWORKS);
                KafkaLog_Puts(kafka,ip_net?ip_net->human_readable_str:templateElement->defaultValue);
            }
            break;

#ifdef HAVE_GEOIP
        case SRC_COUNTRY:
        case DST_COUNTRY:
            if(jsonData->gi){
                const char * country_name = NULL;
                if(ip.family == AF_INET)
                    country_name = GeoIP_country_name_by_ipnum(jsonData->gi,ip.ip32[0]);
                else
                    country_name = GeoIP_country_name_by_ipnum_v6(jsonData->gi,ipv6);
                KafkaLog_Puts(kafka,country_name?country_name:templateElement->defaultValue);
            }
            break;
        case SRC_COUNTRY_CODE:
        case DST_COUNTRY_CODE:
            if(jsonData->gi){
                const char * country_name = NULL;
                if(ip.family == AF_INET)
                    country_name = GeoIP_country_code_by_ipnum(jsonData->gi,ip.ip32[0]);
                else
                    country_name = GeoIP_country_code_by_ipnum_v6(jsonData->gi,ipv6);
                KafkaLog_Puts(kafka,country_name?country_name:templateElement->defaultValue);
            }
            break;
#endif /* HAVE_GEOIP */

        case ICMPTYPE:
            if(p->icmph)
                KafkaLog_Puts(kafka, itoa10(p->icmph->type,buf,bufLen));
            break;
        case ICMPCODE:
            if(p->icmph)
                KafkaLog_Puts(kafka, itoa10(p->icmph->code,buf,bufLen));
            break;
        case ICMPID:
            if(p->icmph)
                KafkaLog_Puts(kafka, itoa10(ntohs(p->icmph->s_icmp_id),buf,bufLen));
            break;
        case ICMPSEQ:
            if(p->icmph){
                /* Doesn't work because "%d" arbitrary
                    PrintJSONFieldName(kafka,JSON_ICMPSEQ_NAME);
                    KafkaLog_Print(kafka, "%d",ntohs(p->icmph->s_icmp_seq));
                */
                KafkaLog_Puts(kafka,itoa10(ntohs(p->icmph->s_icmp_seq),buf,bufLen));
            }
            break;
        case TTL:
            if(IPH_IS_VALID(p))
                KafkaLog_Puts(kafka,itoa10(GET_IPH_TTL(p),buf,bufLen));
            break;

        case TOS: 
            if(IPH_IS_VALID(p))
                KafkaLog_Puts(kafka,itoa10(GET_IPH_TOS(p),buf,bufLen));
            break;
        case ID:
            if(IPH_IS_VALID(p))
                KafkaLog_Puts(kafka,itoa10(IS_IP6(p) ? ntohl(GET_IPH_ID(p)) : ntohs((u_int16_t)GET_IPH_ID(p)),buf,bufLen));
            break;
        case IPLEN:
            if(IPH_IS_VALID(p))
                KafkaLog_Puts(kafka,itoa10(GET_IPH_LEN(p) << 2,buf,bufLen));
            break;
        case DGMLEN:
            if(IPH_IS_VALID(p)){
                // XXX might cause a bug when IPv6 is printed?
                KafkaLog_Puts(kafka, itoa10(ntohs(GET_IPH_LEN(p)),buf,bufLen));
            }
            break;

        case TCPSEQ:
            if(p->tcph){
                // KafkaLog_Print(kafka, "lX%0x",(u_long) ntohl(p->tcph->th_ack)); // hex format
                KafkaLog_Puts(kafka,itoa16(ntohl(p->tcph->th_seq),buf,bufLen));
            }
            break;
        case TCPACK:
            if(p->tcph){
                // KafkaLog_Print(kafka, "0x%lX",(u_long) ntohl(p->tcph->th_ack));
                KafkaLog_Puts(kafka,itoa16(ntohl(p->tcph->th_ack),buf,bufLen));
            }
            break;
        case TCPLEN:
            if(p->tcph){
                KafkaLog_Puts(kafka, itoa10(TCP_OFFSET(p->tcph) << 2,buf,bufLen));
            }
            break;
        case TCPWINDOW:
            if(p->tcph){
                //KafkaLog_Print(kafka, "0x%X",ntohs(p->tcph->th_win));  // hex format
                KafkaLog_Puts(kafka,itoa16(ntohs(p->tcph->th_win),buf,bufLen));
            }
            break;
        case TCPFLAGS:
            if(p->tcph)
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

    if(p == NULL)
        return;

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
            if(kafka->textLog) kafka->textLog->pos = initial_pos;
        }
    }

    KafkaLog_Putc(kafka,'}');
    // Just for debug
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"[KAFKA]: %s",kafka->buf););
    KafkaLog_Flush(kafka);
}

