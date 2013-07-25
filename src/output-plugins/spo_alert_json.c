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
#include "sfutil/sf_kafka.h"
#include "errno.h"
#include "signal.h"
#include "log_text.h"
#include "ipv6_port.h"

#ifdef JSON_GEO_IP
#include "GeoIP.h"
#endif // JSON_GEO_IP


#define DEFAULT_JSON "timestamp,sensor_id,sig_generator,sig_id,sig_rev,priority,classification,msg,proto,src,srcport,dst,dstport,ethsrc,ethdst,ethlen,tcpflags,tcpseq,tcpack,tcpln,tcpwindow,ttl,tos,id,dgmlen,iplen,icmptype,icmpcode,icmpid,icmpseq"

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

#define JSON_TIMESTAMP_NAME "event_timestamp"
#define JSON_SENSOR_ID_SNORT_NAME "sensor_id_snort"
#define JSON_SENSOR_ID_NAME "sensor_id"
#define JSON_SENSOR_NAME_NAME "sensor_name"
#define SENSOR_NOT_FOUND_NUMBER 0
#define JSON_SIG_GENERATOR_NAME "sig_generator"
#define JSON_SIG_ID_NAME "sig_id"
#define JSON_SIG_REV_NAME "rev"
#define JSON_PRIORITY_NAME "priority"
#define DEFAULT_PRIORITY 0
#define JSON_CLASSIFICATION_NAME "classification"
#define DEFAULT_CLASSIFICATION 0
#define JSON_MSG_NAME "msg"
#define JSON_PROTO_NAME "proto"
#define JSON_ETHSRC_NAME "ethsrc"
#define JSON_ETHDST_NAME "ethdst"
#define JSON_ETHTYPE_NAME "ethtype"
#define JSON_UDPLENGTH_NAME "udplength"
#define JSON_ETHLENGTH_NAME "ethlength"
#define JSON_TRHEADER_NAME "trheader"
#define JSON_SRCPORT_NAME "srcport"
#define JSON_DSTPORT_NAME "dstport"
#define JSON_SRC_NAME "src"
#define JSON_SRC_STR_NAME "src_str"
#define JSON_SRC_NAME_NAME "src_name"
#define JSON_SRC_NET_NAME "src_net"
#define JSON_SRC_NET_NAME_NAME "src_net_name"
#define JSON_DST_NAME "dst"
#define JSON_DST_NAME_NAME "dst_name"
#define JSON_DST_STR_NAME "dst_str"
#define JSON_DST_NET_NAME "dst_net"
#define JSON_DST_NET_NAME_NAME "dst_net_name"
#define JSON_ICMPTYPE_NAME "icmptype"
#define JSON_ICMPCODE_NAME "icmpcode"
#define JSON_ICMPID_NAME "icmpid"
#define JSON_ICMPSEQ_NAME "icmpseq"
#define JSON_TTL_NAME "ttl"
#define JSON_TOS_NAME "tos"
#define JSON_ID_NAME "id"
#define JSON_IPLEN_NAME "iplen"
#define JSON_DGMLEN_NAME "dgmlen"
#define JSON_TCPSEQ_NAME "tcpseq"
#define JSON_TCPACK_NAME "tcpack"
#define JSON_TCPLEN_NAME "tcplen"
#define JSON_TCPWINDOW_NAME "tcpwindow"
#define JSON_TCPFLAGS_NAME "tcpflags"

#ifdef JSON_GEO_IP
#define JSON_SRC_COUNTRY_NAME "src_country"
#define JSON_DST_COUNTRY_NAME "dst_country"
#define JSON_SRC_COUNTRY_CODE_NAME "src_country_code"
#define JSON_DST_COUNTRY_CODE_NAME "dst_country_code"
#endif // JSON_GEO_IP


typedef struct _AlertJSONConfig
{
    char *type;
    struct _AlertJSONConfig *next;
} AlertJSONConfig;

typedef struct _IP_str_assoc{
    char * human_readable_str;
    char * number_as_str;
    sfip_t ip;
    struct _IP_str_assoc * next;
} IP_str_assoc;

typedef struct _AlertJSONData
{
    KafkaLog * kafka;
    char * jsonargs;
    char ** args;
    int numargs;
    AlertJSONConfig *config;
    IP_str_assoc * hosts, *nets;
    uint64_t sensor_id;
    char * sensor_name;
#ifdef JSON_GEO_IP
    GeoIP *gi;
#endif 
} AlertJSONData;


/* list of function prototypes for this preprocessor */
static void AlertJSONInit(char *);
static AlertJSONData *AlertJSONParseArgs(char *);
static void AlertJSON(Packet *, void *, uint32_t, void *);
static void AlertJSONCleanExit(int, void *);
static void AlertRestart(int, void *);
static void RealAlertJSON(
    Packet*, void*, uint32_t, char **args, int numargs, AlertJSONData * data
);

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


/* Enumeration for FillHostList 
 * @TODO put in a separate file
 */
typedef enum{HOSTS,NETWORKS,SERVICES,PROTOCOLS} FILLHOSTSLIST_MODE;

/*
 * @TODO put in a separate file
 */
static IP_str_assoc * FillHostList_Host(char *line_buffer){
    /* Assuming format of /etc/hosts: ip hostname */
    char ** toks=NULL;
    int num_toks;
    IP_str_assoc * node = SnortAlloc(sizeof(IP_str_assoc));
    if(node){
        toks = mSplit((char *)line_buffer, " \t", 2, &num_toks, '\\');
        node->number_as_str = SnortStrdup(toks[0]);
        node->human_readable_str = SnortStrdup(toks[1]);
        const SFIP_RET ret = sfip_pton(node->number_as_str, &node->ip);
        if(ret==SFIP_FAILURE){
            free(node->number_as_str);
            free(node->human_readable_str);
            free(node);
            node=NULL;
        }
        mSplitFree(&toks, num_toks);
    }
    return node;
}

/*
 * @TODO put in a separate file
 * @TODO same as FillHostList_Host except for node->number_as_str and human_readable_str order. merge?
 */
static IP_str_assoc * FillHostList_Net(char *line_buffer){
    /* Assuming format of /etc/hosts: ip hostname */
    char ** toks=NULL;
    int num_toks;
    IP_str_assoc * node = SnortAlloc(sizeof(IP_str_assoc));
    if(node){
        toks = mSplit((char *)line_buffer, " \t", 2, &num_toks, '\\');
        node->number_as_str = SnortStrdup(toks[1]);
        node->human_readable_str = SnortStrdup(toks[0]);
        const SFIP_RET ret = sfip_pton(node->number_as_str, &node->ip);
        if(ret==SFIP_FAILURE){
            free(node->number_as_str);
            free(node->human_readable_str);
            free(node);
            node=NULL;
        }
        mSplitFree(&toks, num_toks);
    }
    return node;
}

/*
 * Function FillHostsList
 *
 * Purpose: Fill a host/net -> ip assotiation list from a hosts or network file 
 *          (the format is the same as /etc/hosts and /etc/network)
 *
 * Arguments: filename => route to host/networks file
 *            list     => list to fill
 *            mode     => See FILLHOSTSLIST_MODE
 */
static void FillHostsList(const char * filename,IP_str_assoc ** list, const FILLHOSTSLIST_MODE mode){
    char line_buffer[1024];
    FILE * file;
    int aok=1;
    
    if((file = fopen(filename, "r")) == NULL)
    {
        FatalError("fopen() alert file %s: %s\n",filename, strerror(errno));
    }

    IP_str_assoc ** llinst_iterator = list;
    while(NULL != fgets(line_buffer,1024,file) && aok){
        if(line_buffer[0]!='#' && line_buffer[0]!='\n'){
            IP_str_assoc * ip_str;
            
            switch(mode){
                case HOSTS:
                    ip_str = FillHostList_Host(line_buffer); break;
                case NETWORKS:
                    ip_str = FillHostList_Net(line_buffer); break;
                case PROTOCOLS:
                    /* @TODO ip_str = FillHostList_Proto(line_buffer); */break;
                case SERVICES:
                    /* @TODO ip_str = FillHostList_Service(line_buffer); */break;
            };
            if(ip_str==NULL)
                FatalError("alert_json: cannot parse '%s' line in '%s' file\n",line_buffer,filename);
            *llinst_iterator = ip_str;
            llinst_iterator = &ip_str->next;
            ip_str->next=NULL;
        }
    }

    fclose(file);
}

IP_str_assoc * SearchStrIP(uint32_t ip,const IP_str_assoc *iplist){
    IP_str_assoc * node;
    sfip_t ip_to_cmp;
    const SFIP_RET ret = sfip_set_raw(&ip_to_cmp, &ip, AF_INET);
    if(ret!=SFIP_SUCCESS)
        FatalError("alert_json: Cannot create sfip to compare in line %lu",__LINE__);

    for(node = (IP_str_assoc *)iplist;node;node=node->next){
        if(sfip_equals(ip_to_cmp,node->ip))
            break;
    }
    return node;
}

IP_str_assoc * SearchStrNet(uint32_t ip,const IP_str_assoc *iplist){
    IP_str_assoc * node;
    sfip_t ip_to_cmp;
    const SFIP_RET ret = sfip_set_raw(&ip_to_cmp, &ip, AF_INET);
    if(ret!=SFIP_SUCCESS)
        FatalError("alert_json: Cannot create sfip to compare in line %lu",__LINE__);

    for(node = (IP_str_assoc *)iplist;node;node=node->next){
        if(sfip_fast_cont4(&node->ip,&ip_to_cmp))
            break;
    }
    return node;
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
 * Returns: void function
 */
static AlertJSONData *AlertJSONParseArgs(char *args)
{
    char **toks;
    int num_toks;
    AlertJSONData *data;
    char* filename = NULL;
    char* kafka_str = NULL;
    int i;
    char* hostsListPath = NULL;
    char* networksPath = NULL;
    char* services = NULL;
    char* protocols = NULL;

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

        if ( !strncasecmp(tok, "filename=",strlen("filename=")) && !filename){
            filename = SnortStrdup(tok+strlen("filename="));
        }else if(!strncasecmp(tok,"params=",strlen("params=")) && !data->jsonargs){
            data->jsonargs = SnortStrdup(tok+strlen("params="));
        }else if(!strncasecmp(tok, KAFKA_PROT,strlen(KAFKA_PROT)) && !kafka_str){
            kafka_str = SnortStrdup(tok);
        }else if ( !strncasecmp("default", tok,strlen("default")) && !data->jsonargs){
            data->jsonargs = SnortStrdup(DEFAULT_JSON);
        }else if(!strncmp(tok,"sensor_name=",strlen("sensor_name=")) && !data->sensor_name){
			data->sensor_name = SnortStrdup(tok+strlen("sensor_name="));
		}else if(!strncmp(tok,"sensor_id=",strlen("sensor_id="))){
	        data->sensor_id = atol(tok + strlen("sensor_id="));
        }else if(!strncmp(tok,"hostsListPath=",strlen("hostsListPath="))){
            hostsListPath = SnortStrdup(tok+strlen("hostsListPath="));
        }else if(!strncmp(tok,"networksPath=",strlen("networksPath="))){
            networksPath = SnortStrdup(tok+strlen("networksPath="));
        }else if(!strncmp(tok,"services=",strlen("services="))){
            services = SnortStrdup(tok+strlen("services="));
        }else if(!strncmp(tok,"protocols=",strlen("protocols="))){
            protocols = SnortStrdup(tok+strlen("protocols="));
        }else{
			FatalError("alert_json: Cannot parse %s(%i): %s\n",
			file_name, file_line, tok);
        }
    }

    /* DFEFAULT VALUES */
    if ( !data->jsonargs ) data->jsonargs = SnortStrdup(DEFAULT_JSON);
    if ( !data->sensor_name ) data->sensor_name = SnortStrdup("-");
    if ( !filename ) filename = ProcessFileOption(barnyard2_conf_for_parsing, DEFAULT_FILE);
    if ( !kafka_str ) kafka_str = SnortStrdup(DEFAULT_KAFKA_BROKER);

    mSplitFree(&toks, num_toks);
    toks = mSplit(data->jsonargs, ",", 128, &num_toks, 0);

    data->args = toks;
    data->numargs = num_toks;

    FillHostsList("/etc/hosts",&data->hosts,HOSTS);
    FillHostsList("/etc/networks",&data->nets,NETWORKS);

#ifdef JSON_GEO_IP
    const char * geoIP_path = "/usr/local/share/GeoIP/GeoIP.dat";
    data->gi = GeoIP_open(geoIP_path, GEOIP_MEMORY_CACHE);

    if (data->gi == NULL)
        FatalError("Error opening database %s\n",geoIP_path);

#endif // JSON_GEO_IP

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
            KAFKA_PARTITION,BcDaemonMode()?0:1,filename==kafka_str?NULL:filename);
        free(kafka_server);
    }
    if ( filename ) free(filename);

    return data;
}

static void AlertJSONCleanup(int signal, void *arg, const char* msg)
{
    IP_str_assoc * ip_node=NULL;
    AlertJSONData *data = (AlertJSONData *)arg;
    /* close alert file */
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"%s\n", msg););

    if(data)
    {
        mSplitFree(&data->args, data->numargs);
        if(data->kafka)
            KafkaLog_Term(data->kafka);
        free(data->jsonargs);
        ip_node = data->hosts;
        while(ip_node){
            IP_str_assoc * aux = ip_node->next;
            free(ip_node->human_readable_str);
            free(ip_node->number_as_str);
            free(ip_node);
            ip_node = aux;
        }
        ip_node = data->nets;
        while(ip_node){
            IP_str_assoc * aux = ip_node->next;
            free(ip_node->human_readable_str);
            free(ip_node->number_as_str);
            free(ip_node);
            ip_node = aux;
        }

        #ifdef JSON_GEO_IP
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
    RealAlertJSON(p, event, event_type, data->args, data->numargs, data);
}

static bool inline PrintJSONFieldName(KafkaLog * kafka,const char *fieldName){
    return KafkaLog_Quote(kafka,fieldName) && KafkaLog_Puts(kafka,FIELD_NAME_VALUE_SEPARATOR);
}

static bool inline LogJSON_int(KafkaLog * kafka, const char * fieldName,uint64_t fieldValue,char * fmt){
    return PrintJSONFieldName(kafka,fieldName) && KafkaLog_Print(kafka,fmt,fieldValue);
}

static bool inline LogJSON_i64(KafkaLog * kafka,const char *fieldName,uint64_t fieldValue){
    return LogJSON_int(kafka,fieldName,fieldValue,"%"PRIu64);
}

static bool inline LogJSON_i32(KafkaLog * kafka,const char *fieldName,uint32_t fieldValue){
    return LogJSON_int(kafka,fieldName,fieldValue,"%"PRIu32);
}

static bool inline LogJSON_i16(KafkaLog * kafka,const char *fieldName,uint16_t fieldValue){
    return LogJSON_int(kafka,fieldName,fieldValue,"%"PRIu16);
}

static bool inline LogJSON_a(KafkaLog *kafka,const char *fieldName,const char *fieldValue){
    bool aok = 1;
    if(aok) aok = KafkaLog_Quote(kafka,fieldName);
    if(aok) aok = KafkaLog_Puts(kafka,FIELD_NAME_VALUE_SEPARATOR);
    if(aok) aok = KafkaLog_Quote(kafka,fieldValue);
    return aok;
}

/*
 * A faster replacement for inet_ntoa().
 * Extracted from tcpdump
 */
char* _intoa(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  u_int byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if (byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if (byte > 0)
        *--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}


/*
  * Function: RealAlertJSON(Packet *, char *, FILE *, char *, numargs const int)
 *
 * Purpose: Write a user defined JSON message
 *
 * Arguments:     p => packet. (could be NULL)
 *              msg => the message to send
 *             args => JSON output arguements
 *          numargs => number of arguements
 *             log => Log
 * Returns: void function
 *
 */
static void RealAlertJSON(Packet * p, void *event, uint32_t event_type,
        char **args, int numargs, AlertJSONData * jsonData)
{
    int num;
    SigNode *sn;
    char *type;
    char tcpFlags[9];

    KafkaLog * kafka = jsonData->kafka;

    if(p == NULL)
        return;

    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Logging JSON Alert data\n"););
    KafkaLog_Putc(kafka,'{');
    for (num = 0; num < numargs; num++)
    {
        type = args[num];

        DEBUG_WRAP(DebugMessage(DEBUG_LOG, "JSON Got type %s %d\n", type, num););

        if(!strncasecmp("timestamp", type, 9))
        {
            // LogOrKafka_Puts(log, kafka, JSON_FIELDS_SEPARATOR" "); // Commented cause timestamp will be the first always
            if(!LogJSON_i64(kafka,JSON_TIMESTAMP_NAME,p->pkth->ts.tv_sec*1000 + p->pkth->ts.tv_usec/1000))
                FatalError("Not enough buffer space to escape msg string\n");
        }
        else if(!strncasecmp("sensor_id",type,sizeof "sensor_id"))
        {
            KafkaLog_Puts(kafka,JSON_FIELDS_SEPARATOR);
            if(event != NULL)
            {
                if(!LogJSON_i32(kafka,JSON_SENSOR_ID_SNORT_NAME,ntohl(((Unified2EventCommon *)event)->sensor_id)))
                    FatalError("Not enough buffer space to escape msg string\n");
            }else{
                if(!LogJSON_i32(kafka,JSON_SENSOR_ID_SNORT_NAME,SENSOR_NOT_FOUND_NUMBER))
                    FatalError("Not enough buffer space to escape msg string\n");
            }

            KafkaLog_Puts(kafka,JSON_FIELDS_SEPARATOR);
            if(!LogJSON_i32(kafka,JSON_SENSOR_ID_NAME,jsonData->sensor_id))
                FatalError("Not enough buffer space to escape msg string\n");
		
            KafkaLog_Puts(kafka,JSON_FIELDS_SEPARATOR);
            if(!LogJSON_a(kafka,JSON_SENSOR_NAME_NAME,jsonData->sensor_name))
                FatalError("Not enough buffer space to escape msg string\n");

        }
        else if(!strncasecmp("sig_generator ",type,13))
        {
            if(event != NULL)
            {
                KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
                if(!LogJSON_i64(kafka,JSON_SIG_GENERATOR_NAME,ntohl(((Unified2EventCommon *)event)->generator_id)))
                    FatalError("Not enough buffer space to escape msg string\n");
                    
            }
        }
        else if(!strncasecmp("sig_id",type,6))
        {
            if(event != NULL)
            {
                KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
                if(!LogJSON_i64(kafka,JSON_SIG_ID_NAME,ntohl(((Unified2EventCommon *)event)->signature_id)))
                    FatalError("Not enough buffer space to escape msg string\n");
            }
        }
        else if(!strncasecmp("sig_rev",type,7))
        {
            if(event != NULL)
            {
                KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
                if(!LogJSON_i64(kafka,JSON_SIG_REV_NAME,ntohl(((Unified2EventCommon *)event)->signature_revision)))
                    FatalError("Not enough buffer space to escape msg string\n");
            }
        }
        else if(!strncasecmp("priority",type,sizeof "priority")){
            KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
            if(event != NULL)
            {
                if(!LogJSON_i32(kafka,JSON_PRIORITY_NAME, ntohl(((Unified2EventCommon *)event)->priority_id)))
                    FatalError("Not enough buffer space to escape msg string\n");
            }else{ /* Always log something */
                if(!LogJSON_i32(kafka,JSON_PRIORITY_NAME, DEFAULT_PRIORITY))
                    FatalError("Not enough buffer space to escape msg string\n");
            }
        }
        else if(!strncasecmp("classification",type,sizeof "classification")){
            KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
            if(event != NULL)
            {
                if(!LogJSON_i32(kafka,JSON_CLASSIFICATION_NAME, ntohl(((Unified2EventCommon *)event)->classification_id)))
                    FatalError("Not enough buffer space to escape msg string\n");
            }else{ /* Always log something */
                if(!LogJSON_i32(kafka,JSON_PRIORITY_NAME, DEFAULT_CLASSIFICATION))
                    FatalError("Not enough buffer space to escape msg string\n");
            }
        }
        else if(!strncasecmp("msg", type, 3))
        {
            if ( event != NULL )
            {
                sn = GetSigByGidSid(ntohl(((Unified2EventCommon *)event)->generator_id),
				    ntohl(((Unified2EventCommon *)event)->signature_id),
				    ntohl(((Unified2EventCommon *)event)->signature_revision));

                if (sn != NULL)
                {
                    KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
                    //const int msglen = strlen(sn->msg);
                    if(!LogJSON_a(kafka,JSON_MSG_NAME,sn->msg))
                    {
                        FatalError("Not enough buffer space to escape msg string\n");
                    }
                }
            }
        }
        else if(!strncasecmp("proto", type, 5))
        {
            KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
            if(IPH_IS_VALID(p))
            {

                switch (GET_IPH_PROTO(p))
                {
                    case IPPROTO_UDP:
                        LogJSON_a(kafka,JSON_PROTO_NAME,"UDP");
                        break;
                    case IPPROTO_TCP:
                        LogJSON_a(kafka,JSON_PROTO_NAME,"TCP");
                        break;
                    case IPPROTO_ICMP:
                        LogJSON_a(kafka,JSON_PROTO_NAME,"ICMP");
                        break;
                    default: /* Always log something */
                        LogJSON_a(kafka,JSON_PROTO_NAME,"-");
                        break;
                }
            }else{ /* Always log something */
                LogJSON_a(kafka,JSON_PROTO_NAME,"-");
            }
        }
        else if(!strncasecmp("ethsrc", type, 6))
        {
            if(p->eh)
            {
                KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
                PrintJSONFieldName(kafka,JSON_ETHSRC_NAME);
                KafkaLog_Print(kafka, "\"%X:%X:%X:%X:%X:%X\"", p->eh->ether_src[0],
                    p->eh->ether_src[1], p->eh->ether_src[2], p->eh->ether_src[3],
                    p->eh->ether_src[4], p->eh->ether_src[5]);
            }
        }
        else if(!strncasecmp("ethdst", type, 6))
        {
            if(p->eh)
            {
                KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
                PrintJSONFieldName(kafka,JSON_ETHDST_NAME);
                KafkaLog_Print(kafka, "\"%X:%X:%X:%X:%X:%X\"", p->eh->ether_dst[0],
                p->eh->ether_dst[1], p->eh->ether_dst[2], p->eh->ether_dst[3],
                p->eh->ether_dst[4], p->eh->ether_dst[5]);
            }
        }
        else if(!strncasecmp("ethtype", type, 7))
        {
            if(p->eh)
            {
                KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
                PrintJSONFieldName(kafka,JSON_ETHTYPE_NAME);
                KafkaLog_Print(kafka, "%"PRIu16,ntohs(p->eh->ether_type));
            }
        }
        else if(!strncasecmp("udplength", type, 9))
        {
            if(p->udph){
                KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
                PrintJSONFieldName(kafka,JSON_UDPLENGTH_NAME);
                KafkaLog_Print(kafka, "%"PRIu16,ntohs(p->udph->uh_len));
            }
        }
        else if(!strncasecmp("ethlen", type, 6))
        {
            if(p->eh){
                KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
                PrintJSONFieldName(kafka,JSON_ETHLENGTH_NAME);
                KafkaLog_Print(kafka, "%"PRIu16,p->pkth->len);
            }
        }
#if 0 /* Maybe in the future */
        else if(!strncasecmp("trheader", type, 8))
        {
            if(p->trh){
                KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
                PrintJSONFieldName(kafka,JSON_TRHEADER_NAME);
                LogTrHeader(kafka, p);
            }
        }
#endif

        else if(!strncasecmp("srcport", type, 7))
        {
            KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
            if(IPH_IS_VALID(p))
            {
                switch(GET_IPH_PROTO(p))
                {
                    case IPPROTO_UDP:
                    case IPPROTO_TCP:
                        LogJSON_i16(kafka,JSON_SRCPORT_NAME,p->sp);
                        break;
                    default: /* Always log something */
                        LogJSON_i16(kafka,JSON_SRCPORT_NAME,0);
                        break;
                }
            }else{ /* Always Log something */
                LogJSON_i16(kafka,JSON_SRCPORT_NAME,0);
            }
        }
        else if(!strncasecmp("dstport", type, 7))
        {
            KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
            if(IPH_IS_VALID(p))
            {
                switch(GET_IPH_PROTO(p))
                {
                    case IPPROTO_UDP:
                    case IPPROTO_TCP:
                        LogJSON_i16(kafka,JSON_DSTPORT_NAME,p->dp);
                        break;
                    default:
                        LogJSON_i16(kafka,JSON_DSTPORT_NAME,0);
                        break;
                }
            }else{ /* Always Log something */
                LogJSON_i16(kafka,JSON_DSTPORT_NAME,0);
            }
        }
        else if(!strncasecmp("src", type, 3)) // TODO merge with "dst" field
        {    
            static char buf[sizeof "ff:ff:ff:ff:ff:ff:255.255.255.255"];
            const size_t bufLen = sizeof buf;
            uint32_t ipv4 = IPH_IS_VALID(p) ? ntohl(GET_SRC_ADDR(p).s_addr) : 0;

            KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
            /*
                String version
                PrintJSONFieldName(kafka,JSON_SRC_NAME);
                LogOrKafka_Quote(log,kafka, inet_ntoa(GET_SRC_ADDR(p))); 
            */
            LogJSON_i32(kafka,JSON_SRC_NAME,ipv4);

            char * ip_str=NULL,*ip_name=NULL;
            IP_str_assoc * ip_str_node = SearchStrIP(ipv4,jsonData->hosts);
            if(ip_str_node){
                ip_str = ip_str_node->number_as_str;
                ip_name = ip_str_node->human_readable_str;
            }else{
                ip_name = ip_str = _intoa(ipv4, buf, bufLen);
            }
            KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
            LogJSON_a(kafka,JSON_SRC_STR_NAME,ip_str);

            KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
            LogJSON_a(kafka,JSON_SRC_NAME_NAME,ip_name);

            // networks
            IP_str_assoc * ip_net = SearchStrNet(ipv4,jsonData->nets);
            KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
            LogJSON_a(kafka,JSON_SRC_NET_NAME,ip_net?ip_net->number_as_str:"0.0.0.0/0");
            KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
            LogJSON_a(kafka,JSON_SRC_NET_NAME_NAME,ip_net?ip_net->human_readable_str:"0.0.0.0/0");

            #ifdef JSON_GEO_IP
            const char * country_name = GeoIP_country_name_by_ipnum(jsonData->gi,ipv4);
            const char * country_code =GeoIP_country_code_by_ipnum(jsonData->gi,ipv4);
            KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
            LogJSON_a(kafka,JSON_SRC_COUNTRY_NAME,country_name?country_name:"N/A");
            KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
            LogJSON_a(kafka,JSON_SRC_COUNTRY_CODE_NAME,country_code?country_code:"N/A");
            #endif
        }
        else if(!strncasecmp("dst", type, 3))
        {
            /* @TODO merge with "src" field */
            static char buf[sizeof "ff:ff:ff:ff:ff:ff:255.255.255.255"];
            const size_t bufLen = sizeof buf;
            uint32_t ipv4 = IPH_IS_VALID(p) ? ntohl(GET_DST_ADDR(p).s_addr) : 0;

            KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
            /*
                String version
                PrintJSONFieldName(log,kafka,JSON_SRC_NAME);
                LogOrKafka_Quote(log,kafka, inet_ntoa(GET_SRC_ADDR(p))); 
            */
            LogJSON_i32(kafka,JSON_DST_NAME,ipv4);

            char * ip_str=NULL,*ip_name=NULL;
            IP_str_assoc * ip_str_node = SearchStrIP(ipv4,jsonData->hosts);
            if(ip_str_node){
                ip_str = ip_str_node->number_as_str;
                ip_name = ip_str_node->human_readable_str;
            }else{
                ip_name = ip_str = _intoa(ipv4, buf, bufLen);
            }
            KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
            LogJSON_a(kafka,JSON_DST_STR_NAME,ip_str);

            KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
            LogJSON_a(kafka,JSON_DST_NAME_NAME,ip_name);

            // networks
            IP_str_assoc * ip_net = SearchStrNet(ipv4,jsonData->nets);
            KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
            LogJSON_a(kafka,JSON_DST_NET_NAME,ip_net?ip_net->number_as_str:"0.0.0.0/0");
            KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
            LogJSON_a(kafka,JSON_DST_NET_NAME_NAME,ip_net?ip_net->human_readable_str:"0.0.0.0/0");

            #ifdef JSON_GEO_IP
            const char * country_name = GeoIP_country_name_by_ipnum(jsonData->gi,ipv4);
            const char * country_code =GeoIP_country_code_by_ipnum(jsonData->gi,ipv4);
            KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
            LogJSON_a(kafka,JSON_DST_COUNTRY_NAME,country_name?country_name:"N/A");
            KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
            LogJSON_a(kafka,JSON_DST_COUNTRY_CODE_NAME,country_code?country_code:"N/A");
            #endif
        }
        else if(!strncasecmp("icmptype",type,8))
        {
            if(p->icmph)
            {
                KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
                PrintJSONFieldName(kafka,JSON_ICMPTYPE_NAME);
                KafkaLog_Print(kafka, "%d",p->icmph->type);
            }
        }
        else if(!strncasecmp("icmpcode",type,8))
        {
            if(p->icmph)
            {
                KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
                PrintJSONFieldName(kafka,JSON_ICMPCODE_NAME);
                KafkaLog_Print(kafka, "%d",p->icmph->code);
            }
        }
        else if(!strncasecmp("icmpid",type,6))
        {
            if(p->icmph){
                KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
                PrintJSONFieldName(kafka,JSON_ICMPID_NAME);
                KafkaLog_Print(kafka, "%d",ntohs(p->icmph->s_icmp_id));
            }
        }
        else if(!strncasecmp("icmpseq",type,7))
        {
            if(p->icmph){
                KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
                /* Doesn't work because "%d" arbitrary
                    PrintJSONFieldName(kafka,JSON_ICMPSEQ_NAME);
                    KafkaLog_Print(kafka, "%d",ntohs(p->icmph->s_icmp_seq));
                */
                LogJSON_i16(kafka,JSON_ICMPSEQ_NAME,ntohs(p->icmph->s_icmp_seq));
            }
        }
        else if(!strncasecmp("ttl",type,3))
        {
            if(IPH_IS_VALID(p)){
                KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
                PrintJSONFieldName(kafka,JSON_TTL_NAME);
                KafkaLog_Print(kafka, "%d",GET_IPH_TTL(p));
            }
        }
        else if(!strncasecmp("tos",type,3))
        {
            if(IPH_IS_VALID(p)){
                KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
                PrintJSONFieldName(kafka,JSON_TOS_NAME);
                KafkaLog_Print(kafka, "%d",GET_IPH_TOS(p));
            }
        }
        else if(!strncasecmp("id",type,2))
        {
            if(IPH_IS_VALID(p)){
                KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
                LogJSON_i16(kafka,JSON_ID_NAME,IS_IP6(p) ? ntohl(GET_IPH_ID(p)) : ntohs((u_int16_t)GET_IPH_ID(p)));
            } 
        }
        else if(!strncasecmp("iplen",type,5))
        {
            if(IPH_IS_VALID(p)){
                KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
                PrintJSONFieldName(kafka,JSON_IPLEN_NAME);
                KafkaLog_Print(kafka, "%d",GET_IPH_LEN(p) << 2);
            }
        }
        else if(!strncasecmp("dgmlen",type,6))
        {
            if(IPH_IS_VALID(p)){
                KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
                PrintJSONFieldName(kafka,JSON_DGMLEN_NAME);
                // XXX might cause a bug when IPv6 is printed?
                KafkaLog_Print(kafka, "%d",ntohs(GET_IPH_LEN(p)));
            }
        }
        else if(!strncasecmp("tcpseq",type,6))
        {
            if(p->tcph){
                KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
                // PrintJSONFieldName(kafka,JSON_TCPSEQ_NAME);                     // hex format
                // KafkaLog_Print(kafka, "lX%0x",(u_long) ntohl(p->tcph->th_ack)); // hex format
                LogJSON_i32(kafka,JSON_TCPSEQ_NAME,ntohl(p->tcph->th_seq));
            }
        }
        else if(!strncasecmp("tcpack",type,6))
            {
            if(p->tcph){
                KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
                // PrintJSONFieldName(kafka,JSON_TCPACK_NAME);
                // KafkaLog_Print(kafka, "0x%lX",(u_long) ntohl(p->tcph->th_ack));
                LogJSON_i32(kafka,JSON_TCPACK_NAME,ntohl(p->tcph->th_ack));
            }
        }

        else if(!strncasecmp("tcplen",type,6))
        {
            if(p->tcph){
                KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
                PrintJSONFieldName(kafka,JSON_TCPLEN_NAME);
                KafkaLog_Print(kafka, "%d",TCP_OFFSET(p->tcph) << 2);
            }
        }
        else if(!strncasecmp("tcpwindow",type,9))
        {
            if(p->tcph){
                KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
                //PrintJSONFieldName(kafka,JSON_TCPWINDOW_NAME);         // hex format
                //KafkaLog_Print(kafka, "0x%X",ntohs(p->tcph->th_win));  // hex format
                LogJSON_i16(kafka,JSON_TCPWINDOW_NAME,ntohs(p->tcph->th_win));
            }
        }
        else if(!strncasecmp("tcpflags",type,8))
        {
            if(p->tcph)
            {
                KafkaLog_Puts(kafka, JSON_FIELDS_SEPARATOR);
                CreateTCPFlagString(p, tcpFlags);
                PrintJSONFieldName(kafka,JSON_TCPFLAGS_NAME);
                KafkaLog_Quote(kafka, tcpFlags);
            }
        }

    }

    KafkaLog_Putc(kafka,'}');
    KafkaLog_Flush(kafka);
}

