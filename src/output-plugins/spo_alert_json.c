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
#include "errno.h"
#include "signal.h"
#include "log_text.h"

#ifdef HAVE_GEOIP
#include "GeoIP.h"
#endif // HAVE_GEOIP


#define DEFAULT_JSON "timestamp,sensor_id,sensor_id_snort,sig_generator,sig_id,sig_rev,priority,classification,msg,payload,proto,src,src_str,src_name,src_net,src_net_name,dst_name,dst_str,dst_net,dst_net_name,src_country,dst_country,src_country_code,dst_country_code,srcport,dst,dstport,ethsrc,ethdst,ethlen,tcpflags,tcpseq,tcpack,tcplen,tcpwindow,ttl,tos,id,dgmlen,iplen,icmptype,icmpcode,icmpid,icmpseq"

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

#define TIMESTAMP 1
#define SENSOR_ID_SNORT 2
#define SENSOR_ID 3
#define SENSOR_NAME 4
#define SIG_GENERATOR 5
#define SIG_ID 6
#define SIG_REV 7
#define PRIORITY 8
#define CLASSIFICATION 9
#define MSG 10
#define PAYLOAD 11
#define PROTO 12
#define PROTO_ID 13
#define ETHSRC 14
#define ETHDST 15
#define ETHTYPE 16
#define UDPLENGTH 17
#define ETHLENGTH 18
#define TRHEADER 19
#define SRCPORT 20
#define DSTPORT 21
#define SRCPORT_NAME 22
#define DSTPORT_NAME 23
#define SRC_TEMPLATE_ID 24
#define SRC_STR 25
#define SRC_NAME 26
#define SRC_NET 27
#define SRC_NET_NAME 28
#define DST_TEMPLATE_ID 29
#define DST_NAME 30
#define DST_STR 31
#define DST_NET 32
#define DST_NET_NAME 33
#define ICMPTYPE 34
#define ICMPCODE 35
#define ICMPID 36
#define ICMPSEQ 37
#define TTL 38
#define TOS 39
#define ID 40
#define IPLEN 41
#define DGMLEN 42
#define TCPSEQ 43
#define TCPACK 44
#define TCPLEN 45
#define TCPWINDOW 46
#define TCPFLAGS 47

#ifdef HAVE_GEOIP
#define SRC_COUNTRY 48
#define DST_COUNTRY 49
#define SRC_COUNTRY_CODE 50
#define DST_COUNTRY_CODE 51
#endif // HAVE_GEOIP

#define TEMPLATE_END_ID 52 /* Remember to update it if some template element is added */

typedef enum{stringFormat,numericFormat} JsonPrintFormat;

typedef struct{
    const uint32_t id;
    const char * templateName;
    const char * jsonName;
    const JsonPrintFormat printFormat;
    void * defaultValue;
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
    Number_str_assoc * hosts, *nets, *services, *protocols;
    uint64_t sensor_id;
    char * sensor_name;
#ifdef HAVE_GEOIP
    GeoIP *gi;
#endif 
} AlertJSONData;

/* Remember update printElementWithTemplate if some element modified here */
static AlertJSONTemplateElement template[] = {
    {TIMESTAMP,"timestamp","event_timestamp",numericFormat,0},
    {SENSOR_ID_SNORT,"sensor_id_snort","sensor_id_snort",numericFormat,0},
    {SENSOR_ID,"sensor_id","sensor_id",numericFormat,0},
    {SENSOR_NAME,"sensor_name","sensor_name",stringFormat,"-"},
    {SIG_GENERATOR,"sig_generator","sig_generator",numericFormat,0},
    {SIG_ID,"sig_id","sig_id",numericFormat,0},
    {SIG_REV,"sig_rev","rev",numericFormat,0},
    {PRIORITY,"priority","priority",numericFormat,0},
    {CLASSIFICATION,"classification","classification",stringFormat,"-"},
    {MSG,"msg","msg",stringFormat,"-"},
    {PAYLOAD,"payload","payload",stringFormat,"-"},
    {PROTO,"proto","proto",stringFormat,"-"},
    {PROTO_ID,"proto_id","proto_id",numericFormat,0},
    {ETHSRC,"ethsrc","ethsrc",stringFormat,"-"},
    {ETHDST,"ethdst","ethdst",stringFormat,"-"},
    {ETHTYPE,"ethtype","ethtype",numericFormat,0},
    {UDPLENGTH,"udplength","udplength",numericFormat,0},
    {ETHLENGTH,"ethlen","ethlength",numericFormat,0},
    {TRHEADER,"trheader","trheader",stringFormat,"-"},
    {SRCPORT,"srcport","srcport",numericFormat,0},
    {SRCPORT_NAME,"srcport_name","srcport_name",stringFormat,"-"},
    {DSTPORT,"dstport","dstport",numericFormat,0},
    {DSTPORT_NAME,"dstport_name","dstport_name",stringFormat,"-"},
    {SRC_TEMPLATE_ID,"src","src",numericFormat,0}, 
    {SRC_STR,"src_str","src_str",stringFormat,"-"},
    {SRC_NAME,"src_name","src_name",stringFormat,"-"},
    {SRC_NET,"src_net","src_net",stringFormat,"0.0.0.0/0"},
    {SRC_NET_NAME,"src_net_name","src_net_name",stringFormat,"0.0.0.0/0"},
    {DST_TEMPLATE_ID,"dst","dst",numericFormat,0}, 
    {DST_NAME,"dst_name","dst_name",stringFormat,"-"},
    {DST_STR,"dst_str","dst_str",stringFormat,"-"},
    {DST_NET,"dst_net","dst_net",stringFormat,"0.0.0.0/0"},
    {DST_NET_NAME,"dst_net_name","dst_net_name",stringFormat,"0.0.0.0/0"},
    {ICMPTYPE,"icmptype","icmptype",numericFormat,0},
    {ICMPCODE,"icmpcode","icmpcode",numericFormat,0},
    {ICMPID,"icmpid","icmpid",numericFormat,0},
    {ICMPSEQ,"icmpseq","icmpseq",numericFormat,0},
    {TTL,"ttl","ttl",numericFormat,0},
    {TOS,"tos","tos",numericFormat,0},
    {ID,"id","id",numericFormat,0},
    {IPLEN,"iplen","iplen",numericFormat,0},
    {DGMLEN,"dgmlen","dgmlen",numericFormat,0},
    {TCPSEQ,"tcpseq","tcpseq",numericFormat,0},
    {TCPACK,"tcpack","tcpack",numericFormat,0},
    {TCPLEN,"tcplen","tcplen",numericFormat,0},
    {TCPWINDOW,"tcpwindow","tcpwindow",numericFormat,0},
    {TCPFLAGS,"tcpflags","tcpflags",stringFormat,"-"},
    #ifdef HAVE_GEOIP
    {SRC_COUNTRY,"src_country","src_country",stringFormat,"N/A"},
    {DST_COUNTRY,"dst_country","dst_country",stringFormat,"N/A"},
    {SRC_COUNTRY_CODE,"src_country_code","src_country_code",stringFormat,"N/A"},
    {DST_COUNTRY_CODE,"dst_country_code","dst_country_code",stringFormat,"N/A"},
    #endif /* HAVE_GEOIP */
    {TEMPLATE_END_ID,"","",numericFormat,0}
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
    char* servicesPath = NULL;
    char* protocolsPath = NULL;
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

        if ( !strncasecmp(tok, "filename=",strlen("filename=")) && !filename){
            filename = SnortStrdup(tok+strlen("filename="));
        }else if(!strncasecmp(tok,"params=",strlen("params=")) && !data->jsonargs){
            data->jsonargs = SnortStrdup(tok+strlen("params="));
        }else if(!strncasecmp(tok, KAFKA_PROT,strlen(KAFKA_PROT)) && !kafka_str){
            kafka_str = SnortStrdup(tok);
        }else if ( !strncasecmp("default", tok,strlen("default")) && !data->jsonargs){
            data->jsonargs = SnortStrdup(DEFAULT_JSON);
        }else if(!strncasecmp(tok,"sensor_name=",strlen("sensor_name=")) && !data->sensor_name){
			data->sensor_name = SnortStrdup(tok+strlen("sensor_name="));
		}else if(!strncasecmp(tok,"sensor_id=",strlen("sensor_id="))){
	        data->sensor_id = atol(tok + strlen("sensor_id="));
        }else if(!strncasecmp(tok,"hosts=",strlen("hosts="))){
            hostsListPath = SnortStrdup(tok+strlen("hosts="));
        }else if(!strncasecmp(tok,"networks=",strlen("networks="))){
            networksPath = SnortStrdup(tok+strlen("networks="));
        }else if(!strncasecmp(tok,"services=",strlen("services="))){
            servicesPath = SnortStrdup(tok+strlen("services="));
        }else if(!strncasecmp(tok,"protocols=",strlen("protocols="))){
            protocolsPath = SnortStrdup(tok+strlen("protocols="));
        }else if(!strncasecmp(tok,"start_partition=",strlen("start_partition="))){
            start_partition = end_partition = atol(tok+strlen("start_partition="));
        }else if(!strncasecmp(tok,"end_partition=",strlen("end_partition="))){
            end_partition = atol(tok+strlen("end_partition="));
        #ifdef HAVE_GEOIP
        }else if(!strncasecmp(tok,"geoip=",strlen("geoip="))){
            geoIP_path = SnortStrdup(tok+strlen("geoip="));
        #endif // HAVE_GEOIP
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
    if(hostsListPath) FillHostsList(hostsListPath,&data->hosts,HOSTS);
    if(networksPath) FillHostsList(networksPath,&data->nets,NETWORKS);
    if(servicesPath) FillHostsList(servicesPath,&data->services,SERVICES);
    if(protocolsPath) FillHostsList(protocolsPath,&data->protocols,PROTOCOLS);

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
        freeNumberStrAssocList(data->hosts);
        freeNumberStrAssocList(data->nets);
        freeNumberStrAssocList(data->services);
        freeNumberStrAssocList(data->protocols);
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

static bool inline PrintJSONFieldName(KafkaLog * kafka,const char *fieldName){
    return KafkaLog_Quote(kafka,fieldName) && KafkaLog_Puts(kafka,FIELD_NAME_VALUE_SEPARATOR);
}

static bool inline LogJSON_int(KafkaLog * kafka, const char * fieldName,uint64_t fieldValue,char * fmt){
    return PrintJSONFieldName(kafka,fieldName) && KafkaLog_Print(kafka,fmt,fieldValue);
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
 * Function: PrintElementWithTemplate(Packet *, char *, FILE *, char *, numargs const int)
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
static int printElementWithTemplate(Packet * p, void *event, uint32_t event_type, AlertJSONData *jsonData, AlertJSONTemplateElement *templateElement){
    SigNode *sn;
    char tcpFlags[9];
    char buf[sizeof "ff:ff:ff:ff:ff:ff:255.255.255.255"];
    const size_t bufLen = sizeof buf;
    KafkaLog * kafka = jsonData->kafka;
    uint32_t ipv4 = 0;
    const int initial_buffer_pos = kafka->pos;

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
                ipv4 = GET_SRC_ADDR(p).s_addr;
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
                ipv4 = GET_DST_ADDR(p).s_addr;
                break;
        };
    }

    switch(templateElement->id){
        case TIMESTAMP:
            KafkaLog_Print(kafka,"%"PRIu64,p->pkth->ts.tv_sec*1000 + p->pkth->ts.tv_usec/1000);
            break;
        case SENSOR_ID_SNORT:
            KafkaLog_Print(kafka,"%"PRIu32,event?ntohl(((Unified2EventCommon *)event)->sensor_id):(uint64_t)templateElement->defaultValue);
            break;
        case SENSOR_ID:
            KafkaLog_Print(kafka,"%"PRIu32,jsonData->sensor_id);
            break;
        case SENSOR_NAME:
            KafkaLog_Print(kafka,jsonData->sensor_name);
            break;
        case SIG_GENERATOR:
            if(event != NULL)
                KafkaLog_Print(kafka,"%"PRIu64,ntohl(((Unified2EventCommon *)event)->generator_id));
            break;
        case SIG_ID:
            if(event != NULL)
                KafkaLog_Print(kafka,"%"PRIu64,ntohl(((Unified2EventCommon *)event)->signature_id));
            break;
        case SIG_REV:
            if(event != NULL)
                KafkaLog_Print(kafka,"%"PRIu64,ntohl(((Unified2EventCommon *)event)->signature_revision));
            break;
        case PRIORITY:
            KafkaLog_Print(kafka,"%"PRIu32, event != NULL ? ntohl(((Unified2EventCommon *)event)->priority_id) : (uint64_t)templateElement->defaultValue);
            break;
        case CLASSIFICATION:
            if(event != NULL)
            {
                uint32_t classification_id = ntohl(((Unified2EventCommon *)event)->classification_id);
                const ClassType *cn = ClassTypeLookupById(barnyard2_conf, classification_id);
                KafkaLog_Print(kafka,cn?cn->name:(const char *)templateElement->defaultValue);
            }else{ /* Always log something */
                KafkaLog_Print(kafka, (const char *)templateElement->defaultValue);
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
                    KafkaLog_Print(kafka,sn->msg);
                }
            }
            break;
        case PAYLOAD:
            {
                uint16_t i;
                if(p &&  p->dsize>0){
                    for(i=0;i<p->dsize;++i)
                        KafkaLog_Print(kafka, "%"PRIx8, p->data[i]);
                }else{
                    KafkaLog_Puts(kafka, (const char *)templateElement->defaultValue);
                }
            }
            break;

        case PROTO:
            if(IPH_IS_VALID(p)){
                Number_str_assoc * service_name_asoc = SearchNumberStr(GET_IPH_PROTO(p),jsonData->protocols,PROTOCOLS);
                KafkaLog_Print(kafka,"%s",service_name_asoc?service_name_asoc->human_readable_str:(const char *)templateElement->defaultValue);
            }else{ /* Always log something */
                KafkaLog_Print(kafka,"%s",(const char *)templateElement->defaultValue);
            }
            break;
        case PROTO_ID:
            KafkaLog_Print(kafka,"%"PRIu16,IPH_IS_VALID(p)?GET_IPH_PROTO(p):0);
            break;

        case ETHSRC:
            if(p->eh)
            {
                KafkaLog_Print(kafka, "%X:%X:%X:%X:%X:%X", p->eh->ether_src[0],
                    p->eh->ether_src[1], p->eh->ether_src[2], p->eh->ether_src[3],
                    p->eh->ether_src[4], p->eh->ether_src[5]);
            }
            break;

        case ETHDST:
            if(p->eh)
            {
                KafkaLog_Print(kafka, "%X:%X:%X:%X:%X:%X", p->eh->ether_dst[0],
                p->eh->ether_dst[1], p->eh->ether_dst[2], p->eh->ether_dst[3],
                p->eh->ether_dst[4], p->eh->ether_dst[5]);
            }
            break;

        case ETHTYPE:
            if(p->eh)
            {
                KafkaLog_Print(kafka, "%"PRIu16,ntohs(p->eh->ether_type));
            }
            break;

        case UDPLENGTH:
            if(p->udph){
                KafkaLog_Print(kafka, "%"PRIu16,ntohs(p->udph->uh_len));
            }
            break;
        case ETHLENGTH:
            if(p->eh){
                KafkaLog_Print(kafka, "%"PRIu16,p->pkth->len);
            }
            break;

        case SRCPORT:
        case DSTPORT:
            if(IPH_IS_VALID(p))
            {
                switch(GET_IPH_PROTO(p))
                {
                    case IPPROTO_UDP:
                    case IPPROTO_TCP:
                    {
                        KafkaLog_Print(kafka,"%"PRIu16,templateElement->id==SRCPORT? p->sp:p->dp);
                    }
                        break;
                    default: /* Always log something */
                        KafkaLog_Print(kafka,"%"PRIu16,0);
                        break;
                }
            }else{ /* Always Log something */
                KafkaLog_Print(kafka,"%"PRIu16,0);
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
                        Number_str_assoc * service_name_asoc = SearchNumberStr(port,jsonData->services,SERVICES);
                        KafkaLog_Print(kafka,"%s",service_name_asoc?service_name_asoc->human_readable_str:(const char *)templateElement->defaultValue);
                    }
                        break;
                    default: /* Always log something */
                        KafkaLog_Print(kafka,"%s",(const char *)templateElement->defaultValue);
                        break;
                };
            }else{ /* Always Log something */
                KafkaLog_Print(kafka,"%s",(const char *)templateElement->defaultValue);
            }
            break;

        case SRC_TEMPLATE_ID:
            KafkaLog_Print(kafka,"%"PRIu32,ipv4);
            break;
        case DST_TEMPLATE_ID:
            KafkaLog_Print(kafka,"%"PRIu32,ipv4);
            break;
        case SRC_STR:
        case DST_STR:
            {
                KafkaLog_Print(kafka,"%s",_intoa(ipv4, buf, bufLen));
            }
            break;
        case SRC_NAME:
        case DST_NAME:
            {
                Number_str_assoc * ip_str_node = SearchNumberStr(ipv4,jsonData->hosts,HOSTS);
                const char * ip_name = ip_str_node ? ip_str_node->human_readable_str : _intoa(ipv4, buf, bufLen);
                KafkaLog_Print(kafka, "%s",ip_name);
            }
            break;
        case SRC_NET:
        case DST_NET:
            {
                Number_str_assoc * ip_net = SearchNumberStr(ipv4,jsonData->nets,NETWORKS);
                KafkaLog_Print(kafka,"%s",ip_net?ip_net->number_as_str:(const char *)templateElement->defaultValue);
            }
            break;
        case SRC_NET_NAME:
        case DST_NET_NAME:
            {
                Number_str_assoc * ip_net = SearchNumberStr(ipv4,jsonData->nets,NETWORKS);
                KafkaLog_Print(kafka,"%s",ip_net?ip_net->human_readable_str:(const char *)templateElement->defaultValue);
            }
            break;

#ifdef HAVE_GEOIP
        case SRC_COUNTRY:
        case DST_COUNTRY:
            if(jsonData->gi){
                const char * country_name = GeoIP_country_name_by_ipnum(jsonData->gi,ipv4);
                KafkaLog_Print(kafka,"%s",country_name?country_name:(const char *)templateElement->defaultValue);
            }
            break;
        case SRC_COUNTRY_CODE:
        case DST_COUNTRY_CODE:
            if(jsonData->gi){
                const char * country_code =GeoIP_country_code_by_ipnum(jsonData->gi,ipv4);
                KafkaLog_Print(kafka,"%s",country_code?country_code:(const char *)templateElement->defaultValue);
            }
            break;
#endif /* HAVE_GEOIP */

        case ICMPTYPE:
            if(p->icmph){
                KafkaLog_Print(kafka, "%d",p->icmph->type);
            }
            break;
        case ICMPCODE:
            if(p->icmph)
            {
                KafkaLog_Print(kafka, "%d",p->icmph->code);
            }
            break;
        case ICMPID:
            if(p->icmph){
                KafkaLog_Print(kafka, "%d",ntohs(p->icmph->s_icmp_id));
            }
            break;
        case ICMPSEQ:
            if(p->icmph){
                /* Doesn't work because "%d" arbitrary
                    PrintJSONFieldName(kafka,JSON_ICMPSEQ_NAME);
                    KafkaLog_Print(kafka, "%d",ntohs(p->icmph->s_icmp_seq));
                */
                KafkaLog_Print(kafka,"%"PRIu16,ntohs(p->icmph->s_icmp_seq));
            }
            break;
        case TTL:
            if(IPH_IS_VALID(p)){
                KafkaLog_Print(kafka, "%d",GET_IPH_TTL(p));
            }
            break;

        case TOS: 
            if(IPH_IS_VALID(p)){
                KafkaLog_Print(kafka, "%d",GET_IPH_TOS(p));
            }
            break;
        case ID:
            if(IPH_IS_VALID(p)){
                KafkaLog_Print(kafka,"%"PRIu16,IS_IP6(p) ? ntohl(GET_IPH_ID(p)) : ntohs((u_int16_t)GET_IPH_ID(p)));
            } 
            break;
        case IPLEN:
            if(IPH_IS_VALID(p)){
                KafkaLog_Print(kafka, "%d",GET_IPH_LEN(p) << 2);
            }
            break;
        case DGMLEN:
            if(IPH_IS_VALID(p)){
                // XXX might cause a bug when IPv6 is printed?
                KafkaLog_Print(kafka, "%d",ntohs(GET_IPH_LEN(p)));
            }
            break;

        case TCPSEQ:
            if(p->tcph){
                // PrintJSONFieldName(kafka,JSON_TCPSEQ_NAME);                     // hex format
                // KafkaLog_Print(kafka, "lX%0x",(u_long) ntohl(p->tcph->th_ack)); // hex format
                KafkaLog_Print(kafka,"%"PRIx32,ntohl(p->tcph->th_seq));
            }
            break;
        case TCPACK:
            if(p->tcph){
                // PrintJSONFieldName(kafka,JSON_TCPACK_NAME);
                // KafkaLog_Print(kafka, "0x%lX",(u_long) ntohl(p->tcph->th_ack));
                KafkaLog_Print(kafka,"%"PRIx32,ntohl(p->tcph->th_ack));
            }
            break;
        case TCPLEN:
            if(p->tcph){
                KafkaLog_Print(kafka, "%d",TCP_OFFSET(p->tcph) << 2);
            }
            break;
        case TCPWINDOW:
            if(p->tcph){
                //PrintJSONFieldName(kafka,JSON_TCPWINDOW_NAME);         // hex format
                //KafkaLog_Print(kafka, "0x%X",ntohs(p->tcph->th_win));  // hex format
                KafkaLog_Print(kafka,"%"PRIx16,ntohs(p->tcph->th_win));
            }
            break;
        case TCPFLAGS:
            if(p->tcph)
            {
                CreateTCPFlagString(p, tcpFlags);
                KafkaLog_Quote(kafka, tcpFlags);
            }
            break;

        default:
            *(int *)NULL = 0;
            FatalError("Template id %d not found",templateElement->id); /* just for sanity */
            break;
    };

    return kafka->pos-initial_buffer_pos; /* if we have write something */
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
static void RealAlertJSON(Packet * p, void *event, uint32_t event_type, AlertJSONData * jsonData)
{
    TemplateElementsList * iter;

    KafkaLog * kafka = jsonData->kafka;

    if(p == NULL)
        return;

    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Logging JSON Alert data\n"););
    KafkaLog_Putc(kafka,'{');
    for(iter=jsonData->outputTemplate;iter;iter=iter->next){
        const int initial_pos = kafka->pos;
        if(iter!=jsonData->outputTemplate)
            KafkaLog_Puts(kafka,JSON_FIELDS_SEPARATOR);

        KafkaLog_Print(kafka,"\"%s\":",iter->templateElement->jsonName);

        if(iter->templateElement->printFormat==stringFormat)
            KafkaLog_Putc(kafka,'"');
        const int writed = printElementWithTemplate(p,event,event_type,jsonData,iter->templateElement);
        if(iter->templateElement->printFormat==stringFormat)
            KafkaLog_Putc(kafka,'"');

        if(0==writed)
            kafka->pos = initial_pos; // Revert the insertion of empty element */
    }

    KafkaLog_Putc(kafka,'}');
    // Just for debug
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"[KAFKA]: %s",kafka->buf););
    KafkaLog_Flush(kafka);
}

