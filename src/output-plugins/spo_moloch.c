/*
 ** Copyright (C) 2018 Joseph Landry <jolan78@gmail.com>
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

/* spo_alert_moloch
 *
 * Purpose:
 *
 * This module tags sessions using moloch API
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef ENABLE_PLUGIN_MOLOCH

#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <json-c/json_tokener.h>

#include "barnyard2.h"
#include "decode.h"
#include "debug.h"
#include "mstring.h"
#include "strlcpyu.h"
#include "plugbase.h"
#include "unified2.h"

#ifdef SUP_IP6
typedef sfip_t numip;
#define MOLOCH_IPTOSTR(x) inet_ntoa(&x)
#define MOLOCH_GET_ADDR(x) *x
#else
typedef struct in_addr numip;
#define MOLOCH_IPTOSTR(x) inet_ntoa(x)
#define MOLOCH_GET_ADDR(x) x
#endif

#define MOLOCH_MAX_SPOOLED_TAGS 6000

// records the response of curl API calls
struct curl_resp {
  char *ptr;
  size_t len;
};

#define MOLOCH_SPOOL_FILE_VERSION 1
/*
 * holds data necessary to tag, this will be dumped to the spool file
 * change MOLOCH_SPOOL_FILE_VERSION if you change the TagItem struct
 * must be in the range 1-126. negative values are for IP6 variant
 * hopefully we should be safe but if not we can set 127 and check another byte
 */
typedef struct _TagInfo
  {
  uint32_t gen_id;
  uint32_t sig_id;
  uint32_t sig_rev;
  uint32_t timestamp;
  numip    ip_src;
  uint16_t sp;
  numip    ip_dst;
  uint16_t dp;
  uint8_t  proto;
  } TagInfo;

// linked list of tags waiting for moloch to index sessions to be submitted
typedef struct _TagItem
  {
  time_t lastTry;
  void    *next;
  TagInfo taginfo;
  } TagItem;

typedef struct _MolochData
  {
  char    *host;
  int      port;
  bool     ssl;
  char    *node;
  char    *user;
  char    *password;
  char    *spoolfile;
  bool     spoolFileHaveData;
  long     maxSpoolFileSize;
  bool     tag_message;
  CURL    *curl;
  uint32_t lastpacket;
  bool     apiStatus;
  uint32_t numSpooledTags;
  TagItem *SpooledTags;
  TagItem *SpoolTop;
  } MolochData;

/* constants */
#define KEYWORD_PORT              "port"
#define KEYWORD_HOST              "host"
#define KEYWORD_SSL               "ssl"
#define KEYWORD_NODE              "node"
#define KEYWORD_USER              "user"
#define KEYWORD_PASSWORD          "password"
#define KEYWORD_SPOOLFILE         "spool"
#define KEYWORD_MAXSPOOLFILESIZE  "max_spool_size"
#define KEYWORD_TAGMESSAGE        "tag_message"

// plug-in entry points
void MolochInit(char *);
void MolochPostConfig(int, void*);
void MolochProcess(Packet *, void *, u_int32_t, void *);
void MolochCleanUp(int, void *);
// private functions
MolochData *MolochParseArgs(char *);
char* MolochSearchSession(MolochData* ,TagInfo* );
void MolochFindLastSession(MolochData *, uint32_t, bool);
void MolochProcessTag(MolochData *,TagItem*);
void MolochAddTag(MolochData *,TagItem*,char*);
void MolochAddToSpool(MolochData *,TagItem*);
void MolochReadSpool(MolochData*);
void MolochWriteSpool(MolochData*);
void MolochSubmitSpool(MolochData*);
char* MolochGetSessions(MolochData*,char*,uint32_t);
void MolochLogMatchingSession(MolochData *,TagInfo *);
// API functions
void  MolochInitApi(MolochData *);
char* MolochCallApi(MolochData *,char* ,char* , char* );
void  MolochCheckApi(MolochData *);

// this functions can be used to debug tag operations
void printTagInfo(TagInfo* taginfo)
  {
  LogMessage("   gen_id:    %lu\n",taginfo->gen_id);
  LogMessage("   sig_id:    %lu\n",taginfo->sig_id);
  LogMessage("   sig_rev:   %lu\n",taginfo->sig_rev);
  LogMessage("   timestamp: %u\n",taginfo->timestamp);
  LogMessage("   ip_src:    %s\n",MOLOCH_IPTOSTR(taginfo->ip_src));
  LogMessage("   ip_dst:    %s\n",MOLOCH_IPTOSTR(taginfo->ip_dst));
  LogMessage("   sp:        %u\n",taginfo->sp);
  LogMessage("   dp:        %u\n",taginfo->dp);
  LogMessage("   proto:     %u\n",taginfo->proto);
  }

void printSpooledTags(MolochData* data,uint32_t max)
  {
  int i;
  TagItem * tagitem=data->SpooledTags;
  LogMessage("%u tags in spool. base = %p, top= %p\n",data->numSpooledTags,(void*)data->SpooledTags,(void*)data->SpoolTop);
  for(i=0;i<data->numSpooledTags && i<max;i++)
    {
    LogMessage(" tag %i at %p\n",i,(void*)tagitem);
    printTagInfo(&tagitem->taginfo);
    tagitem=tagitem->next;
    }
  }

/*
 * Function: MolochSetup()
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
void MolochSetup(void)
  {
  RegisterOutputPlugin("moloch", OUTPUT_TYPE_FLAG__ALERT, MolochInit);
  }

// curl write callback: fills a curl_resp struct with the response
size_t _curl_write(char *ptr, size_t size, size_t nmemb, struct curl_resp *resp)
  {
  size_t new_len = resp->len + size*nmemb;
  resp->ptr = realloc(resp->ptr, new_len+1);
  if (resp->ptr == NULL)
    FatalError("moloch: realloc() failed in curl callback\n");
  memcpy(resp->ptr+resp->len, ptr, size*nmemb);
  resp->ptr[new_len] = '\0';
  resp->len = new_len;

  return size*nmemb;
  }

// initialize data->curl
void MolochInitApi(MolochData *data)
  {
  if( data->curl == NULL )
    {
    curl_global_init(CURL_GLOBAL_ALL);
    data->curl = curl_easy_init();

    if( data->curl )
      {
      curl_easy_setopt(data->curl, CURLOPT_WRITEFUNCTION, &_curl_write);
      //curl_easy_setopt(data->curl, CURLOPT_ERRORBUFFER, curl_error_buf);
      curl_easy_setopt(data->curl, CURLOPT_USERNAME, data->user);
      curl_easy_setopt(data->curl, CURLOPT_PASSWORD, data->password);
      curl_easy_setopt(data->curl, CURLOPT_TIMEOUT, 30L);
      curl_easy_setopt(data->curl, CURLOPT_HTTPAUTH, CURLAUTH_DIGEST);
      if(data->ssl)
        {
        curl_easy_setopt(data->curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
        if(data->ssl == 2)
          {
          curl_easy_setopt(data->curl, CURLOPT_SSL_VERIFYPEER, 0);
          curl_easy_setopt(data->curl, CURLOPT_SSL_VERIFYHOST, 0);
          }
        }
      }
    else
      {
      FatalError("moloch[%s]: unable to allocate a CURL structure.\n",data->node);
      }
    }
  }

/*
 * Function: MolochCallApi(MolochData *,char* ,char* , char* )
 *
 * Purpose: Calls moloch API with optionally GET and/or POST data
 *
 * Arguments: endpoint => ptr to the API endpoint to call string
 *            query    => ptr to GET data string or NULL
 *            postdata => ptr to POST data string or NULL
 *
 * Returns: the server reply string or NULL
 *
 */
char* MolochCallApi(MolochData *data,char* endpoint,char* query, char* postdata)
  {
  CURLcode res;
  char uri[2048];
  long rc = 0;
  struct curl_resp resp;
  resp.len=0;
  resp.ptr = SnortAlloc(1);
  resp.ptr[0] = '\0';

  if (query != NULL)
    snprintf(uri, 2048, "http%s://%s:%d/%s?%s", data->ssl?"s":"", data->host, data->port,endpoint,query);
  else
    snprintf(uri, 2048, "http%s://%s:%d/%s", data->ssl?"s":"", data->host, data->port,endpoint);

#ifdef MOLOCH_DEBUG_API
  if(BcLogVerbose())LogMessage("MolochCallApi> URI: %s\n",uri);
#endif

  curl_easy_setopt(data->curl, CURLOPT_URL, uri);
  curl_easy_setopt(data->curl, CURLOPT_WRITEDATA, &resp);

  if (postdata != NULL)
    {
#ifdef MOLOCH_DEBUG_API
    if(BcLogVerbose())LogMessage("MolochCallApi> POST: %s\n",postdata);
#endif
    curl_easy_setopt(data->curl, CURLOPT_POSTFIELDS, postdata);
    }
  else // switch back to GET
    curl_easy_setopt(data->curl, CURLOPT_POST, 0);


  if( ( res = curl_easy_perform(data->curl) ) == CURLE_OK )
    {
    curl_easy_getinfo(data->curl, CURLINFO_RESPONSE_CODE, &rc);

    if( rc == 401 )
      FatalError("moloch[%s]: API access forbidden\n",data->node);
    else if( rc != 200 )
      ErrorMessage( "moloch[%s]: API call returned response code %lu. response: %s\n", data->node, rc,resp);
    else
      {
#ifdef MOLOCH_DEBUG_API
      if(BcLogVerbose())LogMessage("MolochCallApi> resp:\n%s\n",resp);
#endif 
      return resp.ptr; // success
      }
    }
  else
    ErrorMessage("moloch[%s]: curl error : %s\n",data->node,curl_easy_strerror(res));
  // failure
  data->apiStatus=false;
  return NULL;
  }

/*
 * Function: MolochCheckApi()
 *
 * Purpose: calls stats.json API and naively check that the response is correct
 *          on failure, the API status will be checked again after 10sec.
 *
 * Returns: void function
 *
 */
void MolochCheckApi(MolochData *data)
  {
  char* resp;
  static time_t next_retry =0;
  time_t now =time(NULL);
  json_object *json,*entry;
  int64_t nrec;

  if(now < next_retry)
    return;

  next_retry=now+10;

  data->apiStatus=false;
  resp = MolochCallApi(data,"stats.json",NULL,NULL);
  if(resp == NULL)
    ErrorMessage("moloch[%s]: unable to connect to moloch API.\n",data->node);
  else
    {
    json = json_tokener_parse(resp);
    if(json != NULL)
      {
      if(json_object_object_get_ex(json,"recordsTotal",&entry))
        {
        if(!json_object_is_type(entry,json_type_int))
          FatalError("moloch[%s]: unexpected type for 'recordsTotal' in : \n%s\n",data->node,resp);
        else
          {
          nrec = json_object_get_int64(entry);
          if(nrec == 0)
            ErrorMessage("moloch[%s]: Moloch reports 0 records.\n",data->node);
          else
            data->apiStatus=true;
          }
        }
      else
        FatalError("moloch[%s]: could not find 'recordsTotal' in : %s.\n",data->node,resp);
      free(json);
      }
    else
      FatalError("moloch[%s]: Unexpected stats.json response:\n%s\n",data->node,resp);
    }
  free(resp);
  }

/*
 * Function: MolochInit(char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
void MolochInit(char *args)
  {
  MolochData *data;
  FILE *fp;

  /* parse the argument list from the rules file */
  data = MolochParseArgs(args);
  data->lastpacket = 0;
  data->SpooledTags=NULL;
  data->SpoolTop=NULL;
  data->numSpooledTags=0;
  data->spoolFileHaveData=false;
  if(data->spoolfile != NULL)
    {
    // check if spool file is writable
    fp=fopen(data->spoolfile,"ab");
    if (fp == NULL)
      FatalError("moloch[%s]: failed to open spool file %s for writing\n",data->node,data->spoolfile);
    // check if spoolfile is not empty
    if(ftell(fp)>0)
      data->spoolFileHaveData=true;
    fclose(fp);
    }

  /* Set the preprocessor function into the function list */
  AddFuncToOutputList(MolochProcess, OUTPUT_TYPE__ALERT, data);
  AddFuncToPostConfigList(MolochPostConfig,data);
  AddFuncToCleanExitList(MolochCleanUp, data);
  //  AddFuncToRestartList(MolochCleanUp, data);
  }


/*
 * Function: MolochPostConfig(int, void*)
 *
 * Returns: void function
 *
 */
void MolochPostConfig(int dummy,void* arg)
  {
  MolochData *data=(MolochData*)arg;

  MolochInitApi(data);
  MolochCheckApi(data);
  if(data->apiStatus)
    {
    MolochReadSpool(data);
    MolochFindLastSession(data,0,false);
    }
  }

/*
 * Function: MolochParseArgs(char *)
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
MolochData *MolochParseArgs(char *args)
  {
  char **toks;
  int num_toks;
  int i;

  MolochData *data;

  data = (MolochData *)SnortAlloc(sizeof(MolochData));

  if(args == NULL)
    FatalError("moloch: No arguments to moloch preprocessor!\n");

  /* default values */
  data->host = "127.0.0.1";
  data->port = 8005;
  data->ssl  = 0;
  data->tag_message  = false;
  data->node=NULL;
  data->user=NULL;
  data->password=NULL;
  data->maxSpoolFileSize=0; // unlimited

  toks = mSplit(args, ", ", 31, &num_toks, '\\');

  for(i = 0; i < num_toks; ++i)
    {
    char **stoks;
    int num_stoks;
    char *index = toks[i];

    stoks = mSplit(index, "=", 2, &num_stoks, 0);

    if ( !strncasecmp(stoks[0], KEYWORD_PORT, strlen(KEYWORD_PORT)) )
      {
      if(num_stoks > 1)
        data->port = atoi(stoks[1]);
      else
        FatalError("moloch: port error\n");
      }
    else if ( !strncasecmp(stoks[0], KEYWORD_HOST, strlen(KEYWORD_HOST)) )
      {
      if(num_stoks > 1)
        data->host = SnortStrdup(stoks[1]);
      else
        FatalError("moloch: host error\n");
      }
    else if ( !strncasecmp(stoks[0], KEYWORD_SSL, strlen(KEYWORD_SSL)) )
      {
      if(num_stoks > 1)
        data->ssl = atoi(stoks[1]);
      else
        FatalError("moloch: ssl error\n");
      }
    else if ( !strncasecmp(stoks[0], KEYWORD_PASSWORD, strlen(KEYWORD_PASSWORD)) )
      {
      if(num_stoks > 1)
        data->password = SnortStrdup(stoks[1]);
      else
        FatalError("moloch: password error\n");
      }
    else if ( !strncasecmp(stoks[0], KEYWORD_USER, strlen(KEYWORD_USER)) )
      {
      if(num_stoks > 1)
        data->user = SnortStrdup(stoks[1]);
      else
        FatalError("moloch: user error\n");
      }
    else if ( !strncasecmp(stoks[0], KEYWORD_NODE, strlen(KEYWORD_NODE)) )
      {
      if(num_stoks > 1)
        data->node = SnortStrdup(stoks[1]);
      else
        FatalError("moloch: user error\n");
      }
    else if ( !strncasecmp(stoks[0], KEYWORD_SPOOLFILE, strlen(KEYWORD_SPOOLFILE)) )
      {
      if(num_stoks > 1)
        data->spoolfile = SnortStrdup(stoks[1]);
      else
        FatalError("moloch: spool error\n");
      }
    else if ( !strncasecmp(stoks[0], KEYWORD_MAXSPOOLFILESIZE, strlen(KEYWORD_MAXSPOOLFILESIZE)) )
      {
      if(num_stoks > 1)
        data->maxSpoolFileSize = atol(stoks[1]);
      else
        FatalError("moloch: max_spool_size error\n");
      }
    else if ( !strncasecmp(stoks[0], KEYWORD_TAGMESSAGE, strlen(KEYWORD_TAGMESSAGE)) )
      {
      if(num_stoks > 1)
        data->tag_message = (bool)atoi(stoks[1]);
      else
        FatalError("moloch: tag_message error\n");
      }
    else
      {
      FatalError("moloch: unrecognised argument = %s\n", index);
      }
    mSplitFree(&stoks, num_stoks);
    }

  mSplitFree(&toks, num_toks);

  if (data->user == NULL)
    FatalError("moloch: user not configured (mandatory)\n");
  if (data->password == NULL)
    FatalError("moloch: password not configured (mandatory)\n");
  if (data->node == NULL)
    FatalError("moloch: node not configured (mandatory)\n");
  if (data->spoolfile == NULL)
    ErrorMessage("moloch[%s]: spool file not configured: unindexed sessions will not be tagged when barnyarn2 restarts!\n",data->node);

  return data;
  }

/*
 * Function: MolochSearchSession(MolochData *,TagInfo *)
 *
 * Purpose: Returns the ids of the sessions that match a taginfo
 *
 * Returns: the list of ids, comma-separated or NULL
 *
 */
char* MolochSearchSession(MolochData* data,TagInfo* taginfo)
  {
  char query[4096];
  char expression[4096];
  char *resp;
#ifdef SUP_IP6
  char sip[INET6_ADDRSTRLEN];
  char dip[INET6_ADDRSTRLEN];
#else
  char sip[16];
  char dip[16];
#endif
  json_object *json,*entry,*sdata,*session;
  const char *id=NULL;
  char *ids = NULL;
  int i;


  if (strlcpy(sip, MOLOCH_IPTOSTR(taginfo->ip_src), sizeof(sip)) >= sizeof(sip))
    return ids;

  if (strlcpy(dip, MOLOCH_IPTOSTR(taginfo->ip_dst), sizeof(dip)) >= sizeof(dip))
    return ids;

  snprintf(expression, 4096, "(ip.src == %s && ip.dst == %s && port.src == %i && port.dst == %i) || (ip.src == %s && ip.dst == %s && port.src == %i && port.dst == %i) && ip.protocol=%i && node == %s",
      sip, dip, taginfo->sp, taginfo->dp, dip, sip, taginfo->dp, taginfo->sp, taginfo->proto, data->node);
  snprintf(query, 4096, "expression=%s&startTime=%u&stopTime=%u&bounding=either&fields=_id,rootId,firstPacket,lastPacket,srcIp,srcPort,dstIp,dstPort", curl_easy_escape(data->curl, expression,0) , taginfo->timestamp, taginfo->timestamp+1);
  resp = MolochCallApi(data,"sessions.json",query,NULL);
  if(resp == NULL)
    ErrorMessage("moloch[%s]: API call to sessions.json failed.\n",data->node);
  else
    {
    json = json_tokener_parse(resp);
    if(json != NULL)
      {
      if(json_object_object_get_ex(json,"data",&sdata))
        {
        if(!json_object_is_type(sdata,json_type_array))
          {
          data->apiStatus=false;
          FatalError("moloch[%s]: unexpected type for 'data' in : \n%s\n",data->node,resp);
          }
        else
          {
          if(json_object_array_length(sdata)==0)
            {
#ifdef MOLOCH_LOG_MISSES
            if(BcLogVerbose())LogMessage("moloch[%s]: No session found for query %s\n",data->node,query);
#endif
            }
          else
            {
            for(i=0;i<json_object_array_length(sdata);i++)
              {
              session=json_object_array_get_idx(sdata,i);
              if(!json_object_object_get_ex(session,"id",&entry))
                {
                data->apiStatus=false;
                FatalError("moloch[%s]: Unexpected json response : could not find 'id' in %s\n",data->node,resp);
                }
              id=json_object_get_string(entry);
              if (!ids)
                {
                ids = (char*)SnortAlloc(2601);// ~100 ids
                ids[0]='\0';
                }
              if(strlen(ids) + strlen(id) > 2600)
                {
                ErrorMessage("moloch[%s]: Too many sessions matches this alert : %s\n",data->node,query);
                break;
                }
              if(strlen(ids)==0)
                ids=strcpy(ids,id);
              else // appends ',<id>'
                sprintf(ids+strlen(ids), ",%s",id);
              }
            }
          }
        }
      else
        {
        data->apiStatus=false;
        FatalError("moloch[%s]: could not find 'data' in : %s.\n",data->node,resp);
        }
      free(json);
      }
    }
  return ids;
  }
/*
 * Function: MolochLogMatchingSession(MolochData *,TagInfo *)
 *
 * Purpose: Logs the ids of a sessions that could match a tagitem
 *          sessions ovelapping the alert timestamp will be logged with an asterix
 *
 * Returns: void function
 *
 */
void MolochLogMatchingSession(MolochData* data,TagInfo* taginfo)
  {
  char query[4096];
  char expression[4096];
  char *resp;
#ifdef SUP_IP6
  char sip[INET6_ADDRSTRLEN];
  char dip[INET6_ADDRSTRLEN];
#else
  char sip[16];
  char dip[16];
#endif
  json_object *json,*entry,*sdata,*session;
  const char *id=NULL;
  int64_t first,last;
  int i;

  if (strlcpy(sip, MOLOCH_IPTOSTR(taginfo->ip_src), sizeof(sip)) >= sizeof(sip))
    return;

  if (strlcpy(dip, MOLOCH_IPTOSTR(taginfo->ip_dst), sizeof(dip)) >= sizeof(dip))
    return;

  snprintf(expression, 4096, "(ip.src == %s && ip.dst == %s && port.src == %i && port.dst == %i) || (ip.src == %s && ip.dst == %s && port.src == %i && port.dst == %i) && ip.protocol=%i && node == %s",
      sip, dip, taginfo->sp, taginfo->dp, dip, sip, taginfo->dp, taginfo->sp, taginfo->proto, data->node);
  snprintf(query, 4096, "expression=%s&startTime=%u&stopTime=%u&bounding=either&fields=_id,rootId,firstPacket,lastPacket,srcIp,srcPort,dstIp,dstPort", curl_easy_escape(data->curl, expression,0) , taginfo->timestamp-1000, taginfo->timestamp+1000);
  resp = MolochCallApi(data,"sessions.json",query,NULL);
  if(resp == NULL)
    ErrorMessage("moloch[%s]: failed to retrieve session(s). server responded: %s\n",data->node,resp);
  if(resp == NULL)
    {
    // the caller is responsible for spooling the tag (or retry an API call)
    ErrorMessage("moloch[%s]: API call to sessions.json failed.\n",data->node);
    }
  else
    {
    json = json_tokener_parse(resp);
    if(json != NULL)
      {
      if(json_object_object_get_ex(json,"data",&sdata))
        {
        if(!json_object_is_type(sdata,json_type_array))
          {
          data->apiStatus=false;
          FatalError("moloch[%s]: unexpected type for 'data' in : \n%s\n",data->node,resp);
          }
        else
          {
          if(json_object_array_length(sdata)==0)
            {
            if(BcLogVerbose())LogMessage("moloch[%s]: No session found for query %s\n",data->node,query);
            }
          else
            {
            for(i=0;i<json_object_array_length(sdata);i++)
              {
              session=json_object_array_get_idx(sdata,i);
              if(!json_object_object_get_ex(session,"firstPacket",&entry))
                {
                data->apiStatus=false;
                FatalError("moloch[%s]: Unexpected json response : could not find 'firstPacket' in %s\n",data->node,resp);
                }
              first=json_object_get_int64(entry)/1000;
              if(!json_object_object_get_ex(session,"lastPacket",&entry))
                {
                data->apiStatus=false;
                FatalError("moloch[%s]: Unexpected json response : could not find 'lastPacket' in %s\n",data->node,resp);
                }
              last=json_object_get_int64(entry)/1000;
              if(!json_object_object_get_ex(session,"id",&entry))
                {
                data->apiStatus=false;
                FatalError("moloch[%s]: Unexpected json response : could not find 'id' in %s\n",data->node,resp);
                }
              id=json_object_get_string(entry);
              if(taginfo->timestamp >= first && taginfo->timestamp <= last)
                {
                if(BcLogVerbose())LogMessage(" session id %s : %li -> %li *\n",id,first,last);
                }
              else
                if(BcLogVerbose())LogMessage(" session id %s : %li -> %li\n",id,first,last);
              //DEBUG: LogMessage(" in %s\n",json_object_get_string(session));
              }
            }
          }
        }
      else
        {
        data->apiStatus=false;
        FatalError("moloch[%s]: could not find 'data' in : %s.\n",data->node,resp);
        }
      free(json);
      }
    }
  }

/*
 * Function: MolochProcessTag(MolochData *, TagItem *)
 *
 * Purpose: Tags or spools a tag
 *
 * Returns: void function
 *
 */
void MolochProcessTag(MolochData *data,TagItem *tagitem)
  {
  char *ids;
  time_t now=time(NULL);

  if(!data->apiStatus)
    MolochCheckApi(data);

  if(!data->apiStatus)
    {
    MolochAddToSpool(data,tagitem);
    return;
    }

#ifdef MOLOCH_LOG_MATCHING_SESSIONS
  if(BcLogVerbose())
    {
    if(BcLogVerbose())LogMessage("moloch[%s]: Searching sessions at timestamp %u...\n",data->node,tagitem->taginfo.timestamp);
    MolochLogMatchingSession(data,&tagitem->taginfo);
    }
#endif

  if(!data->lastpacket || tagitem->taginfo.timestamp > data->lastpacket) // moloch is not there yet
    MolochAddToSpool(data,tagitem);
  else if(tagitem->taginfo.timestamp > now-1800) // moloch have some data but our session may still be missing
    {
    if(tagitem->lastTry < now - 30 && (ids=MolochSearchSession(data,&tagitem->taginfo))) // unsubmitted tags are tried periodically
      {
      MolochAddTag(data,tagitem,ids);
      free(ids);
      }
    else
      {
      tagitem->lastTry=now;
      MolochAddToSpool(data,tagitem);
      }
    }
  else // there is a good chance moloch will never have this session. blindly try anyway
    MolochAddTag(data,tagitem,NULL);
  }

/*
 * Function: MolochAddTag(MolochData *, TagItem *, char *)
 *
 * Purpose: Tags a moloch session. on API failure, spools the tag instead
 *
 * Returns: void function
 *
 */
void MolochAddTag(MolochData *data, TagItem *tagitem, char *ids)
  {
  char query[4096];
  char expression[4096];
  char postdata[4096];
  char tags[4096];
  char *resp;
  SigNode *sn;
  char *message;
  json_object *json,*entry;
  int i;
#ifdef SUP_IP6
  char sip[INET6_ADDRSTRLEN];
  char dip[INET6_ADDRSTRLEN];
#else
  char sip[16];
  char dip[16];
#endif

  snprintf(tags, 4096, "snort,snort_sid:%u-%u", tagitem->taginfo.gen_id, tagitem->taginfo.sig_id);
  if(data->tag_message)
    {
    sn = GetSigByGidSid(tagitem->taginfo.gen_id, tagitem->taginfo.sig_id, tagitem->taginfo.sig_rev);
    if(sn != NULL)
      {
      // moloch strips /[^-a-za-z0-9_:,]/ and ',' is used to separate tags
      message=SnortStrdup(sn->msg);
      for(i=0;i<strlen(message);i++)
        {
        if (!(message[i] == '-' || message[i] == '_' || message[i] == ':' ||
              (message[i]>='a' && message[i]<='z') ||
              (message[i]>='A' && message[i]<='Z') ||
              (message[i]>='0' && message[i]<='9')))
          message[i]='_';
        }
      // append snort_msg:<message> tag
      // FIXME: use SnortSnprintfAppend
      snprintf(tags+strlen(tags), 4096-strlen(tags), ",snort_msg:%s",message);
      free(message);
      }
    }

  if(ids)
    {
    snprintf(postdata, 4096, "ids=%s&tags=%s", curl_easy_escape(data->curl,ids,0), curl_easy_escape(data->curl,tags,0));

    if(BcLogVerbose())LogMessage("moloch[%s]: Tagging session id(s) %s\n",data->node,ids);
    resp = MolochCallApi(data,"addTags", NULL, postdata);
    }
  else
    {
    snprintf(postdata, 4096, "tags=%s", curl_easy_escape(data->curl,tags,0));

    if (strlcpy(sip, MOLOCH_IPTOSTR(tagitem->taginfo.ip_src), sizeof(sip)) >= sizeof(sip))
      return;

    if (strlcpy(dip, MOLOCH_IPTOSTR(tagitem->taginfo.ip_dst), sizeof(dip)) >= sizeof(dip))
      return;

    snprintf(expression, 4096, "(ip.src == %s && ip.dst == %s && port.src == %i && port.dst == %i) || (ip.src == %s && ip.dst == %s && port.src == %i && port.dst == %i) && ip.protocol=%i && node == %s",
        sip, dip, tagitem->taginfo.sp, tagitem->taginfo.dp, dip, sip, tagitem->taginfo.dp, tagitem->taginfo.sp, tagitem->taginfo.proto, data->node);
    snprintf(query, 4096, "expression=%s&startTime=%u&stopTime=%u&bounding=either", curl_easy_escape(data->curl, expression,0) , tagitem->taginfo.timestamp, tagitem->taginfo.timestamp+1);

    if(BcLogVerbose())LogMessage("moloch[%s]: Tagging session(s) at timestamp %u\n",data->node,tagitem->taginfo.timestamp);
    resp = MolochCallApi(data,"addTags", query, postdata);
    }

  if(resp == NULL)
    {
    ErrorMessage("moloch[%s]: API call to addTags failed.\n",data->node);
    MolochAddToSpool(data,tagitem);
    }
  else
    {
    json = json_tokener_parse(resp);
    if(json != NULL)
      {
      if(json_object_object_get_ex(json,"success",&entry))
        {
        if(!json_object_is_type(entry,json_type_boolean))
          {
          data->apiStatus=false;
          FatalError("moloch[%s]: unexpected type for 'success' in : \n%s\n",data->node,resp);
          }
        else
          {
          if(!json_object_get_boolean(entry))
            {
            ErrorMessage("moloch[%s]: failed to add tag. server responded: %s\n",data->node,resp);
            MolochAddToSpool(data,tagitem);
            data->apiStatus=false;
            }
          else
            {
            free(tagitem);
            // now is a good time to check if we have data to read back
            if(data->numSpooledTags <= MOLOCH_MAX_SPOOLED_TAGS * 0.1)
              MolochReadSpool(data);
            }
          }
        }
      else
        {
        data->apiStatus=false;
        FatalError("moloch[%s]: could not find 'success' in : %s.\n",data->node,resp);
        }
      free(json);
      }
    free(resp);
    }
  }


/*
 * Function: MolochAddToSpool(MolochData *,TagItem *)
 *
 * Purpose: add a tag to data->SpooledTags or records it to spool file
 *
 * Returns: void function
 *
 */
void MolochAddToSpool(MolochData *data,TagItem *tagitem)
  {
  if(data->numSpooledTags >= MOLOCH_MAX_SPOOLED_TAGS)
    {
    if(BcLogVerbose())LogMessage("moloch[%s]: writing sooled tags to spool file\n",data->node);
    MolochWriteSpool(data);
    }

  if(BcLogVerbose())LogMessage("moloch[%s]: Spooling a tag at timestamp %u.\n",data->node,tagitem->taginfo.timestamp);

  if(data->numSpooledTags == 0)
    data->SpooledTags=tagitem;
  else
    data->SpoolTop->next=tagitem;
  data->SpoolTop=tagitem;
  data->numSpooledTags++;
  if(data->numSpooledTags == MOLOCH_MAX_SPOOLED_TAGS)
    {
    ErrorMessage("moloch[%s]: reached maximum of %u tags in memory. is moloch running and getting captured data ?\n",data->node,MOLOCH_MAX_SPOOLED_TAGS);
    if(!data->spoolfile)
      FatalError("moloch[%s]: no spool file configured.\n",data->node);
    }
  }

/*
 * Function: MolochWriteSpool(MolochData*)
 *
 * Purpose: write data->SpooledTags to data->spoolfile
 *
 * Returns: void function
 *
 */
void MolochWriteSpool(MolochData* data)
  {
  TagItem *tagitem,*previoustag;
  int8_t version = MOLOCH_SPOOL_FILE_VERSION;
  FILE *fp;
  size_t currentSize=0;
#ifdef SUP_IP6
  version = -version;
#endif
  if (data->spoolfile == NULL || data->numSpooledTags == 0)
    return;

  fp=fopen(data->spoolfile,"ab");
  if(fp==NULL)
    FatalError("moloch[%s]: failed to open spool file for writing\n",data->node);

  currentSize=ftell(fp);
  if(currentSize == 0 && fwrite(&version,sizeof(int8_t),1,fp) !=1)
    FatalError("moloch[%s]: could not write spool file\n",data->node);

  tagitem=data->SpooledTags;
  while (tagitem!=NULL)
    {
    if(fwrite(&tagitem->taginfo, sizeof(TagInfo), 1, fp) !=1)
      FatalError("moloch[%s]: could not write spool file\n",data->node);
    previoustag=tagitem;
    tagitem=tagitem->next;
    free(previoustag);
    }
  fclose(fp);

  if(BcLogVerbose())LogMessage("moloch[%s]: wrote %u tags in %s\n",data->node,data->numSpooledTags,data->spoolfile);

  data->numSpooledTags=0;
  data->SpooledTags=NULL;
  data->SpoolTop=NULL;
  data->spoolFileHaveData=true;

  if(data->maxSpoolFileSize>0 && currentSize + sizeof(TagInfo) * MOLOCH_MAX_SPOOLED_TAGS > data->maxSpoolFileSize)
    FatalError("moloch[%s]: maximum spool file size of %u bytes (about to be) reached.\n",data->node,data->maxSpoolFileSize);
  }

/*
 * Function: MolochReadSpool(MolochData*);
 *
 * Purpose: read data spoolfile into data->SpooledTags until MOLOCH_MAX_SPOOLED_TAGS
 *          is reached. then generate e new spool file with the remaining data
 *
 * Returns: void function
 *
 */
void MolochReadSpool(MolochData* data)
  {
  FILE *fp,*newfp;
  char *oldFileName;
  TagInfo myTagInfo;
  TagItem *tagitem=NULL;
  uint32_t numReadTags=0;
  int8_t fileversion,version;
  size_t readbytes;
  char buffer[sizeof(TagItem) * 100];
  time_t now = time(NULL);

  if (!data->spoolfile || !data->spoolFileHaveData)
    return;

  fp=fopen(data->spoolfile,"rb");
  if(fp==NULL)
    {
    // spool file have been deleted
    data->spoolFileHaveData=false;
    return;
    }

  version = MOLOCH_SPOOL_FILE_VERSION;
#ifdef SUP_IP6
  version = -version;
#endif
  if(fread(&fileversion,sizeof(int8_t),1,fp) == 1)
    {
    if(fileversion != version && !feof(fp))
      {
      ErrorMessage("moloch[%s]: the spool file %s is not compatible with this version of barnyard2\n",data->node,data->spoolfile);
      if(fileversion<0 && version>0)
        ErrorMessage("   this file was generated with IPv6 support\n");
      if(fileversion>0 && version<0)
        ErrorMessage("   this file was generated without IPv6 support\n");
      if(abs(fileversion) != abs(version))
        ErrorMessage("   the file version is %i. we expect version %i\n",abs(fileversion),abs(version));

      FatalError("   you should either delete the spool file (and loose unsubmited tags)\nor reinstall your previous version of barnyard2 in order to submit them\n");
      }

    while (data->numSpooledTags < MOLOCH_MAX_SPOOLED_TAGS * 0.9 && fread((void*)&myTagInfo, sizeof(TagInfo), 1, fp) == 1)
      {
      // check for obvious error in spool file
      if (myTagInfo.timestamp < now - 24*3600*10*360 || myTagInfo.timestamp > now + 3600)
        {
        ErrorMessage("moloch[%s]: the spool file appears to be corrupted at tag %u :\n",data->node,numReadTags);
        printTagInfo(&myTagInfo);
        data->spoolFileHaveData=false;
        remove(data->spoolfile);
        FatalError("moloch[%s]: the spool file have been deleted\n");
        }

      tagitem=(TagItem *)SnortAlloc(sizeof(TagItem));
      tagitem->lastTry=0;
      memcpy(&tagitem->taginfo,&myTagInfo,sizeof(TagInfo));
      if(data->SpooledTags == NULL)
        data->SpooledTags=tagitem;
      if(data->SpoolTop != NULL)
        data->SpoolTop->next=tagitem;
      data->SpoolTop=tagitem;
      data->numSpooledTags++;
      numReadTags++;
      }
    if (data->SpoolTop != NULL)
      data->SpoolTop->next=NULL;
    if(BcLogVerbose())LogMessage("moloch[%s]: read %u tags from spool file\n",data->node,numReadTags);

    // copy remaining data to a new spool file
    if (!feof(fp) && ftell(fp)>1)
      {
      oldFileName=(char *)SnortAlloc(strlen(data->spoolfile)+5);
      snprintf(oldFileName, strlen(data->spoolfile)+4, "%s.tmp", data->spoolfile);
      remove(oldFileName); // possible leftover
      rename(data->spoolfile,oldFileName);

      newfp=fopen(data->spoolfile,"wb");
      if(newfp!=NULL)
        {
        if(fwrite(&version,sizeof(int8_t),1,newfp) ==1)
          {
          while ((readbytes=fread((void*)buffer, 1, sizeof(TagInfo) * 100, fp))>0)
            {
            if(fwrite(buffer,readbytes,1,newfp) != 1)
              {
              ErrorMessage("moloch[%s]: could not completely write new spool file. discarding old spool file.\n",data->node);
              break;
              }
            }
          }
        else // could not write anything to new spool file
          ErrorMessage("moloch[%s]: could not write new spool file. discarding old spool file.\n",data->node);
        fclose(newfp);
        }
      else
        ErrorMessage("moloch[%s]: failed to open new spool file. discarding old spool file.\n",data->node);
      remove(oldFileName);
      free(oldFileName);
      }
    else // the file is completely read
      {
      data->spoolFileHaveData=false;
      remove(data->spoolfile);
      }
    //printSpooledTags(data,10);
    }
  else // empty spool file
    {
    data->spoolFileHaveData=false;
    remove(data->spoolfile);
    }
  fclose(fp);
  }

/*
 * Function: MolochSubmitSpool(MolochData*);
 *
 * Purpose: submit tags in data->SpooledTags that have been indexed by moloch
 *
 * Returns: void function
 *
 */
void MolochSubmitSpool(MolochData* data)
  {
  TagItem *tagitem;
  uint32_t ntags = data->numSpooledTags;

  if (ntags)
    {
    if(BcLogVerbose())LogMessage("moloch[%s]: Submitting Spooled tags...\n",data->node);

    while (ntags-- && data->apiStatus)
      {
      tagitem=data->SpooledTags;
      if(tagitem->taginfo.timestamp <= data->lastpacket)
        {
        // MolochAddTag may reload spool file and change data->SpooledTags and data->numSpooledTags
        data->numSpooledTags--;
        data->SpooledTags=data->SpooledTags->next;
        MolochProcessTag(data,tagitem);
        }
      else // we may have submittable tags in spool but we will wait until moloch indexes
        break;
      }
    if(BcLogVerbose())LogMessage("moloch[%s]: Finished submitting spooled messages\n",data->node);
    }
  }


/*
 * Function: MolochGetSessions(MolochData *,char *,uint32_t )
 *
 * Purpose: this function is not used currently. it retrieve sessions in text format.
 *          it can be used to debug in conjonction with MOLOCH_DEBUG_API
 *
 * Returns: char* API response
 *
 */
char* MolochGetSessions(MolochData *data,char *expression,uint32_t timestamp)
  {
  char query[4096];
  char *resp;

  snprintf(query, 4096, "expression=%s&startTime=%u&stopTime=%u&bounding=either&fields=_id,firstPacket,lastPacket,srcIp,srcPort,dstIp,dstPort", curl_easy_escape(data->curl, expression,0) , timestamp-1, timestamp+1);
  resp = MolochCallApi(data,"sessions.csv",query,NULL);
  if(resp == NULL)
    ErrorMessage("moloch[%s]: failed to retrieve session(s). server responded: %s\n",data->node,resp);

  return resp;
  }

/*
 * Function: MolochGetLastSession(MolochData *,time_t , time_t )
 *
 * Purpose: Finds the timestamp of the last indexed session by moloch.for a given time frame
 *
 * Returns: void function
 *
 */
void MolochGetLastSession(MolochData *data,uint32_t from, uint32_t to)
  {
  char query[4096];
  char expression[4096];
  char *resp;
  char *last_time;

  LogMessage("moloch[%s]: searching last indexed packet from timestamp %u to %u.\n",data->node,from ,to);

  snprintf(expression, 4096, "node == %s", data->node);
  snprintf(query, 4096, "expression=%s&field=lastPacket&startTime=%u&stopTime=%u", curl_easy_escape(data->curl, expression,0), from,to);
  resp = MolochCallApi(data,"unique.txt",query,NULL);
  if(resp == NULL)
    {
    ErrorMessage("moloch[%s]: API call to unique.txt failed.\n",data->node);
    return;
    }

  // find the last timestamp
  while(true)
    {
    last_time=strrchr(resp,'\n');
    if(last_time== NULL)
      last_time=resp;

    if(strlen(last_time) == 13)
      {
      last_time[11]='\0'; // strip millisec.
      data->lastpacket = strtoul(last_time,NULL,0);
      if(BcLogVerbose())LogMessage("moloch[%s]: found last indexed packet timestamp :%u\n",data->node,data->lastpacket);
      break;
      }
    else if(last_time > resp)
      last_time[-1]='\0';
    else
      break;
    }

  free(resp);
  }

/*
 * Function: MolochFindLastSession(MolochData *, time_t,  bool )
 *
 * Purpose: Finds the timestamp of the last indexed packet by moloch. there is no simple way
 *          to do that so we query all unique values of the lastPacket field or since
 *          the last known timestamp. this is done every 2mn max except if forced==true (on shutdown)
 *          If a new timestamp is found, then we submit spooled tags.
 *
 * Returns: void function
 *
 */
void MolochFindLastSession(MolochData *data, uint32_t tagtimestamp, bool forced)
  {
  time_t now = time(NULL);
  static time_t next_retry =0;

  if(!forced && (now < next_retry))
    return;
  next_retry=now+120;

  if(!data->lastpacket)
    {
    // first we check if moloch indexed a packet in the last 30mn
    MolochGetLastSession(data,now-1800,now);
    if(!data->lastpacket)
      {
      /*
       * if moloch is not getting captured data, we check from an older alert
       * it may not be the oldest alert due to spool file manipulation.
       * if no packet were indexed 30mn after this alert, we will recover
       * once moloch starts capturing again
       */
      if(data->numSpooledTags)
        MolochGetLastSession(data,data->SpooledTags->taginfo.timestamp-120,data->SpooledTags->taginfo.timestamp+1800);
      else if(tagtimestamp && tagtimestamp < now-1800) // we have nothing in spool but we can check from the current packet
        MolochGetLastSession(data,tagtimestamp-120,tagtimestamp+1800);

      }
    }
  else // we already found an indexed packed. we check from it
    MolochGetLastSession(data,data->lastpacket,now);

  if(data->lastpacket)
    MolochSubmitSpool(data);
  else if(BcLogVerbose())
    ErrorMessage("moloch[%s]: failed get the last indexed packet timestamp from moloch. check that it is capturing.\n",data->node);
  }

/*
 * Function: MolochProcess(Packet *, void *, u_int32_t, void *)
 *
 * Purpose: Process an alert (plugin callback)
 *
 * Arguments: p => pointer to the current packet data struct
 *
 * Returns: void function
 *
 */
void MolochProcess(Packet *p, void *event, u_int32_t event_type, void *arg)
  {
  MolochData  *data;
  TagItem *tagitem;

  if ( p == NULL || event == NULL || arg == NULL )
    return;

  data = (MolochData *)arg;

  if(p && IPH_IS_VALID(p))
    {
#ifndef SUP_IP6
    if(p->ip6h != NULL)
      {
      ErrorMessage("moloch[%s]: Ignoring a IPv6 alert. re-build with --enable-ipv6 to handle these.\n",data->node);
      return;
      }
#endif
    tagitem = (TagItem *)SnortAlloc(sizeof(TagItem));
    tagitem->taginfo.gen_id    = ntohl(((Unified2EventCommon *)event)->generator_id);
    tagitem->taginfo.sig_id    = ntohl(((Unified2EventCommon *)event)->signature_id);
    tagitem->taginfo.sig_rev   = ntohl(((Unified2EventCommon *)event)->signature_revision);
    tagitem->taginfo.timestamp = ntohl(((Unified2EventCommon *)event)->event_second);
    tagitem->taginfo.ip_src    = MOLOCH_GET_ADDR(GET_SRC_ADDR(p));
    tagitem->taginfo.sp        = p->sp;
    tagitem->taginfo.ip_dst    = MOLOCH_GET_ADDR(GET_DST_ADDR(p));
    tagitem->taginfo.dp        = p->dp;
    tagitem->taginfo.proto     = GET_IPH_PROTO(p);
    tagitem->lastTry   = 0;
    tagitem->next      = NULL;

    if(!data->lastpacket || tagitem->taginfo.timestamp > data->lastpacket)
      MolochFindLastSession(data,tagitem->taginfo.timestamp,false);

    MolochProcessTag(data,tagitem);
    }

  return;
  }


void MolochCleanUp(int signal, void *arg)
  {
  MolochData *data = (MolochData *)arg;
  if(data)
    {
    if(data->numSpooledTags >0)
      {
      if(!data->spoolfile && data->apiStatus)
        {
        LogMessage("moloch[%s]: trying to submit remaining tags...\n",data->node);
        MolochFindLastSession(data,0,true);
        }
      MolochWriteSpool(data);
      }
    free(data);
    }
  }

#endif /* ENABLE_OUTPUT_PLUGIN */
