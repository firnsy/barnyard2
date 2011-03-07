/* 
**
** Copyright (C) 2008-2011 Ian Firns (SecurixLive) <dev@securixlive.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>

#include "barnyard2.h"
#include "debug.h"
#include "plugbase.h"
#include "spooler.h"
#include "unified2.h"
#include "util.h"

/*
** PRIVATE FUNCTIONS
*/
Spooler *spoolerOpen(const char *, const char *, uint32_t);
int spoolerClose(Spooler *);
int spoolerReadRecordHeader(Spooler *);
int spoolerReadRecord(Spooler *);
void spoolerProcessRecord(Spooler *, int);
void spoolerFreeRecord(Record *record);

int spoolerWriteWaldo(Waldo *, Spooler *);
int spoolerOpenWaldo(Waldo *, uint8_t);
int spoolerCloseWaldo(Waldo *);


/* Find the next spool file timestamp extension with a value equal to or 
 * greater than timet.  If extension != NULL, the extension will be 
 * returned.
 *
 * @retval 0    file found
 * @retval -1   error
 * @retval 1    no file found
 *
 * Bugs:  This function presumes a 1 character delimeter between the base 
 * filename and the extension
 */
static int FindNextExtension(const char *dirpath, const char *filebase, 
        uint32_t timestamp, uint32_t *extension)
{
    DIR                 *dir = NULL;
    struct dirent       *dir_entry;
    size_t              filebase_len;
    uint32_t            timestamp_min = 0;
    char *endptr;
    
    DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Looking in %s %s\n", dirpath, filebase););
    
    /* peform sanity checks */
    if (dirpath == NULL || filebase == NULL)
        return SPOOLER_EXTENSION_EPARAM;

    /* calculate filebase length */
    filebase_len = strlen(filebase);
    
    /* open the directory */
    if ( !(dir=opendir(dirpath)) )
    {
        LogMessage("ERROR: Unable to open directory '%s' (%s)\n", dirpath,
                strerror(errno));
        return SPOOLER_EXTENSION_EOPEN;
    }

    /* step through each entry in the directory */
    while ( (dir_entry=readdir(dir)) )
    {
        unsigned long   file_timestamp;

        if (strncmp(filebase, dir_entry->d_name, filebase_len) != 0)
            continue;

        /* this is a file we may want */
        file_timestamp = strtol(dir_entry->d_name + filebase_len + 1, &endptr, 10);
        if ((errno == ERANGE) || (*endptr != '\0'))
        {
            LogMessage("WARNING: Can't extract timestamp extension from '%s'"
                    "using base '%s'\n", dir_entry->d_name, filebase);
            
            continue;
        }

        /* exact match */
        if (timestamp != 0 && file_timestamp == timestamp)
        {
            timestamp_min = file_timestamp;
            break;
        }
        /* possible overshoot */
        else if (file_timestamp > timestamp)
        {
            /*  realign the minimum timestamp threshold */
            if ( timestamp_min == 0 || (file_timestamp < timestamp_min) )
                timestamp_min = file_timestamp;
        }
    }

    closedir(dir);

    /* no newer extensions were found */
    if (timestamp_min == 0) 
        return SPOOLER_EXTENSION_NONE;

    /* update the extension variable if it exists */
    if (extension != NULL)
        *extension = timestamp_min;

    return SPOOLER_EXTENSION_FOUND;
}

Spooler *spoolerOpen(const char *dirpath, const char *filename, uint32_t extension)
{
    Spooler             *spooler = NULL;
    int                 ret;
        
    /* perform sanity checks */
    if ( filename == NULL )
        return NULL;
    
    /* create the spooler structure and allocate all memory */
    spooler = (Spooler *)SnortAlloc(sizeof(Spooler));

    /* allocate some extra structures required (ie. Packet) */

    spooler->fd = -1;

    /* build the full filepath */
    if (extension == 0)
    {
        ret = SnortSnprintf(spooler->filepath, MAX_FILEPATH_BUF, "%s", filename);
    }
    else
    {
        ret = SnortSnprintf(spooler->filepath, MAX_FILEPATH_BUF, "%s/%s.%u", dirpath, filename,
                extension);
    }

    /* sanity check the filepath */
    if (ret != SNORT_SNPRINTF_SUCCESS)
    {
        spoolerClose(spooler);
        FatalError("spooler: filepath too long!\n");
    }

    spooler->timestamp = extension;
            
    LogMessage("Opened spool file '%s'\n", spooler->filepath);

    /* open the file non-blocking */
    if ( (spooler->fd=open(spooler->filepath, O_RDONLY | O_NONBLOCK, 0)) == -1 )
    {
        LogMessage("ERROR: Unable to open log spool file '%s' (%s)\n", 
                    spooler->filepath, strerror(errno));
        spoolerClose(spooler);
        spooler = NULL;
        return NULL;
    }

    /* set state to initially be open */
    spooler->state = SPOOLER_STATE_OPENED;

    spooler->ifn = GetInputPlugin("unified2");

    if (spooler->ifn == NULL)
    {
        spoolerClose(spooler);
        spooler = NULL;
        FatalError("ERROR: No suitable input plugin found!\n");
    }

    return spooler;
}

int spoolerClose(Spooler *spooler)
{
    /* perform sanity checks */
    if (spooler == NULL)
        return -1;

    LogMessage("Closing spool file '%s'. Read %d records\n",
               spooler->filepath, spooler->record_idx);

    if (spooler->fd != -1)
        close(spooler->fd);

    /* free record */
    spoolerFreeRecord(&spooler->record);
        
    free(spooler);
    spooler = NULL;

    return 0;
}

int spoolerReadRecordHeader(Spooler *spooler)
{
    int                 ret;

    /* perform sanity checks */
    if ( spooler == NULL )
        return -1;

    if (spooler->state != SPOOLER_STATE_OPENED && spooler->state != SPOOLER_STATE_RECORD_READ)
    {
        LogMessage("ERROR: Invalid attempt to read record header.\n");
        return -1;
    }

    if (spooler->ifn->readRecordHeader)
    { 
        ret = spooler->ifn->readRecordHeader(spooler);
    
        if (ret != 0)
            return ret;
        
        spooler->state = SPOOLER_STATE_HEADER_READ;
        spooler->offset = 0;
    }
    else
    {
        LogMessage("WARNING: No function defined to read header.\n");
        return -1;
    }

    return 0;
}

int spoolerReadRecord(Spooler *spooler)
{
    int                 ret;

    /* perform sanity checks */
    if (spooler == NULL)
        return -1;

    if (spooler->state != SPOOLER_STATE_HEADER_READ)
    {
        LogMessage("ERROR: Invalid attempt to read record.\n");
        return -1;
    }

    if (spooler->ifn->readRecord)
    { 
        ret = spooler->ifn->readRecord(spooler);
    
        if (ret != 0)
            return ret;
        
        spooler->state = SPOOLER_STATE_RECORD_READ;
        spooler->record_idx++;
        spooler->offset = 0;
    }
    else
    {
        LogMessage("WARNING: No function defined to read header.\n");
        return -1;
    }

    return 0;
}

int ProcessBatch(const char *dirpath, const char *filename)
{
    Spooler             *spooler = NULL;
    int                 ret = 0;
    int                 pb_ret = 0;

    /* Open the spool file */
    if ( (spooler=spoolerOpen("", filename, 0)) == NULL)
    {
        FatalError("Unable to create spooler: %s\n", strerror(errno));
    }

    while (exit_signal == 0 && pb_ret == 0)
    {
        switch (spooler->state)
        {
            case SPOOLER_STATE_OPENED:
            case SPOOLER_STATE_RECORD_READ:
                ret = spoolerReadRecordHeader(spooler);
            
                if (ret == BARNYARD2_READ_EOF)
                {
                    pb_ret = -1;
                }
                else if (ret != 0)
                {
                    LogMessage("ERROR: Input file '%s' is corrupted! (%u)\n", 
                                spooler->filepath, ret);
                    pb_ret = -1;
                }
                break;

            default:
                ret = spoolerReadRecord(spooler);
    
                if (ret == 0)
                {
                    /* process record, firing output as required */
                    spoolerProcessRecord(spooler, 1);
                }
                else if (ret == BARNYARD2_READ_EOF)
                {
                    pb_ret = -1;
                }
                else
                {
                    LogMessage("ERROR: Input file '%s' is corrupted! (%u)\n", 
                               spooler->filepath, ret);
                    pb_ret = -1;
                }

                spoolerFreeRecord(&spooler->record);
                break;
        }
    }

    /* we've finished with the spooler so destroy and cleanup */
    spoolerClose(spooler);
    spooler = NULL;

    return pb_ret;
}

/*
** ProcessContinuous(const char *dirpath, const char *filebase, uint32_t record_start, time_t timestamp)
**
**
**
*/
int ProcessContinuous(const char *dirpath, const char *filebase, 
        uint32_t record_start, uint32_t timestamp)
{
    Spooler             *spooler = NULL;
    int                 ret = 0;
    int                 pc_ret = 0;
    int                 new_file_available = 0;
    int                 waiting_logged = 0;
    uint32_t            skipped = 0;
    uint32_t            extension = 0;
 
    if (BcProcessNewRecordsOnly())
    {
        LogMessage("Processing new records only.\n");

        /* Find newest file extension */
        while (FindNextExtension(dirpath, filebase, timestamp, &extension) == 0)
        {
            if (timestamp > 0 && BcLogVerbose())
                LogMessage("Skipping file: %s/%s.%u\n", dirpath,
                        filebase, timestamp);

            timestamp = extension + 1;
        }

        timestamp = extension;
    }

    /* Start the main process loop */
    while (exit_signal == 0)
    {
        /* no spooler exists so let's create one */
        if (spooler == NULL)
        {
            /* find the next file to spool */
            ret = FindNextExtension(dirpath, filebase, timestamp, &extension);

            /* no new extensions found */
            if (ret == SPOOLER_EXTENSION_NONE)
            {
                if (waiting_logged == 0)
                {
                    if (BcProcessNewRecordsOnly())
                       LogMessage("Skipped %u old records\n", skipped);

                    LogMessage("Waiting for new spool file\n");
                    waiting_logged = 1;
                    barnyard2_conf->process_new_records_only_flag = 0;
                }

                sleep(1);
                continue;
            }
            /* an error occured whilst looking for new extensions */
            else if (ret != SPOOLER_EXTENSION_FOUND)
            {
                LogMessage("ERROR: Unable to find the next spool file!\n");
                exit_signal = -1;
                pc_ret = -1;
                continue;
            }

            /* found a new extension so create a new spooler */
            if ( (spooler=spoolerOpen(dirpath, filebase, extension)) == NULL )
            {
                LogMessage("ERROR: Unable to create spooler!\n");
                exit_signal = -1;
                pc_ret = -1;
                continue;
            }

            waiting_logged = 0;

            /* set timestamp to ensure we look for a newer file next time */
            timestamp = extension + 1;

            continue;
        }

        /* act according to current spooler state */
        switch(spooler->state)
        {
            case SPOOLER_STATE_OPENED:
            case SPOOLER_STATE_RECORD_READ:
                ret = spoolerReadRecordHeader(spooler);
                break;

            case SPOOLER_STATE_HEADER_READ:
                ret = spoolerReadRecord(spooler);
                break;

            default:
                LogMessage("ERROR: Invalid spooler state (%i). Closing '%s'\n",
                            spooler->state, spooler->filepath);
               
#ifndef WIN32
                /* archive the spool file */
                if (BcArchiveDir() != NULL)
                    ArchiveFile(spooler->filepath, BcArchiveDir());
#endif

                /* we've finished with the spooler so destroy and cleanup */
                spoolerClose(spooler);
                spooler = NULL;
                
                record_start = 0;
                break;
        }

        /* if no spooler exists, we are waiting for a newer file to arrive */
        if (spooler == NULL)
            continue;
        
        if (ret == 0)
        {
            /* check for a successful record read */
            if (spooler->state == SPOOLER_STATE_RECORD_READ)
            {
                if (record_start > 0)
                {
                    /* skip this record */
                    record_start--;
                    DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Skipping due to record start offset (%lu)...\n",
                                 (long unsigned)record_start););

                    /* process record to ensure correlation context, but DO NOT fire output*/
                    spoolerProcessRecord(spooler, 0);
                }
                else if (BcProcessNewRecordsOnly())
                {
                    /* skip this record */
                    skipped++;
                    DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Skipping due to new records only flag...\n"););

                    /* process record to ensure correlation context, but DO NOT fire output*/
                    spoolerProcessRecord(spooler, 0);
                }
                else
                {
                    /* process record, firing output as required */
                    spoolerProcessRecord(spooler, 1);
                }
            }

            spoolerFreeRecord(&spooler->record);
        }
        else if (ret == BARNYARD2_FILE_ERROR)
        {
            LogMessage("ERROR: Reading current file!\n");
            exit_signal = -3;
            pc_ret = -1;
            continue;
        }
        else
        {
            if (new_file_available)
            {
                switch(spooler->state)
                {
                    case SPOOLER_STATE_OPENED:
                    case SPOOLER_STATE_HEADER_READ:
                    case SPOOLER_STATE_RECORD_READ:
                        if (ret == BARNYARD2_ETRUNC)
                            LogMessage("Truncated record in '%s'\n", spooler->filepath);
                        break;

                    default:
                        if (ret == BARNYARD2_READ_PARTIAL)
                            LogMessage("Partial read from '%s'\n",
                                    spooler->filepath);
                        break;
                }

                /* archive the file */
                if (BcArchiveDir() != NULL)
                    ArchiveFile(spooler->filepath, BcArchiveDir());

                /* close (ie. destroy and cleanup) the spooler so we can rotate */
                spoolerClose(spooler);
                spooler = NULL;

                record_start = 0;
                new_file_available = 0;
            }
            else
            {
                ret = FindNextExtension(dirpath, filebase, timestamp, NULL);
                if (ret == 0)
                {
                    new_file_available = 1;
                }
                else if (ret == -1)
                {
                    LogMessage("ERROR: Looking for next spool file!\n");
                    exit_signal = -3;
                    pc_ret = -1;
                }
                else
                {
                    if (!waiting_logged) 
                    {
                        if (BcProcessNewRecordsOnly())
                            LogMessage("Skipped %u old records\n", skipped);
                            
                        LogMessage("Waiting for new data\n");
                        waiting_logged = 1;
                        barnyard2_conf->process_new_records_only_flag = 0;
                    }

                    sleep(1);
                    continue;
                }
            }
        }
    }

    /* close waldo if appropriate */
    spoolerCloseWaldo(&barnyard2_conf->waldo);

    return pc_ret;
}

int ProcessContinuousWithWaldo(Waldo *waldo)
{
    if (waldo == NULL)
        return -1;

    return ProcessContinuous(waldo->data.spool_dir, waldo->data.spool_filebase,
                             waldo->data.record_idx, waldo->data.timestamp);
}



/*
** RECORD PROCESSING EVENTS
*/
/* Less allocation */
Packet *LogPacket = NULL;



/* EVENT  */
/* PACKET */

//EVENT WITHOUT PACKET? NOT.

//EVENT_STATE
//PACKET_STATE
static Unified2IDSEvent_legacy *U2IdsEventLegacyPtr = NULL;
static Unified2IDSEventIPv6_legacy *U2IdeEventV6LegacyPtr = NULL;
static Unified2ExtraData *u2ExtraDataPtr = NULL; 
static Unified2ExtraDataHdr *u2ExtraDataHdrPtr = NULL;
static Unified2Packet *u2PacketPtr = NULL;
static Unified2IDSEventIPv6 *U2IdsEventV6Ptr = NULL;
static Unified2IDSEvent *U2IdsEventPtr = NULL;

static int SpoolerState = 0;
static void  *SpoolerEventPtr = NULL;

#define SPOOLER_NULL         0x00000000
#define SPOOLER_EVENT        0x00000001
#define SPOOLER_READY        0x00000002
#define SPOOLER_FAST_FORWARD 0x10000000

int InitializeSpoolerStatic(void)
{
  
  if( (U2IdsEventLegacyPtr = (Unified2IDSEvent_legacy *)malloc(sizeof(Unified2IDSEvent_legacy)))  == NULL)
    {
      /* XXX */ 
      return 1;
    }

  memset(U2IdsEventLegacyPtr,'\0',sizeof(Unified2IDSEvent_legacy));
  
  if( (U2IdeEventV6LegacyPtr = (Unified2IDSEventIPv6_legacy *)malloc(sizeof(Unified2IDSEventIPv6_legacy))) == NULL)
    {
      /* XXX */
      return 1;
    }
  
  memset(U2IdeEventV6LegacyPtr,'\0',sizeof(Unified2IDSEventIPv6_legacy));

  if( (u2ExtraDataPtr = (Unified2ExtraData *)malloc(sizeof(Unified2ExtraData))) == NULL)
    {
      /* XXX */
      return 1;
    }
  memset(u2ExtraDataPtr,'\0',sizeof(Unified2ExtraData));
  
  if( (u2ExtraDataHdrPtr = (Unified2ExtraDataHdr *)malloc(sizeof(Unified2ExtraDataHdr))) == NULL)
    {
      /* XXX */
      return 1;
    }
  memset(u2ExtraDataHdrPtr,'\0',sizeof(Unified2ExtraDataHdr));  

  if( (u2PacketPtr = (Unified2Packet *)malloc(sizeof(Unified2Packet))) == NULL)
    {
      /* XXX */
      return 1;
    }
  memset(u2PacketPtr,'\0',sizeof(Unified2Packet));
  
  if( (U2IdsEventV6Ptr = (Unified2IDSEventIPv6 *)malloc(sizeof(Unified2IDSEventIPv6))) == NULL)
    {
      /* XXX */
      return 1;
    }
  memset(U2IdsEventV6Ptr,'\0',sizeof(Unified2IDSEventIPv6));
  
  if( (U2IdsEventPtr = (Unified2IDSEvent *)malloc(sizeof(Unified2IDSEvent))) == NULL)
    {
      /* XXX */
      return 1;
    }
  memset(U2IdsEventPtr,'\0',sizeof(Unified2IDSEvent));
  
  return 0;
}

int FreeSpoolerStatic(void)
{
  if( U2IdsEventLegacyPtr != NULL)
    {
      free(U2IdsEventLegacyPtr);
    }

  if( U2IdeEventV6LegacyPtr != NULL)
    {
      free(U2IdeEventV6LegacyPtr);
    }

  if( u2ExtraDataPtr != NULL)
    {
      free(u2ExtraDataHdrPtr);
    }

  if( u2PacketPtr != NULL)
    {
      free(u2PacketPtr);
    }

  if( U2IdsEventPtr != NULL)
    {
      free(U2IdsEventPtr);
    }

  if( U2IdsEventV6Ptr != NULL)
    {
      free(U2IdsEventV6Ptr);
    }

  return 0;
}

int InitializeLogPacket(void)
{

  if(LogPacket == NULL)
    {
      if( (LogPacket=(Packet *)malloc(sizeof(Packet))) == NULL)
	{
	  /* XXX */
	  return 1;
	  
	}
      memset(LogPacket,'\0',sizeof(Packet));
    }
  else
    {
      /* XXX */
      return 1;
    }

  return InitializeSpoolerStatic();
}

int FreeLogPacket(void)
{
  if(LogPacket != NULL)
    {
      memset(LogPacket,'\0',sizeof(Packet));
      free(LogPacket);
      LogPacket = NULL;
      return 0;
    }
  
  return FreeSpoolerStatic();
}


int SpoolerSetStaticEvent(u_int32_t type,void *RecordData)
{
  if(RecordData == NULL)
    {
      /* XXX */
      return 1;
    }
  
  switch(type)
    {
      
    case UNIFIED2_IDS_EVENT:
    case UNIFIED2_IDS_EVENT_MPLS:
    case UNIFIED2_IDS_EVENT_VLAN:
      memset(U2IdsEventPtr,'\0',sizeof(Unified2IDSEvent));
      memcpy(U2IdsEventPtr,RecordData,sizeof(Unified2IDSEvent)); 
      SpoolerEventPtr =(void *)U2IdsEventPtr;
      break;
      
    case UNIFIED2_IDS_EVENT_IPV6:
    case UNIFIED2_IDS_EVENT_IPV6_MPLS:
    case UNIFIED2_IDS_EVENT_IPV6_VLAN:
      memset(U2IdsEventV6Ptr,'\0',sizeof(Unified2IDSEventIPv6));
      memcpy(U2IdsEventV6Ptr,RecordData,sizeof(Unified2IDSEventIPv6));
      SpoolerEventPtr =(void *)U2IdsEventV6Ptr;
      break;
      
    default:
      /* XXX */
      return 1;
      break;
      
    }
  
  return 0;
}


int SpoolerCheckEventPtr(void)
{
  if(SpoolerEventPtr == NULL)
    {
      /* XXX */
      return 1;
    }

  return 0;
}

void * SpoolerGetEventPtr(void)
{
  return SpoolerEventPtr;
}

void spoolerProcessRecord(Spooler *spooler, int fire_output)
{
  struct pcap_pkthdr      pkth;
  uint32_t                type = 0;
  
  if(LogPacket == NULL)
    {
      FatalError("spoolerProcessRecord(): LogPacket is null ....i blame finch! \n");
    }
  
  /* convert type once */
  type = ntohl(((Unified2RecordHeader *)spooler->record.header)->type);
  
  /* increment the stats */
  pc.total_records++;
  
  switch(SpoolerState)
    {
    case SPOOLER_NULL:

      /* Callback in case dual event would be logged...(shoudln't happen)*/
    EVENT_PROCESS:
      if(type ==  UNIFIED2_EVENT)
	{
	  LogMessage("spoolerProcessRecord(): A long long time ago...\n"
		     "caught UNIFIED2_EVENT event type[%lu] ..running a old snort?\n "
		     "Now snort should log UNIFIED2_IDS_EVENT event type [%lu].\n",
		     UNIFIED2_EVENT,
		     UNIFIED2_IDS_EVENT);
	  
	  SpoolerState = SPOOLER_FAST_FORWARD;
	}
      
      /* In case that we have a lonely packet. */
      if( (type ==  UNIFIED2_PACKET))
	{
	  /* increment the stats */
          pc.total_packets++;
	  
	  LogMessage("spoolerProcessRecord(): Received a UNIFIED2 Lonely packet with event_id [%lu] \n\n",
                     ntohl(((Unified2Packet *)spooler->record.data)->event_id));
	  
          /* Cleanup ze mess */
          memset(LogPacket,'\0',sizeof(Packet));
          spooler->record.pkt = LogPacket;
	  
          pkth.caplen = ntohl(((Unified2Packet *)spooler->record.data)->packet_length);
          pkth.len = pkth.caplen;
          pkth.ts.tv_sec = ntohl(((Unified2Packet *)spooler->record.data)->packet_second);
          pkth.ts.tv_usec = ntohl(((Unified2Packet *)spooler->record.data)->packet_microsecond);
	  
          /* decode the packet from the Unified2Packet information */
          datalink = ntohl(((Unified2Packet *)spooler->record.data)->linktype);
	  DecodePacket(datalink, spooler->record.pkt, &pkth,
                       ((Unified2Packet *)spooler->record.data)->packet_data);
	  
	  CallOutputPlugins(OUTPUT_TYPE__SPECIAL,
			    spooler->record.pkt,
			    NULL,
                            type);
	  
	  /* Should not be changed, but lets set it anyways */
	  /* Reset Spooler state */
          SpoolerState = SPOOLER_NULL;
	}
      else
	{
	  if(((type != UNIFIED2_IDS_EVENT ) &&
	      (type != UNIFIED2_IDS_EVENT_IPV6 ) &&
	      (type != UNIFIED2_IDS_EVENT_MPLS) &&
	      (type != UNIFIED2_IDS_EVENT_IPV6_MPLS) &&
	      (type != UNIFIED2_IDS_EVENT_VLAN) &&
	      (type != UNIFIED2_IDS_EVENT_IPV6_VLAN)))
	    {
	      FatalError("Are you using a custom unified2 output plugin? Caught record type [%lu] in SPOOLER_NULL State\n");
	      return;
	    }
	  
	  if( (SpoolerSetStaticEvent(type,spooler->record.data)))
	    {
	      /* XXX */
	      FatalError("SpoolerSetStaticEvent(), failed \n");
	    }
	  
	  /* increment the stats */
	  pc.total_events++;
	  
	  /* We are now in Event State */
	  SpoolerState = SPOOLER_EVENT;
	}
      
      break;
      
    case SPOOLER_EVENT:
      
      if( SpoolerCheckEventPtr())
	{
	  /* XXX */
	  FatalError("SpoolerCheckEventPtr(), error in spoolerProcessRecord(), something went wrong ...\n");
	}
      
      if( ((type == UNIFIED2_IDS_EVENT) ||
           (type == UNIFIED2_IDS_EVENT_IPV6 ) ||
           (type == UNIFIED2_IDS_EVENT_MPLS) ||
           (type == UNIFIED2_IDS_EVENT_IPV6_MPLS) ||
           (type == UNIFIED2_IDS_EVENT_VLAN) ||
           (type == UNIFIED2_IDS_EVENT_IPV6_VLAN)))
        {
	  
	  CallOutputPlugins(OUTPUT_TYPE__SPECIAL,
                            NULL,
                            SpoolerGetEventPtr(),
                            type);
	  
	  /* setting the spooler state back to null shouldn't happend but we do it anyways */
          SpoolerState = SPOOLER_NULL;
	  goto EVENT_PROCESS;
        }
      else if( type == UNIFIED2_PACKET )
	{
	  /* increment the stats */  
	  pc.total_packets++;
	  
	  /* Cleanup ze mess */
	  memset(LogPacket,'\0',sizeof(Packet));
	  spooler->record.pkt = LogPacket;
	  
	  pkth.caplen = ntohl(((Unified2Packet *)spooler->record.data)->packet_length);
	  pkth.len = pkth.caplen;
	  pkth.ts.tv_sec = ntohl(((Unified2Packet *)spooler->record.data)->packet_second);
	  pkth.ts.tv_usec = ntohl(((Unified2Packet *)spooler->record.data)->packet_microsecond);
	  
	  /* decode the packet from the Unified2Packet information */
	  datalink = ntohl(((Unified2Packet *)spooler->record.data)->linktype);
	  DecodePacket(datalink, spooler->record.pkt, &pkth,
		       ((Unified2Packet *)spooler->record.data)->packet_data);
	  
	  CallOutputPlugins(OUTPUT_TYPE__SPECIAL,
                            spooler->record.pkt,
                            SpoolerGetEventPtr(),
                            type);
	  
	  /* Reset Spooler state */
	  SpoolerState = SPOOLER_NULL;
	}
      /* Will integrate EXTRA_DATA processing in here soon ..*/
      else if(type == UNIFIED2_EXTRA_DATA)
	{
	  LogMessage("Caught a UNIFIED2_EXTRA_DATA, spooler and output pluggin do not yet fully support  UNIFIED2_EXTRA_DATA, processing next event.\n");
	  /* Reset Spooler state */
	  SpoolerState = SPOOLER_NULL;
	}
      else 
	{
	  FatalError("Whats going on ...\n");
	}
      
      break;
      
    case SPOOLER_FAST_FORWARD:
      LogMessage("Caught a legacy event companion event type [%lu], fast forward \n",type);
      /* Reset Spooler state */
      SpoolerState = SPOOLER_NULL;
      break;
      
    default:
      FatalError("Unknown spooler state [%lu] \n\n",SpoolerState);
      break;
    }
  
  spoolerWriteWaldo(&barnyard2_conf->waldo, spooler);  
}


void spoolerFreeRecord(Record *record)
{
  if (record->data)
    {
      free(record->data);
    }
  
  record->data = NULL;
}

/*
** WALDO FILE OPERATIONS
*/

/*
** spoolerOpenWaldo(Waldo *waldo, uint8_t mode)
**
** Description:
**   Open the waldo file, non-blocking, defined in the Waldo structure
*/
int spoolerOpenWaldo(Waldo *waldo, uint8_t mode)
{
  struct stat         waldo_info;
  int                 waldo_file_flags = 0;
  mode_t              waldo_file_mode = 0;
  int                 ret = 0;
  
  /* check if waldo file is already open and in the correct mode */
  if ( (waldo->state & WALDO_STATE_OPEN) && (waldo->fd != -1) && (waldo->mode == mode) )
    {
      return WALDO_FILE_SUCCESS;
    }
  
  /* check that a waldo file has been specified */
  if ( waldo->filepath == NULL )
    {
      return WALDO_FILE_EEXIST;
    }

    /* stat the file to see it exists */
    ret = stat(waldo->filepath, &waldo_info);
    
    if ( mode == WALDO_MODE_READ )
        waldo_file_flags = ( O_RDONLY );
    else if ( mode == WALDO_MODE_WRITE )
    {
        waldo_file_flags = ( O_CREAT | O_WRONLY );
        waldo_file_mode = ( S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH ) ;
    }

    /* open the file non-blocking */
    if ( (waldo->fd=open(waldo->filepath, waldo_file_flags, waldo_file_mode)) == -1 )
    {
        LogMessage("WARNING: Unable to open waldo file '%s' (%s)\n", waldo->filepath,
                    strerror(errno));
        return WALDO_FILE_EOPEN;
    }

    if ( ret != 0 )
        return WALDO_FILE_EEXIST;

    /* set waldo state and mode */
    waldo->state |= WALDO_STATE_OPEN;
    waldo->mode = mode;

    return WALDO_FILE_SUCCESS;
}

/*
** spoolerCloseWaldo(Waldo *waldo)
**
** Description:
**   Open the waldo file, non-blocking, defined in the Waldo structure
**
*/
int spoolerCloseWaldo(Waldo *waldo)
{
    /* check we have a valid file descriptor */
    if (waldo->state & WALDO_STATE_OPEN)
        return WALDO_FILE_EOPEN;

    /* close the file */
    close(waldo->fd);
    waldo->fd = -1;

    /* reset open state and mode */
    waldo->state &= ( ~WALDO_STATE_OPEN );
    waldo->mode = WALDO_MODE_NULL;

    return WALDO_FILE_SUCCESS;
}

/*
** spoolReadWaldo(Waldo *waldo) 
**
** Description:
**   Read the waldo file defined in the Waldo structure and populate all values
** within.
**
*/
int spoolerReadWaldo(Waldo *waldo)
{
    int                 ret;
    WaldoData           wd;

    /* check if we have a file in the correct mode (READ) */
    if ( waldo->mode != WALDO_MODE_READ )
    {
        spoolerCloseWaldo(waldo);
        if ( (ret=spoolerOpenWaldo(waldo, WALDO_MODE_READ)) != WALDO_FILE_SUCCESS )
            return ret;
    }
    else if ( ! (waldo->state & WALDO_STATE_OPEN) )
    {
        if ( (ret=spoolerOpenWaldo(waldo, WALDO_MODE_READ)) != WALDO_FILE_SUCCESS )
            return ret;
    }
    else
    {
        /* ensure we are at the beggining since we must be open and in read */
        lseek(waldo->fd, 0, SEEK_SET);
    }

    /* read values into temporary WaldoData structure */
    ret = read(waldo->fd, &wd, sizeof(WaldoData));

    /* TODO: additional checks on the waldo file data to test corruption */
    if ( ret != sizeof(WaldoData) )
        return WALDO_FILE_ETRUNC;

    /* copy waldo file contents to the directory structure */
    memcpy(&waldo->data, &wd, sizeof(WaldoData));

    DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,
        "Waldo read\n\tdir:  %s\n\tbase: %s\n\ttime: %lu\n\tidx:  %d\n",
        waldo->data.spool_dir, waldo->data.spool_filebase,
        waldo->data.timestamp, waldo->data.record_idx););

    /* close the file */
    spoolerCloseWaldo(waldo);

    return WALDO_FILE_SUCCESS;
}

/*
** spoolerWriteWaldo(Waldo *waldo)
**
** Description:
**   Write to the waldo file
**
*/
int spoolerWriteWaldo(Waldo *waldo, Spooler *spooler)
{
    int                 ret;

    /* check if we are using waldo files */
    if ( ! (waldo->state & WALDO_STATE_ENABLED) )
        return WALDO_STRUCT_EMPTY;

    /* check that a waldo file exists before continued */
    if (waldo == NULL)
        return WALDO_STRUCT_EMPTY;

    /* update fields */
    waldo->data.timestamp = spooler->timestamp;
    waldo->data.record_idx = spooler->record_idx;

    /* check if we have a file in the correct mode (READ) */
    if ( waldo->mode != WALDO_MODE_WRITE )
    {
        spoolerCloseWaldo(waldo);
        spoolerOpenWaldo(waldo, WALDO_MODE_WRITE);
    }
    else if ( ! (waldo->state & WALDO_STATE_OPEN) )
    {
        spoolerOpenWaldo(waldo, WALDO_MODE_WRITE);
    }
    else
    {
        /* ensure we are at the start since we must be open and in write */
        lseek(waldo->fd, 0, SEEK_SET);
    }

    /* write values */
    ret = write(waldo->fd, &waldo->data, sizeof(WaldoData));

    if (ret != sizeof(WaldoData) )
        return WALDO_FILE_ETRUNC;

    DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,
        "Waldo write\n\tdir:  %s\n\tbase: %s\n\ttime: %lu\n\tidx:  %d\n",
        waldo->data.spool_dir, waldo->data.spool_filebase,
        waldo->data.timestamp, waldo->data.record_idx););

    return WALDO_FILE_SUCCESS;
}

