/* 
**
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
static Spooler *spoolerOpen(const char *, const char *, uint32_t);
int spoolerClose(Spooler *);
static int spoolerReadRecordHeader(Spooler *);
static int spoolerReadRecord(Spooler *);
static void spoolerProcessRecord(Spooler *, int);
static void spoolerFreeRecord(Record *record);

static int spoolerWriteWaldo(Waldo *, Spooler *);
static int spoolerOpenWaldo(Waldo *, uint8_t);
int spoolerCloseWaldo(Waldo *);

static int spoolerEventCachePush(Spooler *, uint32_t, void *);
static EventRecordNode * spoolerEventCacheGetByEventID(Spooler *, uint32_t);
static EventRecordNode * spoolerEventCacheGetHead(Spooler *);
static uint8_t spoolerEventCacheHeadUsed(Spooler *);
static int spoolerEventCacheClean(Spooler *);

#ifdef RB_EXTRADATA
static Packet * spoolerAllocateFirstPacket(Spooler *);
static int spoolerExtraDataCachePush(Spooler *, uint32_t, void *, EventRecordNode *);
static void spoolerFireLastEvent(Spooler *);
static int spoolerCallOutputPluginsByERN (EventRecordNode *);
static int spoolerExtraDataCacheClean(EventRecordNode *ern);
static void spoolerPrint(Spooler *, int);
static void spoolerPrintRecord(Spooler *, int);
static void spoolerPrintERN(EventRecordNode *, int);
static void spoolerPrintEDRN(ExtraDataRecordNode *, int);
static void spoolerPrintU2ED (Unified2ExtraData *, const char *);
static void spoolerPrintRecordPacket(Spooler *);
static void spoolerPrintERNPacket(EventRecordNode *);
#endif

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

static Spooler *spoolerOpen(const char *dirpath, const char *filename, uint32_t extension)
{
    Spooler             *spooler = NULL;
    int                 ret;

    /* perform sanity checks */
    if ( filename == NULL )
        return NULL;

    /* create the spooler structure and allocate all memory */
    spooler = (Spooler *)SnortAlloc(sizeof(Spooler));

    RegisterSpooler(spooler);

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
	UnRegisterSpooler(spooler);
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
	UnRegisterSpooler(spooler);
        spoolerClose(spooler);
        spooler = NULL;
        return NULL;
    }

    /* set state to initially be open */
    spooler->state = SPOOLER_STATE_OPENED;

    spooler->ifn = GetInputPlugin("unified2");

    if (spooler->ifn == NULL)
    {
	UnRegisterSpooler(spooler);
        spoolerClose(spooler);
        spooler = NULL;
        FatalError("ERROR: No suitable input plugin found!\n");
    }

    TAILQ_INIT(&spooler->event_cache);

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

void RegisterSpooler(Spooler *spooler)
{
    Barnyard2Config *bc =  BcGetConfig();
    
    if(!bc)
	return;
    
    
    if(bc->spooler)
    {
	/* XXX */
	FatalError("[%s()], can't register spooler. \n",
		   __FUNCTION__);
    }
    else
    {
	bc->spooler = spooler;
    }
    
    return;
}

void UnRegisterSpooler(Spooler *spooler)
{
    Barnyard2Config *bc =  BcGetConfig();

    if(!bc)
	return;
    
    if(bc->spooler != spooler)
    {
	/* XXX */
	FatalError("[%s()], can't un-register spooler. \n",
		   __FUNCTION__);
    }
    else
    {
	bc->spooler = NULL;
    }

    return;
}



static int spoolerReadRecordHeader(Spooler *spooler)
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

static int spoolerReadRecord(Spooler *spooler)
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
	/* for SIGUSR1 / dropstats */
	SignalCheck();
	
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

    u_int32_t waldo_timestamp = 0;
    waldo_timestamp = timestamp; /* fix possible bug by keeping invocated timestamp at the time of the initial call */
    
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
        /* for SIGUSR1 / dropstats */
        SignalCheck();

        /* no spooler exists so let's create one */
        if (spooler == NULL)
        {
            /* find the next file to spool */
            ret = FindNextExtension(dirpath, filebase, timestamp, &extension);

            /* The file found is not the same as specified in the waldo,
               thus we need to reset record_start, since we are obviously not processing the same file*/
            if(waldo_timestamp != extension)
            {
                record_start = 0; /* There is no danger to resetting record_start to 0
                                     if called timestamp is not the same */
            }


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
            else
            {
                /* Make sure we create a new waldo even if we did not have processed an event */
                if(waldo_timestamp != extension)
                {
                    spooler->record_idx = 0;    
                    spoolerWriteWaldo(&barnyard2_conf->waldo, spooler);
                }
                waiting_logged = 0;
                
                /* set timestamp to ensure we look for a newer file next time */
                timestamp = extension + 1;
            }
            
            continue;
        }
#ifdef RB_EXTRADATA
        if (AlarmCheck())
        {
            spoolerFireLastEvent(spooler);
            AlarmClear();
        }
#endif
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
                UnRegisterSpooler(spooler);
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
#ifdef RB_EXTRADATA
                spoolerFireLastEvent(spooler);
#endif
                UnRegisterSpooler(spooler);
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
    if(barnyard2_conf)
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

static void spoolerProcessRecord(Spooler *spooler, int fire_output)
{
#ifndef RB_EXTRADATA
    struct pcap_pkthdr      pkth;
#endif
    uint32_t                type;
    EventRecordNode         *ernCache;

    /* convert type once */
    type = ntohl(((Unified2RecordHeader *)spooler->record.header)->type);

    /* increment the stats */
    pc.total_records++;
    switch (type)
    {
        case UNIFIED2_PACKET:
            pc.total_packets++;
            break;
        case UNIFIED2_IDS_EVENT:
        case UNIFIED2_IDS_EVENT_IPV6:
        case UNIFIED2_IDS_EVENT_MPLS:
        case UNIFIED2_IDS_EVENT_IPV6_MPLS:
        case UNIFIED2_IDS_EVENT_VLAN:
        case UNIFIED2_IDS_EVENT_IPV6_VLAN:
            pc.total_events++;
            break;
#ifdef RB_EXTRADATA
        case UNIFIED2_EXTRA_DATA:
            pc.total_extra_data++;
            break;
#endif
        default:
            pc.total_unknown++;
    }

    /* check if it's packet */
    if (type == UNIFIED2_PACKET)
    {
#ifdef RB_EXTRADATA
        if (spooler->record.data != NULL)
        {
            /* convert event id once */
            uint32_t event_id = ntohl(((Unified2Packet *)spooler->record.data)->event_id);

            /* check if there is a previously cached event that matches this event id */
            ernCache = spoolerEventCacheGetByEventID(spooler, event_id);

            /* if the packet and cached event share the same id */
            if (ernCache != NULL)
            {
                /* add the packet into the cached event */
                switch (ernCache->type)
                {
                    case UNIFIED2_IDS_EVENT:
                        /* if there is no previous packet */
                        if (((Unified2IDSEvent_legacy_WithPED *)ernCache->data)->packet == NULL)
                            ((Unified2IDSEvent_legacy_WithPED *)ernCache->data)->packet = spoolerAllocateFirstPacket(spooler);
                        /* when != NULL there is a previous packet cached with the event. do nothing here. */
                        break;
                    case UNIFIED2_IDS_EVENT_MPLS:
                    case UNIFIED2_IDS_EVENT_VLAN:
                        /* if there is no previous packet */
                        if (((Unified2IDSEvent_WithPED *)ernCache->data)->packet == NULL)
                            ((Unified2IDSEvent_WithPED *)ernCache->data)->packet = spoolerAllocateFirstPacket(spooler);
                        /* when != NULL there is a previous packet cached with the event. do nothing here. */
                        break;
                    case UNIFIED2_IDS_EVENT_IPV6:
                        /* if there is no previous packet */
                        if (((Unified2IDSEventIPv6_legacy_WithPED *)ernCache->data)->packet == NULL)
                            ((Unified2IDSEventIPv6_legacy_WithPED *)ernCache->data)->packet = spoolerAllocateFirstPacket(spooler);
                        /* when != NULL there is a previous packet cached with the event. do nothing here. */
                        break;
                    case UNIFIED2_IDS_EVENT_IPV6_MPLS:
                    case UNIFIED2_IDS_EVENT_IPV6_VLAN:
                        /* if there is no previous packet */
                        if (((Unified2IDSEventIPv6_WithPED *)ernCache->data)->packet == NULL)
                            ((Unified2IDSEventIPv6_WithPED *)ernCache->data)->packet = spoolerAllocateFirstPacket(spooler);
                        /* when != NULL there is a previous packet cached with the event. do nothing here. */
                        break;
                    default:
                        LogMessage("WARNING: spoolerProcessRecord(): type inconsistent (%d)\n", ernCache->type);
                    break;
                }
            }
            //else
            //{
                // We are assuming that a packet record will never show up before an event record does
                // This hypothetical case should be taken into account after testings
            //}
        }
#else
        /* convert event id once */
        uint32_t event_id = ntohl(((Unified2Packet *)spooler->record.data)->event_id);

        /* check if there is a previously cached event that matches this event id */
        ernCache = spoolerEventCacheGetByEventID(spooler, event_id);

        /* allocate space for the packet and construct the packet header */
        spooler->record.pkt = SnortAlloc(sizeof(Packet));

        pkth.caplen = ntohl(((Unified2Packet *)spooler->record.data)->packet_length);
        pkth.len = pkth.caplen;
        pkth.ts.tv_sec = ntohl(((Unified2Packet *)spooler->record.data)->packet_second);
        pkth.ts.tv_usec = ntohl(((Unified2Packet *)spooler->record.data)->packet_microsecond);

        /* decode the packet from the Unified2Packet information */
        datalink = ntohl(((Unified2Packet *)spooler->record.data)->linktype);
        DecodePacket(datalink, spooler->record.pkt, &pkth, 
                     ((Unified2Packet *)spooler->record.data)->packet_data);

        /* This is a fixup for portscan... */
        if( (spooler->record.pkt->iph == NULL) && 
            ((spooler->record.pkt->inner_iph != NULL) && (spooler->record.pkt->inner_iph->ip_proto == 255)))
            {
                spooler->record.pkt->iph = spooler->record.pkt->inner_iph;
            }

        /* check if it's been re-assembled */
        if (spooler->record.pkt->packet_flags & PKT_REBUILT_STREAM)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Packet has been rebuilt from a stream\n"););
        }

        /* if the packet and cached event share the same id */
        if ( ernCache != NULL )
        {
            /* call output plugins with a "SPECIAL" alert format (both Event and Packet information) */
            DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Firing SPECIAL style (Packet+Event)\n"););

            if ( fire_output && 
                 ((ernCache->used == 0) || BcAlertOnEachPacketInStream()) )
                CallOutputPlugins(OUTPUT_TYPE__SPECIAL, 
                              spooler->record.pkt, 
                              ernCache->data, 
                              ernCache->type);

            /* indicate that the cached event has been used */
            ernCache->used = 1;
        }
        else
        {
            /* fire the event cache head only if not already used (ie dirty) */ 
            if ( spoolerEventCacheHeadUsed(spooler) == 0 )
            {
                ernCache = spoolerEventCacheGetHead(spooler);

                /* call output plugins with an "ALERT" format (cached Event information only) */
                DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Firing ALERT style (Event only)\n"););

                if (fire_output)
                    CallOutputPlugins(OUTPUT_TYPE__ALERT, 
                                      NULL,
                                      ernCache->data, 
                                      ernCache->type);

                /* set the event cache used flag */
                ernCache->used = 1;
            }

            /* call output plugins with a "LOG" format (Packet information only) */
            DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Firing LOG style (Packet)\n"););

            if (fire_output)
                CallOutputPlugins(OUTPUT_TYPE__SPECIAL,
                                  spooler->record.pkt, 
                                  NULL, 
                                  0);
        }

        /* free the memory allocated in this function */
        free(spooler->record.pkt);
        spooler->record.pkt = NULL;
#endif

        /* waldo operations occur after the output plugins are called */
        if (fire_output)
            spoolerWriteWaldo(&barnyard2_conf->waldo, spooler);
    }
    /* check if it's an event of known sorts */
    else if(type == UNIFIED2_IDS_EVENT || type == UNIFIED2_IDS_EVENT_IPV6 ||
            type == UNIFIED2_IDS_EVENT_MPLS || type == UNIFIED2_IDS_EVENT_IPV6_MPLS ||
            type == UNIFIED2_IDS_EVENT_VLAN || type == UNIFIED2_IDS_EVENT_IPV6_VLAN)
    {
        /* fire the cached event only if not already used (ie dirty) */ 
        if ( spoolerEventCacheHeadUsed(spooler) == 0 )
        {
            /* call output plugins with an "ALERT" format (cached Event information only) */
            DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Firing ALERT style (Event only)\n"););

            ernCache = spoolerEventCacheGetHead(spooler);

#ifdef RB_EXTRADATA
            /* not checked ernCache->used == 0 since this cached event must be fired in any case,
             even though the expected value should be ernCache->used = 0 */
            if (fire_output)
                spoolerCallOutputPluginsByERN(ernCache);
#else
            if (fire_output)
                CallOutputPlugins(OUTPUT_TYPE__ALERT, 
                              NULL,
                              ernCache->data, 
                              ernCache->type);
#endif

            /* flush the event cache flag */
            ernCache->used = 1;
        }

        /* cache new data */
        spoolerEventCachePush(spooler, type, spooler->record.data);
        spooler->record.data = NULL;

        /* waldo operations occur after the output plugins are called */
        if (fire_output)
            spoolerWriteWaldo(&barnyard2_conf->waldo, spooler);
    }
    else if (type == UNIFIED2_EXTRA_DATA)
    {
#ifdef RB_EXTRADATA
        if (spooler->record.data != NULL)
        {
            /* convert event id once */
            uint32_t event_id = ntohl(((Unified2ExtraData *)(((Unified2ExtraDataHdr *)spooler->record.data)+1))->event_id);

            /* check if there is a previously cached event that matches this event id */
            ernCache = spoolerEventCacheGetByEventID(spooler, event_id);

            /* if the packet and cached event share the same id */
            if ( ernCache != NULL )
            {
                /* include extra data record */
                spoolerExtraDataCachePush(spooler, type, spooler->record.data, ernCache);
                spooler->record.data = NULL;
            }
            //else
            //{
                // We are assuming that an extra data record will never show up before an event record does
                // This hypothetical case should be taken into account after testings
            //}
        }
#endif

        /* waldo operations occur after the output plugins are called */
        if (fire_output)
            spoolerWriteWaldo(&barnyard2_conf->waldo, spooler);
    }
    else
    {
        /* fire the cached event only if not already used (ie dirty) */ 
        if ( spoolerEventCacheHeadUsed(spooler) == 0 )
        {
            /* call output plugins with an "ALERT" format (cached Event information only) */
            DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Firing ALERT style (Event only)\n"););

            ernCache = spoolerEventCacheGetHead(spooler);

            if (fire_output)
                CallOutputPlugins(OUTPUT_TYPE__ALERT, 
                              NULL,
                              ernCache->data, 
                              ernCache->type);

            /* waldo operations occur after the output plugins are called */
            if (fire_output)
                spoolerWriteWaldo(&barnyard2_conf->waldo, spooler); 
        }
    }

    /* clean the cache out */
    spoolerEventCacheClean(spooler);
#ifdef RB_EXTRADATA
    /* If there is no more records in TIME_ALARM seconds flush the cached records */
    AlarmStart(TIME_ALARM);
#endif
}

static int spoolerEventCachePush(Spooler *spooler, uint32_t type, void *data)
{
    EventRecordNode     *ernNode;

    DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Caching event %lu\n",ntohl(((Unified2EventCommon *)data)->event_id)););

    /* allocate memory */
    ernNode = (EventRecordNode *)SnortAlloc(sizeof(EventRecordNode));

    /* create the new node */
    ernNode->used = 0;
    ernNode->type = type;
    ernNode->data = data;

    /* add new events to the front of the cache */
    TAILQ_INSERT_HEAD(&spooler->event_cache, ernNode, entry);
    spooler->events_cached++;

    DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Cached event: %d\n", spooler->events_cached););

    return 0;
}

static EventRecordNode *spoolerEventCacheGetByEventID(Spooler *spooler, uint32_t event_id)
{
    EventRecordNode     *ernCurrent = NULL;

    TAILQ_FOREACH(ernCurrent, &spooler->event_cache, entry)
    {
        if ( ntohl(((Unified2EventCommon *)ernCurrent->data)->event_id) == event_id )
        {
            return ernCurrent;
        }
    }

    return NULL;
}

static EventRecordNode *spoolerEventCacheGetHead(Spooler *spooler)
{
    if ( spooler == NULL )
        return NULL;

    return TAILQ_FIRST(&spooler->event_cache);
}

static uint8_t spoolerEventCacheHeadUsed(Spooler *spooler)
{
    if ( spooler == NULL || TAILQ_EMPTY(&spooler->event_cache) )
        return 255;

    return spoolerEventCacheGetHead(spooler)->used;
}

/* Extracted from Magnus Edenhill's librd */
#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(elm,tmpelm,head,field) \
        for ((elm) = TAILQ_FIRST(head) ; \
        (elm) && ((tmpelm) = TAILQ_NEXT((elm), field), 1) ; \
        (elm) = (tmpelm))
#endif

static int spoolerEventCacheClean(Spooler *spooler)
{
    EventRecordNode     *ernCurrent = NULL;
    EventRecordNode     *ernPrev = NULL;

    if (spooler == NULL || TAILQ_EMPTY(&spooler->event_cache) )
        return 1;
    
    ernCurrent = TAILQ_LAST(&spooler->event_cache,_EventRecordList);
    while (ernCurrent != NULL && spooler->events_cached > barnyard2_conf->event_cache_size )
    {
        ernPrev = TAILQ_PREV(ernCurrent, _EventRecordList, entry);
        if ( ernCurrent->used == 1 )
        {
            /* Delete from list */
            TAILQ_REMOVE(&spooler->event_cache, ernCurrent, entry);
            spooler->events_cached--;

            if(ernCurrent->data != NULL)
            {
#ifdef RB_EXTRADATA
                spoolerExtraDataCacheClean(ernCurrent);
#endif
                free(ernCurrent->data);
            }

            if(ernCurrent != NULL)
                free(ernCurrent);
        }
        ernCurrent = ernPrev;
    }

    return 0;
}

void spoolerEventCacheFlush(Spooler *spooler)
{
    EventRecordNode *next_ptr = NULL;
    EventRecordNode *evt_ptr = NULL;
    
    if (spooler == NULL || TAILQ_EMPTY(&spooler->event_cache))
        return;
    
    TAILQ_FOREACH_SAFE(evt_ptr,next_ptr,&spooler->event_cache,entry)
    {
        TAILQ_REMOVE(&spooler->event_cache,evt_ptr,entry);

        if(evt_ptr->data)
        {
#ifdef RB_EXTRADATA
            spoolerExtraDataCacheClean(evt_ptr);
#endif
            free(evt_ptr->data);
            evt_ptr->data = NULL;
        }

        free(evt_ptr);
    }

    return;
}


static void spoolerFreeRecord(Record *record)
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
static int spoolerOpenWaldo(Waldo *waldo, uint8_t mode)
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
    if(waldo == NULL)
	return WALDO_STRUCT_EMPTY;
    
    /* check we have a valid file descriptor */
    if (waldo->state & WALDO_STATE_OPEN)
        return WALDO_FILE_EOPEN;
    
    /* close the file */
    if(waldo->fd > 0)
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
	/* close waldo if appropriate */
	if(barnyard2_conf)
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

    
    /* close waldo if appropriate */
    if(barnyard2_conf)
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
static int spoolerWriteWaldo(Waldo *waldo, Spooler *spooler)
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
	/* close waldo if appropriate */
        if(barnyard2_conf)
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

#ifdef RB_EXTRADATA
static Packet * spoolerAllocateFirstPacket(Spooler *spooler)
{
    struct pcap_pkthdr      pkth;
    Packet *packet = NULL;

    /* allocate space for the packet and construct the packet header */
    packet = SnortAlloc(sizeof(Packet));

    pkth.caplen = ntohl(((Unified2Packet *)spooler->record.data)->packet_length);
    pkth.len = pkth.caplen;
    pkth.ts.tv_sec = ntohl(((Unified2Packet *)spooler->record.data)->packet_second);
    pkth.ts.tv_usec = ntohl(((Unified2Packet *)spooler->record.data)->packet_microsecond);

    /* decode the packet from the Unified2Packet information */
    datalink = ntohl(((Unified2Packet *)spooler->record.data)->linktype);
    DecodePacket(datalink, packet, &pkth, 
                 ((Unified2Packet *)spooler->record.data)->packet_data);

    /* This is a fixup for portscan... */
    if( (packet->iph == NULL) && 
        ((packet->inner_iph != NULL) && (packet->inner_iph->ip_proto == 255)))
        {
            packet->iph = packet->inner_iph;
        }

    /* check if it's been re-assembled */
    if (packet->packet_flags & PKT_REBUILT_STREAM)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Packet has been rebuilt from a stream\n"););
    }

    return packet;
}

static int spoolerExtraDataCachePush(Spooler *spooler, uint32_t type, void *data, EventRecordNode *ern)
{
    ExtraDataRecordNode     *edrnNode;
    ExtraDataRecordCache    *edrc;

    DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Including extra data with cached event %lu\n",ntohl(((Unified2EventCommon *)data)->event_id)););

    /* allocate memory */
    edrnNode = (ExtraDataRecordNode *)SnortAlloc(sizeof(ExtraDataRecordNode));

    /* create the new node */
    edrnNode->used = 0;
    edrnNode->type = type;
    edrnNode->data = data;

    /* add new extra data to the front of the cache */
        switch (ern->type)
        {
            case UNIFIED2_IDS_EVENT:
                edrc = &((Unified2IDSEvent_legacy_WithPED *)(ern->data))->extra_data_cache;
                break;
            case UNIFIED2_IDS_EVENT_MPLS:
            case UNIFIED2_IDS_EVENT_VLAN:
                edrc = &((Unified2IDSEvent_WithPED *)(ern->data))->extra_data_cache;
                break;
            case UNIFIED2_IDS_EVENT_IPV6:
                edrc = &((Unified2IDSEventIPv6_legacy_WithPED *)(ern->data))->extra_data_cache;
                break;
            case UNIFIED2_IDS_EVENT_IPV6_MPLS:
            case UNIFIED2_IDS_EVENT_IPV6_VLAN:
                edrc = &((Unified2IDSEventIPv6_WithPED *)(ern->data))->extra_data_cache;
                break;
            default:
                edrc = NULL;
                LogMessage("WARNING: spoolerExtraDataCachePush(): type inconsistent (%d)\n", ern->type);
                break;
        }

    if (edrc != NULL)
        TAILQ_INSERT_HEAD(edrc, edrnNode, entry);

    return 0;
}

/* Fire the last cached event if it exists */
static void spoolerFireLastEvent(Spooler *spooler)
{
    EventRecordNode *ern;

    if (spooler == NULL)
    {
        LogMessage("spoolerFireLastEvent(): spooler is NULL\n");
        return;
    }

    if (TAILQ_EMPTY(&spooler->event_cache))
    {
        LogMessage("spoolerFireLastEvent(): event_cache is empty\n");
        return;
    }

    ern = TAILQ_FIRST(&spooler->event_cache);
    if (ern->used == 0)
        if (spoolerCallOutputPluginsByERN(ern))
            ern->used = 1;
}

static int spoolerCallOutputPluginsByERN(EventRecordNode *ern)
{
    int ret;

    if (ern == NULL)
        ret = 0;
    else if (ern->data == NULL)
        ret = 0;
    else
    {
        switch (ern->type)
        {
            case UNIFIED2_IDS_EVENT:
                /* if there is a cached packet */
                if (((Unified2IDSEvent_legacy_WithPED *)ern->data)->packet != NULL)
                {
                    CallOutputPlugins(OUTPUT_TYPE__SPECIAL,
                                      ((Unified2IDSEvent_legacy_WithPED *)ern->data)->packet,
                                      ern->data,
                                      ern->type);
                    free(((Unified2IDSEvent_legacy_WithPED *)ern->data)->packet);
                    ((Unified2IDSEvent_legacy_WithPED *)ern->data)->packet = NULL;
                }
                else
                    CallOutputPlugins(OUTPUT_TYPE__ALERT,
                                      NULL,
                                      ern->data,
                                      ern->type);
                break;
            case UNIFIED2_IDS_EVENT_MPLS:
            case UNIFIED2_IDS_EVENT_VLAN:
                /* if there is a cached packet */
                if (((Unified2IDSEvent_WithPED *)ern->data)->packet != NULL)
                {
                    CallOutputPlugins(OUTPUT_TYPE__SPECIAL,
                                      ((Unified2IDSEvent_WithPED *)ern->data)->packet,
                                      ern->data,
                                      ern->type);
                    free(((Unified2IDSEvent_WithPED *)ern->data)->packet);
                    ((Unified2IDSEvent_WithPED *)ern->data)->packet = NULL;
                }
                else
                    CallOutputPlugins(OUTPUT_TYPE__ALERT,
                                      NULL,
                                      ern->data,
                                      ern->type);
                break;
            case UNIFIED2_IDS_EVENT_IPV6:
                /* if there is a cached packet */
                if (((Unified2IDSEventIPv6_legacy_WithPED *)ern->data)->packet != NULL)
                {
                    CallOutputPlugins(OUTPUT_TYPE__SPECIAL,
                                      ((Unified2IDSEventIPv6_legacy_WithPED *)ern->data)->packet,
                                      ern->data,
                                      ern->type);
                    free(((Unified2IDSEventIPv6_legacy_WithPED *)ern->data)->packet);
                    ((Unified2IDSEventIPv6_legacy_WithPED *)ern->data)->packet = NULL;
                }
                else
                    CallOutputPlugins(OUTPUT_TYPE__ALERT,
                                      NULL,
                                      ern->data,
                                      ern->type);
                break;
            case UNIFIED2_IDS_EVENT_IPV6_MPLS:
            case UNIFIED2_IDS_EVENT_IPV6_VLAN:
                /* if there is a cached packet */
                if (((Unified2IDSEventIPv6_WithPED *)ern->data)->packet != NULL)
                {
                    CallOutputPlugins(OUTPUT_TYPE__SPECIAL,
                                      ((Unified2IDSEventIPv6_WithPED *)ern->data)->packet,
                                      ern->data,
                                      ern->type);
                    free(((Unified2IDSEventIPv6_WithPED *)ern->data)->packet);
                    ((Unified2IDSEventIPv6_WithPED *)ern->data)->packet = NULL;
                }
                else
                    CallOutputPlugins(OUTPUT_TYPE__ALERT,
                                      NULL,
                                      ern->data,
                                      ern->type);
                break;
            default:
                LogMessage("WARNING: spoolerCallOutputPluginsByERN(): type inconsistent (%d)\n", ern->type);
                break;
        }
        ret = 1;
    }
    return ret;
}

static int spoolerExtraDataCacheClean(EventRecordNode *ern)
{
    ExtraDataRecordNode *edrn_next = NULL;
    ExtraDataRecordNode *edrn = NULL;
    ExtraDataRecordCache *edrc = NULL;

    if (ern == NULL)
    {
        LogMessage("WARNING: spoolerExtraDataCacheClean(): ern is NULL\n");
        return 1;
    }

    switch (ern->type)
    {
        case UNIFIED2_IDS_EVENT:
            edrc = &((Unified2IDSEvent_legacy_WithPED *)(ern->data))->extra_data_cache;
            if (((Unified2IDSEvent_legacy_WithPED *)(ern->data))->packet != NULL)
            {
                free(((Unified2IDSEvent_legacy_WithPED *)(ern->data))->packet);
                ((Unified2IDSEvent_legacy_WithPED *)(ern->data))->packet = NULL;
            }
            break;
        case UNIFIED2_IDS_EVENT_MPLS:
        case UNIFIED2_IDS_EVENT_VLAN:
            edrc = &((Unified2IDSEvent_WithPED *)(ern->data))->extra_data_cache;
            if (((Unified2IDSEvent_WithPED *)(ern->data))->packet != NULL)
            {
                free(((Unified2IDSEvent_WithPED *)(ern->data))->packet);
                ((Unified2IDSEvent_WithPED *)(ern->data))->packet = NULL;
            }
            break;
        case UNIFIED2_IDS_EVENT_IPV6:
            edrc = &((Unified2IDSEventIPv6_legacy_WithPED *)(ern->data))->extra_data_cache;
            if (((Unified2IDSEventIPv6_legacy_WithPED *)(ern->data))->packet != NULL)
            {
                free(((Unified2IDSEventIPv6_legacy_WithPED *)(ern->data))->packet);
                ((Unified2IDSEventIPv6_legacy_WithPED *)(ern->data))->packet = NULL;
            }
            break;
        case UNIFIED2_IDS_EVENT_IPV6_MPLS:
        case UNIFIED2_IDS_EVENT_IPV6_VLAN:
            edrc = &((Unified2IDSEventIPv6_WithPED *)(ern->data))->extra_data_cache;
            if (((Unified2IDSEventIPv6_WithPED *)(ern->data))->packet != NULL)
            {
                free(((Unified2IDSEventIPv6_WithPED *)(ern->data))->packet);
                ((Unified2IDSEventIPv6_WithPED *)(ern->data))->packet = NULL;
            }
            break;
        case UNIFIED2_PACKET:
        case UNIFIED2_EXTRA_DATA:
            break;
        default:
            LogMessage("WARNING: spoolerExtraDataCacheClean(): type inconsistent (%d)\n", ern->type);
            break;
    }

    if (edrc == NULL || TAILQ_EMPTY(edrc))
        return 1;

    TAILQ_FOREACH_SAFE(edrn, edrn_next, edrc, entry)
    {
        TAILQ_REMOVE(edrc, edrn, entry);

        if (edrn && edrn->data)
        {
            free(edrn->data);
            edrn->data = NULL;
        }
        if (edrn)
        {
            free(edrn);
            edrn = NULL;
        }
    }

    return 0;
}

/*
    Print a formated output of spooler
    printType:
        0: No print.
        1: Print.
        2: Full print.
*/
static void spoolerPrint(Spooler *spooler, int printType)
{
    EventRecordNode *ern;

    if (spooler == NULL)
    {
        LogMessage("spoolerPrint(): spooler is NULL\n");
        return;
    }

    switch (printType)
    {
        case 0:
            LogMessage ("spoolerPrint(): No print\n");
            break;
        case 1:
        case 2:
            LogMessage ("spoolerPrint(): Print\n");
            LogMessage ("fd (file descriptor): %d\n", spooler->fd);
            LogMessage ("filepath: %s\n", spooler->filepath);
            LogMessage ("timestamp: %u\n", (unsigned int) spooler->timestamp);
            LogMessage ("state: %u\n", spooler->state);
            LogMessage ("offset: %u\n", spooler->offset);
            LogMessage ("record_idx: %u\n", spooler->record_idx);
            LogMessage ("magic: %u\n", spooler->magic);
            LogMessage ("header (header of input file): 0x%lu\n", (long unsigned int) spooler->header);

            // Print current record and related ERN if exists
            LogMessage ("[Current Record]\n");
            spoolerPrintRecord(spooler, printType);

            // Print every ERN
            LogMessage ("events_cached: %u\n", spooler->events_cached);
            if (printType == 2)
            {
                LogMessage ("[ERN from spooler->event_cache]\n");
                TAILQ_FOREACH(ern, &spooler->event_cache, entry)
                {
                    LogMessage ("ern->data->event_id: %u\n", ntohl(((Unified2EventCommon *)ern->data)->event_id));
                    spoolerPrintERN(ern, printType);
                }
            }

            LogMessage ("packets_cached: %u\n", spooler->packets_cached);

            break;
    }
    LogMessage ("\n");
}

static void spoolerPrintRecord(Spooler *spooler, int printType)
{
    uint32_t type;
    uint32_t event_id = -1;
    EventRecordNode *ern;

    if (spooler->record.header != NULL)
    {
        type = ntohl(((Unified2RecordHeader *)spooler->record.header)->type);
        switch (type)
        {
            case UNIFIED2_PACKET:
                LogMessage ("  spooler->record.header->type = %u (UNIFIED2_PACKET)\n", type);
                break;
            case UNIFIED2_IDS_EVENT:
            case UNIFIED2_IDS_EVENT_IPV6:
            case UNIFIED2_IDS_EVENT_MPLS:
            case UNIFIED2_IDS_EVENT_IPV6_MPLS:
            case UNIFIED2_IDS_EVENT_VLAN:
            case UNIFIED2_IDS_EVENT_IPV6_VLAN:
                LogMessage ("  spooler->record.header->type = %u (UNIFIED2_IDS_EVENT*)\n", type);
                break;
            case UNIFIED2_EXTRA_DATA:
                LogMessage ("  spooler->record.header->type = %u (UNIFIED2_EXTRA_DATA)\n", type);
                break;
            default:
                LogMessage ("  spooler->record.header->type = %u (Unknown)\n", type);
                return; // revisar si el return es lo mejor
        }
    }
    else
        LogMessage ("  spooler->record.header is NULL\n");

    if (spooler->record.data != NULL)
    {
        switch (type)
        {
            case UNIFIED2_PACKET:
            case UNIFIED2_IDS_EVENT:
            case UNIFIED2_IDS_EVENT_IPV6:
            case UNIFIED2_IDS_EVENT_MPLS:
            case UNIFIED2_IDS_EVENT_IPV6_MPLS:
            case UNIFIED2_IDS_EVENT_VLAN:
            case UNIFIED2_IDS_EVENT_IPV6_VLAN:
                event_id = ntohl(((Unified2EventCommon *)spooler->record.data)->event_id);
                LogMessage ("  spooler->record.data->event_id = %u\n", event_id);
                break;
            case UNIFIED2_EXTRA_DATA:
                event_id = ntohl(((Unified2ExtraData *)(((Unified2ExtraDataHdr *)spooler->record.data)+1))->event_id);
                LogMessage ("  spooler->record.data->event_id = %u\n", event_id);
                spoolerPrintU2ED((Unified2ExtraData *)(((Unified2ExtraDataHdr *)spooler->record.data)+1), "record.data");
                break;
            default:
                event_id = 0;
                LogMessage ("  spooler->record.data->event_id could not be catched\n");
        }
    }
    else
        LogMessage ("  spooler->record.data is NULL\n");

    if (spooler->record.pkt != NULL)
    {
        LogMessage ("  spooler->record.pkt: [");
        uint16_t i;
        uint16_t max = 16; // packet payload bytes to print
        max = spooler->record.pkt->dsize>max?max:spooler->record.pkt->dsize;
        if(spooler->record.pkt && spooler->record.pkt->dsize>0){
            for(i=0;i<max;++i)
                LogMessage ("%x",spooler->record.pkt->data[i]);
        }else{
            LogMessage ("NULL");
        }
        LogMessage ("]\n");
    }
    else
        LogMessage ("  spooler->record.pkt is NULL\n");


    if (event_id > 0)
    {
        ern = spoolerEventCacheGetByEventID(spooler, event_id);
        LogMessage ("[ERN of this Record]\n");
        spoolerPrintERN(ern, printType);
    }
}

static void spoolerPrintERN(EventRecordNode *ern, int printType)
{
    ExtraDataRecordCache *edrc;
    ExtraDataRecordNode *edrn, *edrn_next;
    Packet *p = NULL;

    if (ern != NULL)
    {
        switch (ern->type)
        {
            case UNIFIED2_IDS_EVENT:
                LogMessage ("  ern->type = %u (UNIFIED2_IDS_EVENT)\n", ern->type);
                break;
            case UNIFIED2_IDS_EVENT_MPLS:
            case UNIFIED2_IDS_EVENT_VLAN:
                LogMessage ("  ern->type = %u (UNIFIED2_IDS_EVENT_MPLS/VLAN)\n", ern->type);
                break;
            case UNIFIED2_IDS_EVENT_IPV6:
                LogMessage ("  ern->type = %u (UNIFIED2_IDS_EVENT_IPV6)\n", ern->type);
                break;
            case UNIFIED2_IDS_EVENT_IPV6_MPLS:
            case UNIFIED2_IDS_EVENT_IPV6_VLAN:
                LogMessage ("  ern->type = %u (UNIFIED2_IDS_EVENT_IPV6_MPLS/VLAN)\n", ern->type);
                break;
            default:
                LogMessage("  ern->type = %u (Unknown)\n", ern->type);
                break;
        }

        if (ern->data != NULL)
        {
            switch (ern->type)
            {
                case UNIFIED2_IDS_EVENT:
                    p = (Packet *) ((Unified2IDSEvent_legacy_WithPED *)ern->data)->packet;
                    edrc = &((Unified2IDSEvent_legacy_WithPED *)(ern->data))->extra_data_cache;
                    break;
                case UNIFIED2_IDS_EVENT_MPLS:
                case UNIFIED2_IDS_EVENT_VLAN:
                    p = (Packet *) ((Unified2IDSEvent_WithPED *)ern->data)->packet;
                    edrc = &((Unified2IDSEvent_WithPED *)(ern->data))->extra_data_cache;
                    break;
                case UNIFIED2_IDS_EVENT_IPV6:
                    p = (Packet *) ((Unified2IDSEventIPv6_legacy_WithPED *)ern->data)->packet;
                    edrc = &((Unified2IDSEventIPv6_legacy_WithPED *)(ern->data))->extra_data_cache;
                    break;
                case UNIFIED2_IDS_EVENT_IPV6_MPLS:
                case UNIFIED2_IDS_EVENT_IPV6_VLAN:
                    p = (Packet *) ((Unified2IDSEventIPv6_WithPED *)ern->data)->packet;
                    edrc = &((Unified2IDSEventIPv6_WithPED *)(ern->data))->extra_data_cache;
                    break;
                default:
                    p = NULL;
                    edrc = NULL;
                    break;
            }

            if (p != NULL)
            {
                LogMessage ("  ern->data->packet: [");
                uint16_t i;
                uint16_t max = 16; // packet payload bytes to print
                max = p->dsize>max?max:p->dsize;
                if(p && p->dsize>0){
                    for(i=0;i<max;++i)
                        LogMessage ("%x",p->data[i]);
                }else{
                    LogMessage ("NULL");
                }
                LogMessage ("]\n");
            }
            else
                LogMessage ("  ern->data->packet is NULL\n");

            if (edrc != NULL)
            {
                if (!TAILQ_EMPTY(edrc))
                {
                    LogMessage ("  [EDRN from ern->data->extra_data_cache]\n");
                    TAILQ_FOREACH_SAFE(edrn, edrn_next, edrc, entry)
                    {
                        spoolerPrintEDRN(edrn, printType);
                    }
                }
            }
            else
                LogMessage ("  ern->data->extra_data_cache is NULL\n");
        }
        else
            LogMessage ("  ern->data is NULL\n");

        LogMessage("  ern->used = %u\n", ern->used);
    }
    else
        LogMessage ("  ern is NULL\n");
}

static void spoolerPrintEDRN(ExtraDataRecordNode *edrn, int printType)
{
    if (edrn != NULL)
    {
        switch (edrn->type)
        {
            case UNIFIED2_IDS_EVENT:
                LogMessage ("  WRONG! edrn->type = %u (UNIFIED2_IDS_EVENT)\n", edrn->type);
                break;
            case UNIFIED2_IDS_EVENT_MPLS:
            case UNIFIED2_IDS_EVENT_VLAN:
                LogMessage ("  WRONG! edrn->type = %u (UNIFIED2_IDS_EVENT_MPLS/VLAN)\n", edrn->type);
                break;
            case UNIFIED2_IDS_EVENT_IPV6:
                LogMessage ("  WRONG! edrn->type = %u (UNIFIED2_IDS_EVENT_IPV6)\n", edrn->type);
                break;
            case UNIFIED2_IDS_EVENT_IPV6_MPLS:
            case UNIFIED2_IDS_EVENT_IPV6_VLAN:
                LogMessage ("  WRONG! edrn->type = %u (UNIFIED2_IDS_EVENT_IPV6_MPLS/VLAN)\n", edrn->type);
                break;
            case UNIFIED2_EXTRA_DATA:
                LogMessage ("  edrn->type = %u (UNIFIED2_EXTRA_DATA)\n", edrn->type);
                break;
            default:
                LogMessage("  edrn->type = %u (Unknown)\n", edrn->type);
                break;
        }

        if (edrn->data != NULL)
            spoolerPrintU2ED((Unified2ExtraData *)(((Unified2ExtraDataHdr *)edrn->data)+1), "edrn->data");
        else
            LogMessage ("    edrn->data is NULL\n");

        LogMessage("    edrn->used = %u\n", edrn->used);
    }
    else
        LogMessage ("    edrn is NULL\n");
}

static void spoolerPrintU2ED (Unified2ExtraData *U2ExtraData, const char *source)
{
    uint32_t type;
    uint32_t data_type;
    uint32_t blob_length;
    const uint8_t *sha_str;
    const char *str;
    int len;
    uint16_t smb_uid;

    type = ntohl(U2ExtraData->type); // data->type
    data_type = ntohl(U2ExtraData->data_type); // data->data_type
    blob_length = ntohl(U2ExtraData->blob_length); // data->blob_length

    switch (type)
    {
        case EVENT_INFO_FILE_SHA256:
            LogMessage ("    %s->type: %u (EVENT_INFO_FILE_SHA256)\n", source, type);
            LogMessage ("    %s->sha256: [", source);
            sha_str = (uint8_t *)(U2ExtraData+1);
            len = (int) (blob_length - sizeof(U2ExtraData->data_type) - sizeof(U2ExtraData->blob_length));
            uint16_t i;
            if(sha_str && len>0)
                for(i=0; i<len; ++i)
                    LogMessage("%x",sha_str[i]);
            else
                LogMessage("NULL");
            LogMessage("]\n");
            break;
        case EVENT_INFO_FILE_SIZE:
            LogMessage ("    %s->type: %u (EVENT_INFO_FILE_SIZE)\n", source, type);
            str = (char *)(U2ExtraData+1);
            len = (int) (ntohl(U2ExtraData->blob_length) - sizeof(U2ExtraData->data_type) - sizeof(U2ExtraData->blob_length));
            LogMessage("    %s->file_size: %s\n", source, str);
            break;
        case EVENT_INFO_FILE_NAME:
            LogMessage ("    %s->type: %u (EVENT_INFO_FILE_NAME)\n", source, type);
            str = (char *)(U2ExtraData+1);
            len = (int) (ntohl(U2ExtraData->blob_length) - sizeof(U2ExtraData->data_type) - sizeof(U2ExtraData->blob_length));
            LogMessage("    %s->file_name: %s\n", source, str);
            break;
        case EVENT_INFO_FILE_HOSTNAME:
            LogMessage ("    %s->type: %u (EVENT_INFO_FILE_HOSTNAME)\n", source, type);
            str = (char *)(U2ExtraData+1);
            len = (int) (ntohl(U2ExtraData->blob_length) - sizeof(U2ExtraData->data_type) - sizeof(U2ExtraData->blob_length));
            LogMessage("    %s->file_hostname: %s\n", source, str);
            break;
        case EVENT_INFO_FILE_MAILFROM:
            LogMessage ("    %s->type: %u (EVENT_INFO_FILE_MAILFROM)\n", source, type);
            str = (char *)(U2ExtraData+1);
            len = (int) (ntohl(U2ExtraData->blob_length) - sizeof(U2ExtraData->data_type) - sizeof(U2ExtraData->blob_length));
            LogMessage("    %s->email_sender: %s\n", source, str);
            break;
        case EVENT_INFO_FILE_RCPTTO:
            LogMessage ("    %s->type: %u (EVENT_INFO_FILE_RCPTTO)\n", source, type);
            str = (char *)(U2ExtraData+1);
            len = (int) (ntohl(U2ExtraData->blob_length) - sizeof(U2ExtraData->data_type) - sizeof(U2ExtraData->blob_length));
            LogMessage("    %s->email_destinations: %s\n", source, str);
            break;
        case EVENT_INFO_FILE_EMAIL_HDRS:
            LogMessage ("    %s->type: %u (EVENT_INFO_FILE_EMAIL_HDRS)\n", source, type);
            str = (char *)(U2ExtraData+1);
            len = (int) (ntohl(U2ExtraData->blob_length) - sizeof(U2ExtraData->data_type) - sizeof(U2ExtraData->blob_length));
            LogMessage("    %s->email_headers: %s\n", source, str);
            break;
        case EVENT_INFO_FTP_USER:
            LogMessage ("    %s->type: %u (EVENT_INFO_FTP_USER)\n", source, type);
            str = (char *)(U2ExtraData+1);
            len = (int) (ntohl(U2ExtraData->blob_length) - sizeof(U2ExtraData->data_type) - sizeof(U2ExtraData->blob_length));
            LogMessage("    %s->ftp_user: %s\n", source, str);
            break;
        case EVENT_INFO_SMB_UID:
            LogMessage ("    %s->type: %u (EVENT_INFO_SMB_UID)\n", source, type);
            smb_uid = ntohs(*(uint16_t *)(U2ExtraData+1));
            len = (int) (ntohl(U2ExtraData->blob_length) - sizeof(U2ExtraData->data_type) - sizeof(U2ExtraData->blob_length));
            LogMessage ("    %s->smb_uid: %u", source, smb_uid);
            break;
        case EVENT_INFO_SMB_IS_UPLOAD:
            LogMessage ("    %s->type: %u (EVENT_INFO_SMB_IS_UPLOAD)\n", source, type);
            smb_uid = ntohs(*(uint16_t *)(U2ExtraData+1));
            len = (int) (ntohl(U2ExtraData->blob_length) - sizeof(U2ExtraData->data_type) - sizeof(U2ExtraData->blob_length));
            if (smb_uid == 0)
                LogMessage ("    %s->smb_upload: false", source);
            else
                LogMessage ("    %s->smb_upload: true", source);
            break;
        default:
            break;
    }
}

static void spoolerPrintRecordPacket(Spooler *spooler)
{
    uint32_t type;
    uint32_t event_id = -1;
    EventRecordNode *ern;

    if (spooler->record.header != NULL)
    {
        type = ntohl(((Unified2RecordHeader *)spooler->record.header)->type);
        if (type == UNIFIED2_PACKET)
            LogMessage ("  spooler->record.header->type = %u (UNIFIED2_PACKET)\n", type);
    }
    else
        LogMessage ("  spooler->record.header is NULL\n");

    if (type == UNIFIED2_PACKET)
    {
        if (spooler->record.data != NULL)
        {
            event_id = ntohl(((Unified2EventCommon *)spooler->record.data)->event_id);
            LogMessage ("  spooler->record.data->event_id = %u\n", event_id);
        }
        else
            LogMessage ("  spooler->record.data is NULL\n");

        /* Packets are never allocated in spooler->record.pkt
        if (spooler->record.pkt != NULL)
        {
            LogMessage ("  (0x%x) ern->data->packet: (0x%x) [",
                spooler->record.pkt, &(spooler->record.pkt->data[0]));
            uint16_t i;
            uint16_t max = 16; // packet payload bytes to print
            max = spooler->record.pkt->dsize>max?max:spooler->record.pkt->dsize;
            if(spooler->record.pkt && spooler->record.pkt->dsize>0){
                for(i=0;i<max;++i)
                    LogMessage ("%x",spooler->record.pkt->data[i]);
            }else{
                LogMessage ("NULL");
            }
            LogMessage ("]\n");
        }
        else
            LogMessage ("  spooler->record.pkt is NULL\n");
        //*/

        if (event_id > 0)
        {
            ern = spoolerEventCacheGetByEventID(spooler, event_id);
            spoolerPrintERNPacket(ern);
        }
    }
}

static void spoolerPrintERNPacket(EventRecordNode *ern)
{
    Packet *p = NULL;

    if (ern != NULL)
    {
        if (ern->data != NULL)
        {
            switch (ern->type)
            {
                case UNIFIED2_IDS_EVENT:
                    p = (Packet *) ((Unified2IDSEvent_legacy_WithPED *)ern->data)->packet;
                    break;
                case UNIFIED2_IDS_EVENT_MPLS:
                case UNIFIED2_IDS_EVENT_VLAN:
                    p = (Packet *) ((Unified2IDSEvent_WithPED *)ern->data)->packet;
                    break;
                case UNIFIED2_IDS_EVENT_IPV6:
                    p = (Packet *) ((Unified2IDSEventIPv6_legacy_WithPED *)ern->data)->packet;
                    break;
                case UNIFIED2_IDS_EVENT_IPV6_MPLS:
                case UNIFIED2_IDS_EVENT_IPV6_VLAN:
                    p = (Packet *) ((Unified2IDSEventIPv6_WithPED *)ern->data)->packet;
                    break;
                default:
                    p = NULL;
                    break;
            }

            if (p != NULL)
            {
                LogMessage ("  (0x%x) ern->data->packet: (0x%x) [", p, &(p->data[0]));
                uint16_t i;
                uint16_t max = 16; // packet payload bytes to print
                max = p->dsize>max?max:p->dsize;
                if(p && p->dsize>0){
                    for(i=0;i<max;++i)
                        LogMessage ("%x",p->data[i]);
                }else{
                    LogMessage ("NULL");
                }
                LogMessage ("]\n");
            }
            else
                LogMessage ("  ern->data->packet is NULL\n");
        }
        else
            LogMessage ("  ern->data is NULL\n");

        //LogMessage("  ern->used = %u\n", ern->used);
    }
    else
        LogMessage ("  ern is NULL\n");
}
#endif