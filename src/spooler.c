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
        else
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
        /* convert event id once */
        uint32_t event_id = ntohl(((Unified2Packet *)spooler->record.data)->event_id);

        /* check if there is a previously cached event that matches this event id */
        ernCache = spoolerEventCacheGetByEventID(spooler, event_id);

#ifdef RB_EXTRADATA
        datalink = ntohl(((Unified2Packet *)spooler->record.data)->linktype);

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
#else
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
edrc = &(((Unified2IDSEvent_WithPED *)(ern->data)))->extra_data_cache;
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
                LogMessage("WARNING: spoolerExtraDataCachePush(): type inconsistent (%d)\n", ern->type);
                break;
        }

    TAILQ_INSERT_HEAD(edrc, edrnNode, entry);
    //((Unified2IDSEvent_WithExtra *)data)->extra_data_cached++;
    //DEBUG_WRAP(DebugMessage(DEBUG_SPOOLER,"Cached extra data record: %d\n", ((Unified2IDSEvent_WithExtra *)data)->extra_data_cached););

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
    void *packet = NULL;

    if (ern == NULL)
    {
        LogMessage("WARNING: spoolerExtraDataCacheClean(): ern is NULL\n");
        return 1;
    }

    switch (ern->type)
    {
        case UNIFIED2_IDS_EVENT:
            edrc = &((Unified2IDSEvent_legacy_WithPED *)(ern->data))->extra_data_cache;
            packet = (((Unified2IDSEvent_legacy_WithPED *)(ern->data))->packet);
            break;
        case UNIFIED2_IDS_EVENT_MPLS:
        case UNIFIED2_IDS_EVENT_VLAN:
            edrc = &((Unified2IDSEvent_WithPED *)(ern->data))->extra_data_cache;
            packet = ((Unified2IDSEvent_WithPED *)(ern->data))->packet;
            break;
        case UNIFIED2_IDS_EVENT_IPV6:
            edrc = &((Unified2IDSEventIPv6_legacy_WithPED *)(ern->data))->extra_data_cache;
            packet = ((Unified2IDSEventIPv6_legacy_WithPED *)(ern->data))->packet;
            break;
        case UNIFIED2_IDS_EVENT_IPV6_MPLS:
        case UNIFIED2_IDS_EVENT_IPV6_VLAN:
            edrc = &((Unified2IDSEventIPv6_WithPED *)(ern->data))->extra_data_cache;
            packet = ((Unified2IDSEventIPv6_WithPED *)(ern->data))->packet;
            break;
        case UNIFIED2_PACKET:
        case UNIFIED2_EXTRA_DATA:
            break;
        default:
            LogMessage("WARNING: spoolerExtraDataCacheClean(): type inconsistent (%d)\n", ern->type);
            break;
    }

    if (packet)
    {
        free(packet);
        packet = NULL;
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
#endif
