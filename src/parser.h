/*             
** Copyright (C) 2002-2009 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 2000-2001 Andrew R. Baker <andrewb@uab.edu>
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
#ifndef __PARSER_H__
#define __PARSER_H__

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#include "rules.h"
#include "decode.h"
#include "barnyard2.h"
#include "util.h"

/* Macros *********************************************************************/
#define BARNYARD2_CONF_KEYWORD__CONFIG               "config"
#define BARNYARD2_CONF_KEYWORD__INPUT                "input"
#define BARNYARD2_CONF_KEYWORD__OUTPUT               "output"
#define BARNYARD2_CONF_KEYWORD__IPVAR                "ipvar"
#define BARNYARD2_CONF_KEYWORD__VAR                  "var"
#define BARNYARD2_CONF_KEYWORD__VERSION              "version"

/* Config options */
#define CONFIG_OPT__DISABLE_ALERT_ON_EACH_PACKET_IN_STREAM  "disable_alert_on_each_packet_in_stream"
#define CONFIG_OPT__EVENT_CACHE_SIZE                "event_cache_size"
#define CONFIG_OPT__ALERT_ON_EACH_PACKET_IN_STREAM  "alert_on_each_packet_in_stream"
#define CONFIG_OPT__ALERT_WITH_IFACE_NAME           "alert_with_interface_name"
#define CONFIG_OPT__ARCHIVE_DIR                     "archivedir"
#define CONFIG_OPT__CHROOT_DIR                      "chroot"
#define CONFIG_OPT__CLASSIFICATION                  "classification"
#define CONFIG_OPT__CLASSIFICATION_FILE             "classification_file"
#define CONFIG_OPT__DAEMON                          "daemon"
#define CONFIG_OPT__DECODE_DATA_LINK                "decode_data_link"
#define CONFIG_OPT__DUMP_CHARS_ONLY                 "dump_chars_only"
#define CONFIG_OPT__DUMP_PAYLOAD                    "dump_payload"
#define CONFIG_OPT__DUMP_PAYLOAD_VERBOSE            "dump_payload_verbose"
#define CONFIG_OPT__GEN_FILE                        "gen_file"
#define CONFIG_OPT__HOSTNAME                        "hostname"
#define CONFIG_OPT__INTERFACE                       "interface"
#define CONFIG_OPT__LOG_DIR                         "logdir"
#define CONFIG_OPT__OBFUSCATE                       "obfuscate"
#define CONFIG_OPT__PID_PATH                        "pidpath"
#define CONFIG_OPT__PROCESS_NEW_RECORDS_ONLY        "process_new_records_only"
#define CONFIG_OPT__QUIET                           "quiet"
#define CONFIG_OPT__REFERENCE                       "reference"
#define CONFIG_OPT__REFERENCE_FILE                  "reference_file"
#define CONFIG_OPT__REFERENCE_NET                   "reference_net"
#define CONFIG_OPT__SET_GID                         "set_gid"
#define CONFIG_OPT__SET_UID                         "set_uid"
#define CONFIG_OPT__SHOW_YEAR                       "show_year"
#define CONFIG_OPT__SID_FILE                        "sid_file"
#define CONFIG_OPT__STATEFUL                        "stateful"
#define CONFIG_OPT__UMASK                           "umask"
#define CONFIG_OPT__UTC                             "utc"
#define CONFIG_OPT__VERBOSE                         "verbose"
#define CONFIG_OPT__WALDO_FILE                      "waldo_file"
#define CONFIG_OPT__SIGSUPPRESS                     "sig_suppress"
#ifdef MPLS
# define CONFIG_OPT__MAX_MPLS_LABELCHAIN_LEN        "max_mpls_labelchain_len"
# define CONFIG_OPT__MPLS_PAYLOAD_TYPE              "mpls_payload_type"
#endif  /* MPLS */



/* exported values */
extern char *file_name;
extern int file_line;

/* rule setup funcs */
Barnyard2Config * ParseBarnyard2Conf(void);

void ParseInput(Barnyard2Config *, char *);
void ParseOutput(Barnyard2Config *, char *);
void OrderRuleLists(Barnyard2Config *, char *);

char * VarGet(char *);
char * ProcessFileOption(Barnyard2Config *, const char *);
void SetRuleStates(Barnyard2Config *);

void ParserCleanup(void);
void FreeRuleLists(Barnyard2Config *);
void VarTablesFree(Barnyard2Config *);

void ResolveOutputPlugins(Barnyard2Config *, Barnyard2Config *);
void ConfigureInputPlugins(Barnyard2Config *);
void ConfigureOutputPlugins(Barnyard2Config *);

NORETURN void ParseError(const char *, ...);
void ParseMessage(const char *, ...);

void ConfigDisableAlertOnEachPacketInStream(Barnyard2Config *, char *);
void ConfigAlertOnEachPacketInStream(Barnyard2Config *, char *);
void ConfigAlertWithInterfaceName(Barnyard2Config *, char *);
void ConfigArchiveDir(Barnyard2Config *, char *);
void ConfigChrootDir(Barnyard2Config *, char *);
void ConfigClassification(Barnyard2Config *, char *);
void ConfigClassificationFile(Barnyard2Config *, char *);
void ConfigCreatePidFile(Barnyard2Config *, char *);
void ConfigDaemon(Barnyard2Config *, char *);
void ConfigDecodeDataLink(Barnyard2Config *, char *);
void ConfigDumpCharsOnly(Barnyard2Config *, char *);
void ConfigDumpPayload(Barnyard2Config *, char *);
void ConfigDumpPayloadVerbose(Barnyard2Config *, char *);
void ConfigGenFile(Barnyard2Config *, char *);
void ConfigHostname(Barnyard2Config *, char *);
void ConfigInterface(Barnyard2Config *, char *);
void ConfigLogDir(Barnyard2Config *, char *);
void ConfigNoLoggingTimestamps(Barnyard2Config *, char *);
void ConfigObfuscate(Barnyard2Config *, char *);
void ConfigObfuscationMask(Barnyard2Config *, char *);
void ConfigPidPath(Barnyard2Config *, char *);
void ConfigProcessNewRecordsOnly(Barnyard2Config *, char *);
void ConfigQuiet(Barnyard2Config *, char *);
void ConfigReference(Barnyard2Config *, char *);
void ConfigReferenceFile(Barnyard2Config *, char *);
void ConfigReferenceNet(Barnyard2Config *, char *);
void ConfigSetGid(Barnyard2Config *, char *);
void ConfigSetUid(Barnyard2Config *, char *);
void ConfigSidFile(Barnyard2Config *, char *);
void ConfigShowYear(Barnyard2Config *, char *);
void ConfigStateful(Barnyard2Config *, char *);
void ConfigSpoolFilebase(Barnyard2Config *, char *);
void ConfigSpoolDirectory(Barnyard2Config *, char *);
void ConfigUmask(Barnyard2Config *, char *);
void ConfigUtc(Barnyard2Config *, char *);
void ConfigVerbose(Barnyard2Config *, char *);
void ConfigWaldoFile(Barnyard2Config *, char *);
void ConfigSetEventCacheSize(Barnyard2Config *, char *);
#ifdef MPLS
void ConfigMaxMplsLabelChain(Barnyard2Config *, char *);
void ConfigMplsPayloadType(Barnyard2Config *, char *);
#endif
void ConfigSigSuppress(Barnyard2Config *, char *);
void DisplaySigSuppress(SigSuppress_list **);


// use this so mSplit doesn't split IP lists (try c = ';')
char* FixSeparators (char* rule, char c, const char* err);

// use this as an alternative to mSplit when you just want name, value
void GetNameValue (char* arg, char** nam, char** val, const char* err);

#endif /* __PARSER_H__ */

