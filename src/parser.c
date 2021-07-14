/* $Id$ */
/*
** Copyright (C) 2002-2009 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 2000,2001 Andrew R. Baker <andrewb@uab.edu>
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <stdarg.h>

#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif

#ifndef WIN32
# include <netdb.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <grp.h>
# include <pwd.h>
# include <fnmatch.h>
#endif /* !WIN32 */

#include "bounds.h"
#include "rules.h"
#include "parser.h"
#include "plugbase.h"
#include "debug.h"
#include "util.h"
#include "mstring.h"
#include "log.h"
#include "generators.h"
#include "strlcatu.h"
#include "strlcpyu.h"
#include "barnyard2.h"
#include "sf_vartable.h"
#include "ipv6_port.h"
#include "sfutil/sf_ip.h"

#ifdef TARGET_BASED
# include "sftarget_reader.h"
#endif

#ifdef PORTLISTS
# include "sfutil/sfrim.h"
# include "sfutil/sfportobject.h"
#endif
 
/* MPLS payload types */
#ifdef MPLS
# define MPLS_PAYLOAD_OPT__IPV4      "ipv4"
# define MPLS_PAYLOAD_OPT__IPV6      "ipv6"
# define MPLS_PAYLOAD_OPT__ETHERNET  "ethernet"
#endif

/* Macros *********************************************************************/
#define MAX_RULE_OPTIONS     256
#define MAX_LINE_LENGTH    32768
#define MAX_IPLIST_ENTRIES  4096 
#define DEFAULT_LARGE_RULE_GROUP 9
#define SF_IPPROTO_UNKNOWN -1
#define MAX_RULE_COUNT (65535 * 2)

/* For user defined rule type */
#define RULE_TYPE_OPT__TYPE    "type"

#define ERR_PAIR_COUNT \
    "%s has incorrect argument count; should be %d pairs.", ERR_KEY
#define ERR_NOT_PAIRED \
    "%s is missing an option or argument to go with: %s.", ERR_KEY, pairs[0]
#define ERR_EXTRA_OPTION \
    "%s has extra option of type: %s.", ERR_KEY, pairs[0]
#define ERR_BAD_OPTION \
    "%s has unknown option: %s.", ERR_KEY, pairs[0]
#define ERR_BAD_VALUE \
    "%s has unknown %s: %s.", ERR_KEY, pairs[0], pairs[1]
#define ERR_BAD_ARG_COUNT \
    "%s has incorrect argument count.", ERR_KEY
#define ERR_CREATE \
    "%s could not be created.", ERR_KEY
#define ERR_CREATE_EX \
    "%s could not be created: %s.", ERR_KEY

// arbitrary conf file name used to allow initialization w/o conf
// (required for packet logging mode)
#define NULL_CONF "null"

/* Data types *****************************************************************/
typedef void (*ParseFunc)(Barnyard2Config *, char *);
typedef void (*ParseConfigFunc)(Barnyard2Config *, char *);

/* Used to determine whether or not to parse the keyword line based on
 * whether or not we're parsing rules */
typedef enum _KeywordType
{
    KEYWORD_TYPE__MAIN,
    KEYWORD_TYPE__RULE,
    KEYWORD_TYPE__ALL

} KeywordType;

typedef enum _VarType
{
    VAR_TYPE__DEFAULT,
    VAR_TYPE__PORTVAR,
    VAR_TYPE__IPVAR

} VarType;

typedef struct _KeywordFunc
{
    char *name              __attribute__((aligned(8)));
    KeywordType type        __attribute__((aligned(8)));
    int expand_vars         __attribute__((aligned(8)));
    ParseFunc parse_func    __attribute__((aligned(8)));

} KeywordFunc;

typedef struct _ConfigFunc
{
    char *name                    __attribute__((aligned(8)));
    int args_required             __attribute__((aligned(8)));
    int only_once                 __attribute__((aligned(8)));
    ParseConfigFunc parse_func    __attribute__((aligned(8)));

} ConfigFunc;

/* Externs ********************************************************************/
extern VarNode *cmd_line_var_list;
extern char *barnyard2_conf_file;
extern char *barnyard2_conf_dir;

/* Globals ********************************************************************/

/* Set to the current barnyard2 config we're parsing.  Mostly used for the
 * plugins (input and output) since the callbacks don't pass a barnyard2
 * configuration */
Barnyard2Config *barnyard2_conf_for_parsing = NULL;

char *file_name = NULL;   /* current config file being processed */
int file_line = 0;        /* current line being processed in the file */

/* Main parsing function uses this to indicate whether or not
 * rules are to be parsed. */
static int parse_rules = 0;

static void ParseConfig(Barnyard2Config *, char *);
static void ParseIpVar(Barnyard2Config *, char *);
static void ParseVar(Barnyard2Config *, char *);
static void AddVarToTable(Barnyard2Config *, char *, char *);

static const KeywordFunc barnyard2_conf_keywords[] =
{
    /* Non-rule keywords */
    { BARNYARD2_CONF_KEYWORD__VAR,               KEYWORD_TYPE__MAIN, 0, ParseVar },
    { BARNYARD2_CONF_KEYWORD__CONFIG,            KEYWORD_TYPE__MAIN, 1, ParseConfig },
    { BARNYARD2_CONF_KEYWORD__IPVAR,             KEYWORD_TYPE__MAIN, 0, ParseIpVar },
    { BARNYARD2_CONF_KEYWORD__INPUT,             KEYWORD_TYPE__MAIN, 1, ParseInput },
    { BARNYARD2_CONF_KEYWORD__OUTPUT,            KEYWORD_TYPE__MAIN, 1, ParseOutput },
    { NULL, 0, 0, NULL }   /* Marks end of array */
};

static const ConfigFunc config_opts[] =
{
    { CONFIG_OPT__DISABLE_ALERT_ON_EACH_PACKET_IN_STREAM, 0, 1, ConfigDisableAlertOnEachPacketInStream },
    { CONFIG_OPT__EVENT_CACHE_SIZE, 0, 1, ConfigSetEventCacheSize },
    { CONFIG_OPT__ALERT_ON_EACH_PACKET_IN_STREAM, 0, 1, ConfigAlertOnEachPacketInStream },
    { CONFIG_OPT__ALERT_WITH_IFACE_NAME, 0, 1, ConfigAlertWithInterfaceName },
    { CONFIG_OPT__ARCHIVE_DIR, 1, 1, ConfigArchiveDir },
    { CONFIG_OPT__CHROOT_DIR, 1, 1, ConfigChrootDir },
    { CONFIG_OPT__CLASSIFICATION, 1, 0, ConfigClassification },
    { CONFIG_OPT__CLASSIFICATION_FILE, 1, 0, ConfigClassificationFile },
    { CONFIG_OPT__DAEMON, 0, 1, ConfigDaemon },
    { CONFIG_OPT__DECODE_DATA_LINK, 0, 1, ConfigDecodeDataLink },
    { CONFIG_OPT__DUMP_CHARS_ONLY, 0, 1, ConfigDumpCharsOnly },
    { CONFIG_OPT__DUMP_PAYLOAD, 0, 1, ConfigDumpPayload },
    { CONFIG_OPT__DUMP_PAYLOAD_VERBOSE, 0, 1, ConfigDumpPayloadVerbose },
    { CONFIG_OPT__GEN_FILE, 1, 0, ConfigGenFile },
    { CONFIG_OPT__HOSTNAME, 1, 0, ConfigHostname },
    { CONFIG_OPT__INTERFACE, 1, 1, ConfigInterface },
    { CONFIG_OPT__LOG_DIR, 1, 1, ConfigLogDir },
    { CONFIG_OPT__OBFUSCATE, 0, 1, ConfigObfuscate },
    { CONFIG_OPT__SIGSUPPRESS,0,0,ConfigSigSuppress},
    /* XXX We can configure this on the command line - why not in config file ??? */
#ifdef NOT_UNTIL_WE_DAEMONIZE_AFTER_READING_CONFFILE
    { CONFIG_OPT__PID_PATH, 1, 1, ConfigPidPath },
#endif
    { CONFIG_OPT__PROCESS_NEW_RECORDS_ONLY, 0, 1, ConfigProcessNewRecordsOnly },
    { CONFIG_OPT__QUIET, 0, 1, ConfigQuiet },
    { CONFIG_OPT__REFERENCE, 1, 0, ConfigReference },
    { CONFIG_OPT__REFERENCE_FILE, 1, 0, ConfigReferenceFile },
    { CONFIG_OPT__REFERENCE_NET, 1, 1, ConfigReferenceNet },
    { CONFIG_OPT__SET_GID, 1, 1, ConfigSetGid },
    { CONFIG_OPT__SET_UID, 1, 1, ConfigSetUid },
    { CONFIG_OPT__SID_FILE, 1, 0, ConfigSidFile },
    { CONFIG_OPT__SHOW_YEAR, 0, 1, ConfigShowYear },
    { CONFIG_OPT__UMASK, 1, 1, ConfigUmask },
    { CONFIG_OPT__UTC, 0, 1, ConfigUtc },
    { CONFIG_OPT__VERBOSE, 0, 1, ConfigVerbose },
    { CONFIG_OPT__WALDO_FILE, 1, 0, ConfigWaldoFile },
#ifdef MPLS
    { CONFIG_OPT__MAX_MPLS_LABELCHAIN_LEN, 0, 1, ConfigMaxMplsLabelChain },
    { CONFIG_OPT__MPLS_PAYLOAD_TYPE, 0, 1, ConfigMplsPayloadType },
#endif
    { NULL, 0, 0, NULL }   /* Marks end of array */
};

/* Used to determine if a config option has already been configured
 * Gets zeroed when initially parsing a configuration file, then each 
 * index gets set to 1 as an option is configured.  Maps to config_opts */
static uint8_t config_opt_configured[sizeof(config_opts) / sizeof(ConfigFunc)];


/* Private function prototypes ************************************************/
static void InitVarTables(Barnyard2Config *);
static void InitParser(void);
#ifdef SUP_IP6
static int VarIsIpAddr(vartable_t *, char *);
#endif
static void ParseConfigFile(Barnyard2Config *, char *);
static int ContinuationCheck(char *);
static VarEntry * VarDefine(Barnyard2Config *, char *, char *);
static char * VarSearch(Barnyard2Config *, char *);
static char * ExpandVars(Barnyard2Config *, char *);
static VarEntry * VarAlloc(void);
static void DeleteVars(VarEntry *);
static void TransferOutputConfigs(OutputConfig *, OutputConfig **);
static OutputConfig * DupOutputConfig(OutputConfig *);
static void RemoveOutputConfigs(OutputConfig **, int);

static void DisallowCrossTableDuplicateVars(Barnyard2Config *, char *, VarType);

/****************************************************************************
 * Function: ParseSnortConf()
 *
 * Read the rules file a line at a time and send each rule to the rule parser
 * This is the first pass of the configuration file.  It parses everything
 * except the rules.
 *
 * Arguments: None
 *
 * Returns:
 *  Barnyard2Config *
 *      An initialized and configured snort configuration struct.
 *      This struct should be passed on the second pass of the
 *      configuration file to parse the rules.
 *
 ***************************************************************************/
Barnyard2Config * ParseBarnyard2Conf(void)
{
    Barnyard2Config *bc = Barnyard2ConfNew();
    VarNode *tmp = cmd_line_var_list;

    file_line = 0;
    file_name = barnyard2_conf_file ? barnyard2_conf_file : NULL_CONF;

    /* Need to set this for plugin configurations since they're using
     * lists of callbacks */
    barnyard2_conf_for_parsing = bc;
    

    InitParser();

    /* By default */
    bc->alert_on_each_packet_in_stream_flag=1;

    /* We're not going to parse rules on the first pass */
    parse_rules = 0;

    InitVarTables(bc);

    /* Add command line defined variables - duplicates will already
     * have been resolved */
    while (tmp != NULL)
    {
        AddVarToTable(bc, tmp->name, tmp->value);
        tmp = tmp->next;
    }

    if ( strcmp(file_name, NULL_CONF) )
        ParseConfigFile(bc, file_name);

    /* Add command line defined variables - duplicates will already
     * have been resolved */
    tmp = cmd_line_var_list;
    while (tmp != NULL)
    {
        AddVarToTable(bc, tmp->name, tmp->value);
        tmp = tmp->next;
    }

    /* Make sure this gets set back to NULL when we're done parsing */
    barnyard2_conf_for_parsing = NULL;

    /* Reset these.  The only issue in not reseting would be if we were
     * parsing a command line again, but do it anyway */
    file_name = NULL;
    file_line = 0;

    return bc;
}

void ParseInput(Barnyard2Config *bc, char *args)
{
    char **toks;
    int num_toks;
    char *opts = NULL;
    InputConfig *config;

    toks = mSplit(args, ":", 2, &num_toks, '\\');

    if (num_toks > 1)
        opts = toks[1];

    config = (InputConfig *)SnortAlloc(sizeof(InputConfig));

    if (bc->input_configs == NULL)
    {
        bc->input_configs = config;
    }
    else
    {
        InputConfig *tmp = bc->input_configs;

        while (tmp->next != NULL)
            tmp = tmp->next;

        tmp->next = config;
    }

    config->keyword = SnortStrdup(toks[0]);
    if (opts != NULL)
        config->opts = SnortStrdup(opts);

    /* This could come from parsing the command line */
    if (file_name != NULL)
    {
        config->file_name = SnortStrdup(file_name);
        config->file_line = file_line;
    }

    mSplitFree(&toks, num_toks);
}

void ConfigureInputPlugins(Barnyard2Config *bc)
{
    InputConfig *config;
    char *stored_file_name = file_name;
    int stored_file_line = file_line;

    barnyard2_conf_for_parsing = bc;

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Input Plugin\n"););

    for (config = bc->input_configs; config != NULL; config = config->next)
    {
        InputConfigFunc func;

        file_name = config->file_name;
        file_line = config->file_line;

        func = GetInputConfigFunc(config->keyword);
        if (func == NULL)
            ParseError("Unknown input plugin: \"%s\"", config->keyword);

        func(config->opts);
    }

    /* Reset these since we're done with configuring dynamic preprocessors */
    file_name = stored_file_name;
    file_line = stored_file_line;

    barnyard2_conf_for_parsing = NULL;
}

void ParseOutput(Barnyard2Config *bc, char *args)
{
    char **toks;
    int num_toks;
    char *opts = NULL;
    OutputConfig *config;

    toks = mSplit(args, ":", 2, &num_toks, '\\');

    if (num_toks > 1)
        opts = toks[1];

    config = (OutputConfig *)SnortAlloc(sizeof(OutputConfig));

    if (bc->output_configs == NULL)
    {
        bc->output_configs = config;
    }
    else
    {
        OutputConfig *tmp = bc->output_configs;

        while (tmp->next != NULL)
            tmp = tmp->next;

        tmp->next = config;
    }

    config->keyword = SnortStrdup(toks[0]);
    if (opts != NULL)
        config->opts = SnortStrdup(opts);

    /* This could come from parsing the command line */
    if (file_name != NULL)
    {
        config->file_name = SnortStrdup(file_name);
        config->file_line = file_line;
    }

    mSplitFree(&toks, num_toks);
}

static void TransferOutputConfigs(OutputConfig *from_list, OutputConfig **to_list)
{
    if ((from_list == NULL) || (to_list == NULL))
        return;

    for (; from_list != NULL; from_list = from_list->next)
    {
        if (*to_list == NULL)
        {
            *to_list = DupOutputConfig(from_list);
        }
        else
        {
            OutputConfig *tmp = DupOutputConfig(from_list);

            if (tmp != NULL)
            {
                tmp->next = *to_list;
                *to_list = tmp;
            }
        }
    }
}

static OutputConfig * DupOutputConfig(OutputConfig *dupme)
{
    OutputConfig *medup;

    if (dupme == NULL)
        return NULL;

    medup = (OutputConfig *)SnortAlloc(sizeof(OutputConfig));

    if (dupme->keyword != NULL)
        medup->keyword = SnortStrdup(dupme->keyword);

    if (dupme->opts != NULL)
        medup->opts = SnortStrdup(dupme->opts);

    if (dupme->file_name != NULL)
        medup->file_name = SnortStrdup(dupme->file_name);

    medup->file_line = dupme->file_line;

    return medup;
}

static void RemoveOutputConfigs(OutputConfig **head, int remove_flags)
{
    OutputConfig *config;
    OutputConfig *last = NULL;

    if (head == NULL)
        return;

    config = *head;

    while (config != NULL)
    {
        int type_flags = GetOutputTypeFlags(config->keyword);

        if (type_flags & remove_flags)
        {
            OutputConfig *tmp = config;

            config = config->next;

            if (last == NULL)
                *head = config;
            else
                last->next = config;

            free(tmp->keyword);

            if (tmp->opts != NULL)
                free(tmp->opts);

            if (tmp->file_name != NULL)
                free(tmp->file_name);

            free(tmp);
        }
        else
        {
            last = config;
            config = config->next;
        }
    }
}

void ResolveOutputPlugins(Barnyard2Config *cmd_line, Barnyard2Config *config_file)
{
    int cmd_line_type_flags = 0;

    if (cmd_line == NULL)
        return;

    /* Command line overrides configuration file output */
    if (cmd_line->output_configs != NULL)
    {
        OutputConfig *config = cmd_line->output_configs;

        for (; config != NULL; config = config->next)
        {
            int type_flags = GetOutputTypeFlags(config->keyword);

            cmd_line_type_flags |= type_flags;

            if (config_file != NULL)
            {
                RemoveOutputConfigs(&config_file->output_configs, type_flags);
            }
        }

        /* Put what's in the command line output into the config file output */
        if (config_file != NULL)
            TransferOutputConfigs(cmd_line->output_configs, &config_file->output_configs);
    }

    /* Don't try to configure defaults if running in test mode */
    if (!BcTestMode())
    {
        if (config_file == NULL)
        {
            if (!(cmd_line_type_flags & OUTPUT_TYPE__LOG))
                ParseOutput(cmd_line, "log_tcpdump");

            if (!(cmd_line_type_flags & OUTPUT_TYPE__ALERT))
                ParseOutput(cmd_line, "alert_full");
        }
        else
        {
            int config_file_type_flags = 0;
            OutputConfig *config = config_file->output_configs;

            for (; config != NULL; config = config->next)
                config_file_type_flags |= GetOutputTypeFlags(config->keyword);

//            if (!(config_file_type_flags & OUTPUT_TYPE__LOG))
//                ParseOutput(config_file, "log_tcpdump");

//            if (!(config_file_type_flags & OUTPUT_TYPE__ALERT))
//                ParseOutput(config_file, "alert_full");
        }
    }
}

void ConfigureOutputPlugins(Barnyard2Config *bc)
{
    OutputConfig *config;
    char *stored_file_name = file_name;
    int stored_file_line = file_line;

    barnyard2_conf_for_parsing = bc;

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Output Plugin\n"););

    for (config = bc->output_configs; config != NULL; config = config->next)
    {
        OutputConfigFunc func;

        file_name = config->file_name;
        file_line = config->file_line;

        func = GetOutputConfigFunc(config->keyword);
        if (func == NULL)
            ParseError("Unknown output plugin: \"%s\"", config->keyword);

        func(config->opts);
    }

    /* Reset these since we're done with configuring dynamic preprocessors */
    file_name = stored_file_name;
    file_line = stored_file_line;

    barnyard2_conf_for_parsing = NULL;
}

/****************************************************************************
 *
 * Function: VarAlloc()
 *
 * Purpose: allocates memory for a variable
 *
 * Arguments: none
 *
 * Returns: pointer to new VarEntry
 *
 ***************************************************************************/
VarEntry *VarAlloc()
{
    VarEntry *new;

    new = (VarEntry *)SnortAlloc(sizeof(VarEntry));

    return(new);
}

#ifdef SUP_IP6
/****************************************************************************
 *
 * Function: VarIsIpAddr(char *, char *)
 *
 * Purpose: Checks if a var is an IP address. Necessary since moving forward
 *          we want all IP addresses handled by the IP variable table.
 *          If a list is given, this checks each value.
 *
 * Arguments: value => the string to check
 *
 * Returns: 1 if IP address, 0 otherwise
 *
 ***************************************************************************/
static int VarIsIpAddr(vartable_t *ip_vartable, char *value)
{
    char *tmp;
   
    /* empty list, consider this an IP address */
    if ((*value == '[') && (*(value+1) == ']'))
        return 1;

    while(*value == '!' || *value == '[') value++;

    /* Check for dotted-quad */
    if( isdigit((int)*value) &&
         ((tmp = strchr(value, (int)'.')) != NULL) && 
         ((tmp = strchr(tmp+1, (int)'.')) != NULL) &&
         (strchr(tmp+1, (int)'.') != NULL))
        return 1; 

    /* IPv4 with a mask, and fewer than 4 fields */
    else if( isdigit((int)*value) &&
         (strchr(value+1, (int)':') == NULL) &&
         ((tmp = strchr(value+1, (int)'/')) != NULL) &&
         isdigit((int)(*(tmp+1))) )
        return 1;

    /* IPv6 */
    else if((tmp = strchr(value, (int)':')) != NULL) 
    {
        char *tmp2;

        if((tmp2 = strchr(tmp+1, (int)':')) == NULL) 
            return 0;

        for(tmp++; tmp < tmp2; tmp++)
            if(!isxdigit((int)*tmp)) 
                return 0;

        return 1;
    }

    /* Check if it's a variable containing an IP */
    else if(sfvt_lookup_var(ip_vartable, value+1) || sfvt_lookup_var(ip_vartable, value))
        return 1;

    return 0;
}

/****************************************************************************
 * 
 * Function: CheckBrackets(char *)
 *
 * Purpose: Check that the brackets match up in a string that
 *          represents a list.
 *
 * Arguments: value => the string to check
 *
 * Returns: 1 if the brackets match correctly, 0 otherwise
 *
 ***************************************************************************/
static int CheckBrackets(char *value)
{
    int num_brackets = 0;

    while (*value == '!')
        value++;

    if ((value[0] != '[') || value[strlen(value)-1] != ']')
    {
        /* List does not begin or end with a bracket. */
        return 0;
    }

    while ((*value != '\0') && (num_brackets >= 0))
    {
        if (*value == '[')
            num_brackets++;
        else if (*value == ']')
            num_brackets--;
        value++;
    }
    if (num_brackets != 0)
    {
        /* Mismatched brackets */
        return 0;
    }

    return 1;
}

/****************************************************************************
 *
 * Function: VarIsIpList(vartable_t *, char*)
 *
 * Purpose: Checks if a var is a list of IP addresses.
 *
 * Arguments: value => the string to check
 *
 * Returns: 1 if each item is an IP address, 0 otherwise
 *
 ***************************************************************************/
static int VarIsIpList(vartable_t *ip_vartable, char *value)
{
    char *copy, *item;
    int item_is_ip = 1;

    copy = SnortStrdup((const char*)value);

    /* Ensure that the brackets are correct. */
    if (strchr((const char*)copy, ','))
    {
        /* This is a list! */
        if (CheckBrackets(copy) == 0)
        {
            free(copy);
            return 0;
        }
    }

    /* There's no need to worry about the list structure here.
     * We just strip out the IP delimiters and process each one. */
    item = strtok(copy, "[],!");
    while ((item != NULL) && item_is_ip)
    {
        item_is_ip = VarIsIpAddr(ip_vartable, item);
        item = strtok(NULL, "[],!");
    }

    free(copy);
    return item_is_ip;
}
#endif

/****************************************************************************
 *
 * Function: DisallowCrossTableDuplicateVars(char *, int) 
 *
 * Purpose: FatalErrors if the a variable name is redefined across variable 
 *          types.  Enforcing this mutual exclusion prevents the
 *          catatrophe where the variable lookup fall-through (see VarSearch)
 *          finds an unintended variable from the wrong table.  Note:  VarSearch
 *          is only necessary for ExpandVars. 
 *
 * Arguments: name => The name of the variable
 *            var_type => The type of the variable that is about to be defined.
 *                        The corresponding variable table will not be searched.
 *
 * Returns: void function
 *
 ***************************************************************************/
static void DisallowCrossTableDuplicateVars(Barnyard2Config *bc, char *name, VarType var_type) 
{
#ifdef SUP_IP6
    VarEntry            *var_table = bc->var_table;
    vartable_t          *ip_vartable = bc->ip_vartable;
    VarEntry            *p = var_table;
#endif


    switch (var_type) 
    {
        case VAR_TYPE__DEFAULT:
            if(
#ifdef SUP_IP6
               sfvt_lookup_var(ip_vartable, name) ||
#endif
            /* This 0 is for the case that neither IPv6 
             * support or Portlists is compiled in. Quiets a warning. */
            0) 
            {
                ParseError("Can not redefine variable name %s to be of type "
                           "'var'. Use a different name.", name);
            }
            break;

#ifdef SUP_IP6
        case VAR_TYPE__IPVAR:
            if (var_table != NULL)
            {
                do
                {
                    if(strcasecmp(p->name, name) == 0)
                    {
                        ParseError("Can not redefine variable name %s to be of "
                                   "type 'ipvar'. Use a different name.", name);
                    }

                    p = p->next;
                } while(p != var_table);
            }
#endif /* SUP_IP6 */

        default:
            /* Invalid function usage */
            break;
    }
}

/****************************************************************************
 *
 * Function: VarDefine(char *, char *)
 *
 * Purpose: define the contents of a variable
 *
 * Arguments: name => the name of the variable
 *            value => the contents of the variable
 *
 * Returns: void function
 *
 ***************************************************************************/
VarEntry * VarDefine(Barnyard2Config *bc, char *name, char *value)
{
    VarEntry *var_table = bc->var_table;
#ifdef SUP_IP6
    vartable_t *ip_vartable = bc->ip_vartable;
#endif
    VarEntry *p;
    //int    vlen,n;
    //char  *s;

    if(value == NULL)
    {
        ParseError("Bad value in variable definition!  Make sure you don't "
                   "have a \"$\" in the var name.");
    }

#ifdef SUP_IP6
    if(VarIsIpList(ip_vartable, value)) 
    {
        SFIP_RET ret;

        if (ip_vartable == NULL)
            return NULL;

        /* Verify a variable by this name is not already used as either a 
         * portvar or regular var.  Enforcing this mutual exclusion prevents the
         * catatrophe where the variable lookup fall-through (see VarSearch)
         * finds an unintended variable from the wrong table.  Note:  VarSearch
         * is only necessary for ExpandVars. */
        DisallowCrossTableDuplicateVars(bc, name, VAR_TYPE__IPVAR); 

        if((ret = sfvt_define(ip_vartable, name, value)) != SFIP_SUCCESS)
        {
            switch(ret) {
                case SFIP_ARG_ERR:
                    ParseError("The following is not allowed: %s.", value);
                    break;

                case SFIP_DUPLICATE:
                    ParseMessage("Var '%s' redefined.", name);
                    break;

                case SFIP_CONFLICT:
                    ParseError("Negated IP ranges that are more general than "
                               "non-negated ranges are not allowed. Consider "
                               "inverting the logic in %s.", name);
                    break;

                case SFIP_NOT_ANY:
                    ParseError("!any is not allowed in %s.", name);
                    break;

                default:
                    ParseError("Failed to parse the IP address: %s.", value);
            }
        }
        return NULL;
    }
    /* Check if this is a variable that stores an IP */
    else if(*value == '$')
    {
        sfip_var_t *var;
        if((var = sfvt_lookup_var(ip_vartable, value)) != NULL) 
        {
            sfvt_define(ip_vartable, name, value);
            return NULL;
        }
    }

#endif

    DisallowCrossTableDuplicateVars(bc, name, VAR_TYPE__DEFAULT); 

    if (var_table == NULL)
    {
        p = VarAlloc();
        p->name  = SnortStrdup(name);
        p->value = SnortStrdup(value);
        
        p->prev = p;
        p->next = p;

        bc->var_table = p;

        return p;
    }

    /* See if an existing variable is being redefined */
    p = var_table;

    do
    {
        if (strcasecmp(p->name, name) == 0)
        {
            if (p->value != NULL)
                free(p->value);

            p->value = SnortStrdup(value);
            LogMessage("Var '%s' redefined\n", p->name);
            return p;
        }

        p = p->next;

    } while (p != var_table);   /* List is circular */

    p = VarAlloc();
    p->name  = SnortStrdup(name);
    p->value = SnortStrdup(value);
    p->prev = var_table;
    p->next = var_table->next;
    p->next->prev = p;
    var_table->next = p;

    return p;
}

static void DeleteVars(VarEntry *var_table)
{
    VarEntry *q, *p = var_table;

    while (p)
    {
        q = p->next;
        if (p->name)
            free(p->name);
        if (p->value)
            free(p->value);
        free(p);
        p = q;
        if (p == var_table)
            break;  /* Grumble, it's a friggin circular list */
    }
}

/****************************************************************************
 *
 * Function: VarGet(char *)
 *
 * Purpose: get the contents of a variable
 *
 * Arguments: name => the name of the variable
 *
 * Returns: char * to contents of variable or FatalErrors on an
 *          undefined variable name
 *
 ***************************************************************************/
char *VarGet(char *name)
{
    Barnyard2Config *bc = barnyard2_conf_for_parsing;
    VarEntry *var_table;
#ifdef SUP_IP6
    vartable_t *ip_vartable;
    sfip_var_t *var;
#else
    VarEntry *p = NULL;
    char *ret = NULL;
#endif

    if (bc == NULL)
        return NULL;

    var_table = bc->var_table;

#ifdef SUP_IP6
// XXX-IPv6 This function should never be used if IP6 support is enabled!
// Infact it won't presently even work for IP variables since the raw ASCII 
// value is never stored, and is never meant to be used.
    ip_vartable = bc->ip_vartable;

    if((var = sfvt_lookup_var(ip_vartable, name)) == NULL) {
        /* Do the old style lookup since it wasn't found in 
         * the variable table */
        if(var_table != NULL)
        {
            VarEntry *p = var_table;
            do
            {
                if(strcasecmp(p->name, name) == 0)
                    return p->value;
                p = p->next;
            } while(p != var_table);
        }

        ParseError("Undefined variable name: %s.", name);
    }

    return name;

#else

    if (var_table != NULL)
    {
        p = var_table;

        do
        {
            if (strcasecmp(p->name, name) == 0)
            {
                ret = p->value;
                break;
            }

            p = p->next;

        } while (p != var_table);
    }

    if (ret == NULL)
        ParseError("Undefined variable name: %s.", name);

    return ret;
#endif
}

/****************************************************************************
 *
 * Function: ExpandVars()
 *
 * Purpose: expand all variables in a string
 *
 * Arguments:
 *  Barnyard2Config *
 *      The snort config that has the vartables.
 *  char *
 *      The name of the variable.
 *
 * Returns:
 *  char *
 *      The expanded string.  Note that the string is returned in a 
 *      static variable and most likely needs to be string dup'ed.
 *
 ***************************************************************************/
static char * ExpandVars(Barnyard2Config *bc, char *string)
{
    static char estring[ PARSERULE_SIZE ];

    char rawvarname[128], varname[128], varaux[128], varbuffer[128];
    char varmodifier, *varcontents;
    int varname_completed, c, i, j, iv, jv, l_string, name_only;
    int quote_toggle = 0;

    if(!string || !*string || !strchr(string, '$'))
        return(string);

    memset((char *) estring, 0, PARSERULE_SIZE); /* bzero() deprecated, replaced by memset() */

    i = j = 0;
    l_string = strlen(string);
    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, "ExpandVars, Before: %s\n", string););

    while(i < l_string && j < (int)sizeof(estring) - 1)
    {
        c = string[i++];
        
        if(c == '"')
        {
            /* added checks to make sure that we are inside a quoted string
             */
            quote_toggle ^= 1;
        }

        if(c == '$' && !quote_toggle)
        {
	    memset((char *) rawvarname, 0, sizeof(rawvarname)); /* bzero() deprecated, replaced by memset() */
            varname_completed = 0;
            name_only = 1;
            iv = i;
            jv = 0;

            if(string[i] == '(')
            {
                name_only = 0;
                iv = i + 1;
            }

            while(!varname_completed
                  && iv < l_string
                  && jv < (int)sizeof(rawvarname) - 1)
            {
                c = string[iv++];

                if((name_only && !(isalnum(c) || c == '_'))
                   || (!name_only && c == ')'))
                {
                    varname_completed = 1;

                    if(name_only)
                        iv--;
                }
                else
                {
                    rawvarname[jv++] = (char)c;
                }
            }

            if(varname_completed || iv == l_string)
            {
                char *p;

                i = iv;

                varcontents = NULL;

		memset((char *) varname, 0, sizeof(varname)); /* bzero() deprecated, replaced by memset() */
		memset((char *) varaux, 0, sizeof(varaux)); /* bzero() deprecated, replaced by memset() */
                varmodifier = ' ';

                p = strchr(rawvarname, ':');
                if (p)
                {
                    SnortStrncpy(varname, rawvarname, p - rawvarname);

                    if(strlen(p) >= 2)
                    {
                        varmodifier = *(p + 1);
                        SnortStrncpy(varaux, p + 2, sizeof(varaux));
                    }
                }
                else
                    SnortStrncpy(varname, rawvarname, sizeof(varname));

		memset((char *) varbuffer, 0, sizeof(varbuffer)); /* bzero() deprecated, replaced by memset() */

                varcontents = VarSearch(bc, varname);

                switch(varmodifier)
                {
                    case '-':
                        if(!varcontents || !strlen(varcontents))
                            varcontents = varaux;
                        break;

                    case '?':
                        if(!varcontents || !strlen(varcontents))
                        {
                            ErrorMessage("%s(%d): ", file_name, file_line);

                            if(strlen(varaux))
                                ParseError("%s", varaux);
                            else
                                ParseError("Undefined variable \"%s\".", varname);
                        }
                        break;
                }

                /* If variable not defined now, we're toast */
                if(!varcontents || !strlen(varcontents))
                    ParseError("Undefined variable name: %s.", varname);

                if(varcontents)
                {
                    int l_varcontents = strlen(varcontents);

                    iv = 0;

                    while(iv < l_varcontents && j < (int)sizeof(estring) - 1)
                        estring[j++] = varcontents[iv++];
                }
            }
            else
            {
                estring[j++] = '$';
            }
        }
        else
        {
            estring[j++] = (char)c;
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, "ExpandVars, After: %s\n", estring););

    return estring;
}

char * ProcessFileOption(Barnyard2Config *bc, const char *filespec)
{
    char *filename = NULL;
    char buffer[STD_BUF];

    if (bc == NULL)
        bc = barnyard2_conf;

    if(filespec == NULL)
    {
        FatalError("no arguement in this file option, remove extra ':' at the end of the alert option\n");
    }

    /* look for ".." in the string and complain and exit if it is found */
    if(strstr(filespec, "..") != NULL)
    {
        FatalError("file definition contains \"..\".  Do not do that!\n");
    }

    if(filespec[0] == '/')
    {
        /* absolute filespecs are saved as is */
        filename = SnortStrdup(filespec);
    }
    else
    {
        /* relative filespec is considered relative to the log directory */
        /* or /var/log if the log directory has not been set */
        /* Make sure this function isn't called before log dir is set */
        if ((bc != NULL) && (bc->log_dir != NULL))
        {
            strlcpy(buffer, barnyard2_conf->log_dir, STD_BUF);
        }
        else
        {
            strlcpy(buffer, "/var/log/barnyard2", STD_BUF);
        }

        strlcat(buffer, "/", STD_BUF - strlen(buffer));
        strlcat(buffer, filespec, STD_BUF - strlen(buffer));
        buffer[sizeof(buffer) - 1] = '\0';
        filename = SnortStrdup(buffer);
    }

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"ProcessFileOption: %s\n", filename););

    return filename;
}

static void ParseConfig(Barnyard2Config *bc, char *args)
{
    char **toks;
    int num_toks;
    char *opts = NULL;
    int i;

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Rule file config\n"););

    toks = mSplit(args, ":", 2, &num_toks, 0);

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Opt: %s\n", toks[0]););

    if (num_toks > 1)
    {
  
        opts = SnortStrdup(toks[1]);
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Args: %s\n", opts););
    }

    for (i = 0; config_opts[i].name != NULL; i++)
    {
        if (strcasecmp(toks[0], config_opts[i].name) == 0)
        {
            if (config_opts[i].only_once && config_opt_configured[i])
            {
                /* Configured already and set to only configure once
                 * This array is reset for each policy read in so this is
                 * on a per policy basis */
                ParseError("Config option \"%s\" can only be "
                           "configured once.", toks[0]);
            }

            if (config_opts[i].args_required && (opts == NULL))
            {
                /* Need arguments and there are none */
                 ParseError("Config option \"%s\" requires arguments.", toks[0]);
            }

            config_opts[i].parse_func(bc, opts);
            config_opt_configured[i] = 1;
            break;
        }
    }

    if (config_opts[i].name == NULL)
    {
        /* Didn't find a matching config option */
        ParseError("Unknown config directive: %s.", toks[0]);
    }

    mSplitFree(&toks, num_toks);

    if(opts)
    {
	free(opts);
    }

}

/*
 * Same as VarGet - but this does not Fatal out if a var is not found
 */
static char * VarSearch(Barnyard2Config *bc, char *name)
{
    VarEntry *var_table = bc->var_table;
#ifdef SUP_IP6
    vartable_t *ip_vartable = bc->ip_vartable;
#endif

#ifdef SUP_IP6
    if(!sfvt_lookup_var(ip_vartable, name)) 
    {
#endif

        if(var_table != NULL)
        {
            VarEntry *p = var_table;
            do
            {
                if(strcasecmp(p->name, name) == 0)
                    return p->value;
                p = p->next;
            } while(p != var_table);
        }
       
        return NULL;

#ifdef SUP_IP6
    }
#endif

    return name;
}

void ParserCleanup(void)
{
}

static void InitVarTables(Barnyard2Config *bc)
{
    if (bc == NULL)
        return;

    if (bc->var_table != NULL)
        DeleteVars(bc->var_table);

#ifdef SUP_IP6
    if (bc->ip_vartable != NULL)
        sfvt_free_table(bc->ip_vartable);
    bc->ip_vartable = sfvt_alloc_table();
#endif
}

static void InitParser(void)
{
    /* This is for determining if a config option has already been
     * configured.  Most can only be configured once */
    memset(config_opt_configured, 0, sizeof(config_opt_configured));
}

static void ParseConfigFile(Barnyard2Config *bc, char *fname)
{
    /* Used for line continuation */
    int continuation = 0;
    char *saved_line = NULL;
    char *new_line = NULL;
    char *buf = (char *)SnortAlloc(MAX_LINE_LENGTH + 1);
    FILE *fp = fopen(fname, "r");

    /* open the rules file */
    if (fp == NULL)
    {
        FatalError("Unable to open config file \"%s\": %s.\n",
                   fname, strerror(errno));
    }

    /* loop thru each file line and send it to the rule parser */
    while ((fgets(buf, MAX_LINE_LENGTH, fp)) != NULL)
    {
        /* buffer indexing pointer */
        char *index = buf;

        /* Increment the line counter so the error messages know which
         * line to bitch about */
        file_line++;

        /* fgets always appends a null, so doing a strlen should be safe */
        if ((strlen(buf) + 1) == MAX_LINE_LENGTH)
        {
            ParseError("Line greater than or equal to %u characters which is "
                       "more than the parser is willing to handle.  Try "
                       "splitting it up on multiple lines if possible.",
                       MAX_LINE_LENGTH);
        }

        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, "Got line %s (%d): %s\n",
                                fname, file_line, buf););

        /* advance through any whitespace at the beginning of the line */
        while (isspace((int)*index))
            index++;

        /* If it's an empty line or starts with a comment character */
        if ((strlen(index) == 0) || (*index == '#') || (*index == ';'))
            continue;
          
        if (continuation)
        {
            int new_line_len = strlen(saved_line) + strlen(index) + 1;

            if (new_line_len >= PARSERULE_SIZE)
            {
                ParseError("Rule greater than or equal to %u characters which "
                           "is more than the parser is willing to handle.  "
                           "Submit a bug to bugs@snort.org if you legitimately "
                           "feel like your rule or keyword configuration needs "
                           "more than this amount of space.", PARSERULE_SIZE);
            }

            new_line = (char *)SnortAlloc(new_line_len);
            snprintf(new_line, new_line_len, "%s%s", saved_line, index);

            free(saved_line);
            saved_line = NULL;
            index = new_line;

            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"concat rule: %s\n", 
                                    new_line););
        }

        /* check for a '\' continuation character at the end of the line
         * if it's there we need to get the next line in the file */
        if (ContinuationCheck(index) == 0) 
        {
            char **toks;
            int num_toks;
            char *keyword;
            char *args;
            int i;

            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,
                                    "[*] Processing keyword: %s\n", index););

            /* Get the keyword and args */
            toks = mSplit(index, " \t", 2, &num_toks, 0);
            if (num_toks != 2)
                ParseError("Invalid configuration line: %s", index);

            keyword = SnortStrdup(ExpandVars(bc, toks[0]));
            args = toks[1];

            for (i = 0; barnyard2_conf_keywords[i].name != NULL; i++)
            {
                if (strcasecmp(keyword, barnyard2_conf_keywords[i].name) == 0)
                {
                    if (barnyard2_conf_keywords[i].expand_vars)
                        args = SnortStrdup(ExpandVars(bc, toks[1]));

                    barnyard2_conf_keywords[i].parse_func(bc, args);

                    break;
                }
            }

            if (args != toks[1])
                free(args);

            free(keyword);
            mSplitFree(&toks, num_toks);

            if(new_line != NULL)
            {
                free(new_line);
                new_line = NULL;
                continuation = 0;
            }
        }
        else
        {
            /* save the current line */
            saved_line = SnortStrdup(index);

            /* current line was a continuation itself... */
            if (new_line != NULL)
            {
                free(new_line);
                new_line = NULL;
            }

            /* set the flag to let us know the next line is 
             * a continuation line */ 
            continuation = 1;
        }   
    }

    fclose(fp);
    free(buf);
}

static int ContinuationCheck(char *rule)
{
    char *idx;  /* indexing var for moving around on the string */

    idx = rule + strlen(rule) - 1;

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"initial idx set to \'%c\'\n", 
                *idx););

    while(isspace((int)*idx))
    {
        idx--;
    }

    if(*idx == '\\')
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Got continuation char, "
                    "clearing char and returning 1\n"););

        /* clear the '\' so there isn't a problem on the appended string */
        *idx = '\x0';
        return 1;
    }

    return 0;
}


void ConfigAlertOnEachPacketInStream(Barnyard2Config *bc, char *args)
{
    if (bc == NULL)
        return;

    LogMessage("INFO: Alerting on each packet associated with an event: is now enabled by default. \n"
               " use: command line argument --disable-alert-on-each-packet-in-stream or \n"
               " configure file argument disable-alert-on-each-packet-in-stream to disable the feature \n");

    return;
}


void ConfigSetEventCacheSize(Barnyard2Config *bc, char *args)
{
    if( (bc == NULL) ||
        (args == NULL))
    {
        return;
    }

    bc->event_cache_size = strtoul(args,NULL,10);
    return;
}

void ConfigDisableAlertOnEachPacketInStream(Barnyard2Config *bc, char *args)
{
    if (bc == NULL)
        return;

    bc->alert_on_each_packet_in_stream_flag = 0;
}

void ConfigArchiveDir(Barnyard2Config *bc, char *args)
{
    if ((args == NULL) || (bc == NULL) || (bc->archive_dir != NULL))
        return;

    bc->archive_dir = SnortStrdup(args);
}

void ConfigAlertWithInterfaceName(Barnyard2Config *bc, char *args)
{
    if (bc == NULL)
        return;

    bc->output_flags |= OUTPUT_FLAG__ALERT_IFACE;
}

void ConfigChrootDir(Barnyard2Config *bc, char *args)
{
#ifdef WIN32
    ParseError("Setting the chroot directory is not supported in "
               "the WIN32 port of snort!");
#else
    if ((args == NULL) || (bc == NULL) || (bc->chroot_dir != NULL))
        return;

    bc->chroot_dir = SnortStrdup(args);
#endif
}

void ConfigClassification(Barnyard2Config *bc, char *args)
{
    char **toks;
    int num_toks;
    char *endptr;
    ClassType *new_node, *current;
    int max_id = 0;

    if ((args == NULL) || (bc == NULL))
        return;

    toks = mSplit(args, ",", 0, &num_toks, '\\');
    if (num_toks != 3)
        ParseError("Invalid classification config: %s.", args);

    /* create the new node */
    new_node = (ClassType *)SnortAlloc(sizeof(ClassType));

    new_node->type = SnortStrdup(toks[0]);
    new_node->name = SnortStrdup(toks[1]);

    new_node->priority = strtol(toks[2], &endptr, 0);
    if ((errno == ERANGE) || (*endptr != '\0') || (new_node->priority <= 0))
    {
        ParseError("Invalid argument for classification priority "
                   "configuration: %s.  Must be a positive integer.", toks[2]);
    }

    current = bc->classifications;
    while (current != NULL)
    {
        /* dup check */
        if (strcasecmp(current->type, new_node->type) == 0)
        {
            LogMessage("%s(%d): Duplicate classification \"%s\""
                         "found, ignoring this line\n", file_name, file_line, 
                         new_node->type);
            break;
        }

        if (current->id > max_id)
            max_id = current->id;

        current = current->next;
    }

    /* Got a dup */
    if (current != NULL)
    {
        free(new_node->name);
        free(new_node->type);
        free(new_node);
        mSplitFree(&toks, num_toks);
        return;
    }

    /* insert node */
    new_node->id = max_id + 1;
    new_node->next = bc->classifications;
    bc->classifications = new_node;

    mSplitFree(&toks, num_toks);
}

void ConfigClassificationFile(Barnyard2Config *bc, char *args)
{
    if ((args == NULL) || (bc == NULL) )
        return;

    bc->class_file = SnortStrndup(args,strlen(args));

    ReadClassificationFile(bc);
}

void ConfigCreatePidFile(Barnyard2Config *bc, char *args)
{
    if (bc == NULL)
        return;

    bc->run_flags |= RUN_FLAG__CREATE_PID_FILE;
}

void ConfigDaemon(Barnyard2Config *bc, char *args)
{
#ifdef WIN32
    ParseError("Setting the Daemon mode is not supported in the "
               "WIN32 port of barnyard2!  Use 'barnyard2 /SERVICE ...' instead.");
#else
    if (bc == NULL)
        return;

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Daemon mode flag set\n"););
    bc->run_flags |= RUN_FLAG__DAEMON;
    bc->logging_flags |= LOGGING_FLAG__QUIET;
#endif
}

void ConfigDecodeDataLink(Barnyard2Config *bc, char *args)
{
    if (bc == NULL)
        return;

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Decode DLL set\n"););
    bc->output_flags |= OUTPUT_FLAG__SHOW_DATA_LINK;
}

void ConfigDumpCharsOnly(Barnyard2Config *bc, char *args)
{
    if (bc == NULL)
        return;

    /* dump the application layer as text only */
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Character payload dump set\n"););
    bc->output_flags |= OUTPUT_FLAG__CHAR_DATA;
}

void ConfigDumpPayload(Barnyard2Config *bc, char *args)
{
    if (bc == NULL)
        return;

    /* dump the application layer */
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Payload dump set\n"););
    bc->output_flags |= OUTPUT_FLAG__APP_DATA;
}

void ConfigDumpPayloadVerbose(Barnyard2Config *bc, char *args)
{
    if (bc == NULL)
        return;

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Verbose packet bytecode dumps enabled\n"););
    bc->output_flags |= OUTPUT_FLAG__VERBOSE_DUMP;
}

void ConfigGenFile(Barnyard2Config *bc, char *args)
{
    if ((args == NULL) || (bc == NULL) )
        return;

    bc->gen_msg_file = SnortStrndup(args,PATH_MAX);
    return;
}

void ConfigHostname(Barnyard2Config *bc, char *args)
{
    if ((args == NULL) || (bc == NULL) || (bc->hostname != NULL))
        return;

    /* this code handles the case in which the user specifies
     * the entire name of the host and it is compiled regardless
     * of which OS you have */
    bc->hostname = SnortStrdup(args);
}

void ConfigInterface(Barnyard2Config *bc, char *args)
{
    if ((args == NULL) || (bc == NULL) || (bc->interface != NULL))
        return;

    /* this code handles the case in which the user specifies
     * the entire name of the interface and it is compiled
     * regardless of which OS you have */
    bc->interface = SnortStrdup(args);
}

void ConfigLogDir(Barnyard2Config *bc, char *args)
{
    if ((args == NULL) || (bc == NULL) || (bc->log_dir != NULL))
        return;

    bc->log_dir = SnortStrdup(args);
}

void ConfigNoLoggingTimestamps(Barnyard2Config *bc, char *args)
{
    if (bc == NULL)
        return;

    bc->output_flags |= OUTPUT_FLAG__NO_TIMESTAMP;
}

void ConfigObfuscate(Barnyard2Config *bc, char *args)
{
    if (bc == NULL)
        return;

    bc->output_flags |= OUTPUT_FLAG__OBFUSCATE;
}

void ConfigObfuscationMask(Barnyard2Config *bc, char *args)
{
#ifndef SUP_IP6
    struct in_addr net;       /* place to stick the local network data */
    char **toks;              /* dbl ptr to store mSplit return data in */
    int num_toks;             /* number of tokens mSplit returns */
    int nmask;                /* temporary netmask storage */
# ifdef DEBUG
    struct in_addr sin;
# endif
#endif

    if ((bc == NULL) || (args == NULL))
        return;

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Got obfus data: %s\n", args););

#ifdef SUP_IP6
    sfip_pton(args, &bc->obfuscation_net);
    bc->output_flags |= OUTPUT_FLAG__OBFUSCATE;
#else
    /* break out the CIDR notation from the IP address */
    toks = mSplit(args, "/", 2, &num_toks, 0);

    if(num_toks > 1)
    {
        /* convert the CIDR notation into a real live netmask */
        nmask = atoi(toks[1]);

        if((nmask > 0) && (nmask < 33))
        {
            bc->obfuscation_mask = htonl(netmasks[nmask]);
        }
        else
        {
            ParseError("Bad CIDR block (%s) in obfuscation mask %s. "
                       "1 to 32 please!", toks[1], args);
        }
    }
    else
    {
        ParseError("No netmask specified for obsucation mask!");
    }

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "obfuscation netmask = %#8lX\n", 
                            bc->obfuscation_mask););

    /* convert the IP addr into its 32-bit value */
    if((net.s_addr = inet_addr(toks[0])) == INADDR_NONE)
        ParseError("Obfuscation mask (%s) didn't translate.", toks[0]);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Obfuscation Net = %s (%X)\n", 
                            inet_ntoa(net), net.s_addr););

    /* set the final homenet address up */
    bc->obfuscation_net = net.s_addr & bc->obfuscation_mask;

#ifdef DEBUG
    sin.s_addr = bc->obfuscation_net;
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Obfuscation Net = %s (%X)\n", 
                            inet_ntoa(sin), sin.s_addr););
#endif

    bc->obfuscation_mask = ~bc->obfuscation_mask;
    bc->output_flags |= OUTPUT_FLAG__OBFUSCATE;

    mSplitFree(&toks, num_toks);
#endif
}

void ConfigPidPath(Barnyard2Config *bc, char *args)
{
    if ((args == NULL) || (bc == NULL))
        return;

    LogMessage("Found pid path directive (%s)\n", args);

    bc->run_flags |= RUN_FLAG__CREATE_PID_FILE;
    if (SnortStrncpy(bc->pid_path, args, sizeof(bc->pid_path)) != SNORT_STRNCPY_SUCCESS)
        ParseError("Pid path too long.");
    
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Pid Path directory = %s\n", 
                            bc->pid_path););
}

void ConfigQuiet(Barnyard2Config *bc, char *args)
{
    if (bc == NULL)
        return;

    bc->logging_flags |= LOGGING_FLAG__QUIET;
}

void ConfigReference(Barnyard2Config *bc, char *args)
{
    char **toks;
    int num_toks;
    char *url = NULL;

    if ((bc == NULL) || (args == NULL))
        return;

    /* 2 tokens: name <url> */
    toks = mSplit(args, " \t", 0, &num_toks, 0);

    if (num_toks > 2)
    {
        ParseError("Reference config requires at most two arguments: "
                   "\"name [<url>]\".");
    }

    if (num_toks == 2)
        url = toks[1];
    
    ReferenceSystemAdd(&bc->references, toks[0], url);

    mSplitFree(&toks, num_toks);
}

void ConfigReferenceFile(Barnyard2Config *bc, char *args)
{
    if ((args == NULL) || (bc == NULL) )
        return;

    ReadReferenceFile(bc, args);
}

/*
 * Function: ConfigReferenceNet
 *
 * Purpose: Translate the command line character string into its equivalent
 *          32-bit network byte ordered value (with netmask)
 *
 * Arguments: args => The address/CIDR block
 *
 * Returns: void function
 */
void ConfigReferenceNet(Barnyard2Config *bc, char *args)
{
#ifndef SUP_IP6
    struct in_addr net;    /* place to stick the local network data */
    char **toks;           /* dbl ptr to store mSplit return data in */
    int num_toks;          /* number of tokens mSplit returns */
    int nmask;             /* temporary netmask storage */
# ifdef DEBUG
    struct in_addr sin;
# endif
#endif

    if ((bc == NULL) || (args == NULL))
        return;

#ifdef SUP_IP6
    sfip_pton(args, &bc->homenet);
#else

    /* break out the CIDR notation from the IP address */
    toks = mSplit(args, "/", 2, &num_toks, 0);

    if(num_toks > 1)
    {
        /* convert the CIDR notation into a real live netmask */
        nmask = atoi(toks[1]);

        if((nmask > 0) && (nmask < 33))
        {
            bc->netmask = htonl(netmasks[nmask]);
        }
        else
        {
            ParseError("Bad CIDR block (%s) in obfuscation mask %s. "
                       "1 to 32 please!", toks[1], args);
        }
    }
    else
    {
        ParseError("No netmask specified for home network!");
    }

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "homenet netmask = %#8lX\n",
                            bc->netmask););

    /* convert the IP addr into its 32-bit value */
    if((net.s_addr = inet_addr(toks[0])) == INADDR_NONE)
        ParseError("Homenet (%s) didn't translate", toks[0]);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Net = %s (%X)\n",
                            inet_ntoa(net), net.s_addr););

    /* set the final homenet address up */
    bc->homenet = net.s_addr & bc->netmask;

# ifdef DEBUG
    sin.s_addr = bc->homenet;
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Homenet = %s (%X)\n",
                            inet_ntoa(sin), sin.s_addr););
# endif

    mSplitFree(&toks, num_toks);
#endif
}

void ConfigSetGid(Barnyard2Config *bc, char *args)
{
#ifdef WIN32
    ParseError("Setting the group id is not supported in the "
               "WIN32 port of barnyard2!");
#else
    size_t i;
    char *endptr;

    if ((bc == NULL) || (args == NULL))
        return;

    for (i = 0; i < strlen(args); i++)
    {
        /* If we get something other than a digit, assume it's
         * a group name */
        if (!isdigit((int)args[i]))
        {
            struct group *gr = getgrnam(args);

            if (gr == NULL)
                ParseError("Group \"%s\" unknown.", args);

            bc->group_id = gr->gr_gid;
            break;
        }
    }

    /* It's all digits.  Assume it's a group id */
    if (i == strlen(args))
    {
        bc->group_id = strtol(args, &endptr, 10);
        if ((errno == ERANGE) || (*endptr != '\0') ||
            (bc->group_id < 0))
        {
            ParseError("Group id \"%s\" out of range.", args);
        }
    }
#endif
}

void ConfigSetUid(Barnyard2Config *bc, char *args)
{
#ifdef WIN32
    ParseError("Setting the user id is not supported in the "
               "WIN32 port of barnyard2!");
#else
    size_t i;
    char *endptr;

    if ((bc == NULL) || (args == NULL))
        return;

    for (i = 0; i < strlen(args); i++)
    {
        /* If we get something other than a digit, assume it's
         * a user name */
        if (!isdigit((int)args[i]))
        {
            struct passwd *pw = getpwnam(args);

            if (pw == NULL)
                ParseError("User \"%s\" unknown.", args);

            bc->user_id = (int)pw->pw_uid;

            /* Why would someone want to run as another user
             * but still as root group? */
            if (bc->group_id == -1)
                bc->group_id = (int)pw->pw_gid;

            break;
        }
    }

    /* It's all digits.  Assume it's a user id */
    if (i == strlen(args))
    {
        bc->user_id = strtol(args, &endptr, 10);
        if ((errno == ERANGE) || (*endptr != '\0'))
            ParseError("User id \"%s\" out of range.", args);

        /* Set group id to user's default group if not
         * already set */
        if (bc->group_id == -1)
        {
            struct passwd *pw = getpwuid((uid_t)bc->user_id);

            if (pw == NULL)
                ParseError("User \"%s\" unknown.", args);

            bc->group_id = (int)pw->pw_gid;
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "UserID: %d GroupID: %d.\n",
                            bc->user_id, bc->group_id););
#endif  /* !WIN32 */
}

void ConfigShowYear(Barnyard2Config *bc, char *args)
{
    if (bc == NULL)
        return;

    bc->output_flags |= OUTPUT_FLAG__INCLUDE_YEAR;
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Enabled year in timestamp\n"););
}

void ConfigSidFile(Barnyard2Config *bc, char *args)
{
    if ((args == NULL) || (bc == NULL) )
        return;

    bc->sid_msg_file = SnortStrndup(args,PATH_MAX);
}

void ConfigUmask(Barnyard2Config *bc, char *args)
{
#ifdef WIN32
    ParseError("Setting the umask is not supported in the "
               "WIN32 port of snort!");
#else
    char *endptr;
    long mask;

    if ((bc == NULL) || (args == NULL))
        return;

    mask = strtol(args, &endptr, 0);

    if ((errno == ERANGE) || (*endptr != '\0') ||
        (mask < 0) || (mask & ~FILEACCESSBITS))
    {
        ParseError("Bad umask: %s", args);
    }
    bc->file_mask = (mode_t)mask;
#endif
}

void ConfigUtc(Barnyard2Config *bc, char *args)
{
    if (bc == NULL)
        return;

    bc->output_flags |= OUTPUT_FLAG__USE_UTC;
}

void ConfigVerbose(Barnyard2Config *bc, char *args)
{
    if (bc == NULL)
        return;

    bc->logging_flags |= LOGGING_FLAG__VERBOSE;
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Verbose Flag active\n"););
}

void ConfigProcessNewRecordsOnly(Barnyard2Config *bc, char *args)
{
    if (bc == NULL)
        return;

    bc->process_new_records_only_flag = 1;
}

void ConfigSpoolFilebase(Barnyard2Config *bc, char *args)
{
    if ((args == NULL) || (bc == NULL) )
        return;

    if ( SnortSnprintf(bc->waldo.data.spool_filebase, STD_BUF, "%s", args) != SNORT_SNPRINTF_SUCCESS )
        FatalError("barnyard2: spool filebase too long\n");
}

void ConfigSpoolDirectory(Barnyard2Config *bc, char *args)
{
    if ((args == NULL) || (bc == NULL) )
        return;

    if ( SnortSnprintf(bc->waldo.data.spool_dir, STD_BUF, "%s", args) != SNORT_SNPRINTF_SUCCESS )
        FatalError("barnyard2: spool directory too long\n");
}

void ConfigWaldoFile(Barnyard2Config *bc, char *args)
{
    if ((args == NULL) || (bc == NULL) )
        return;

    if ( SnortSnprintf(bc->waldo.filepath, STD_BUF, "%s", args) != SNORT_SNPRINTF_SUCCESS )
        FatalError("barnyard2: waldo filepath too long\n");

    bc->waldo.state |= WALDO_STATE_ENABLED;
}


void DisplaySigSuppress(SigSuppress_list **sHead)
{
    if(sHead == NULL)
    {
	return;
    }
    SigSuppress_list *cNode = *sHead;

    LogMessage("\n\n+[ Signature Suppress list ]+\n"
	            "----------------------------\n");

    if(cNode)
    {
	while(cNode)
	{
	    LogMessage("-- Element type:[%s] gid:[%d] sid min:[%d] sid max:[%d] \n",
		       (cNode->ss_type & SS_SINGLE) ? "SINGLE" : "RANGE ",
		       cNode->gid,
		       cNode->ss_min,
		       cNode->ss_max);
	    
	    cNode = cNode->next;
	}
    }
    else
    {
	LogMessage("+[No entry in Signature Suppress List]+\n");
    }
    LogMessage("----------------------------\n"
	       "+[ Signature Suppress list ]+\n\n");
    return;
}

int SigSuppressUnlinkNode(SigSuppress_list **sHead,SigSuppress_list **cNode,SigSuppress_list **pNode)
{
    SigSuppress_list *nNode = NULL;

    if( ((sHead == NULL) || (*sHead == NULL)) ||
	((cNode == NULL) || (*cNode == NULL)) ||
	((pNode == NULL) || (*pNode == NULL)))
    {
	return 1;
    }
    
    nNode =(SigSuppress_list *)(*cNode)->next;

    if( *cNode == *sHead)
    {
	*sHead = nNode;
	free(*cNode);
	*cNode = nNode;
	*pNode = *cNode;
    }
    else
    {
	(*(SigSuppress_list **)(pNode))->next = nNode;
	free(*cNode);
	*cNode = nNode;
    }

    return 0;
}

int SigSuppressAddElement(SigSuppress_list **sHead,SigSuppress_list *sElement)
{
    SigSuppress_list *cNode = NULL;
    SigSuppress_list *pNode = NULL;
    SigSuppress_list *newNode = NULL;
    
    u_int8_t comp_set[4] = {0};
    
    int has_flag = 0;
    int no_add = 0;

    if( (sHead == NULL) ||
	(sElement == NULL))
    {
	return 1;
    }
    
    if(*sHead == NULL)
    {
	if( (newNode = calloc(1,sizeof(SigSuppress_list))) == NULL)
	{
	    return 1;
	}

	memcpy(newNode,sElement,sizeof(SigSuppress_list));
	*sHead = newNode;
    }
    else
    {
	cNode = *sHead;
	pNode = cNode;

	has_flag = 0;
	no_add = 0;
	
	while(cNode != NULL)
	{
	    memset(&comp_set,'\0',(sizeof(u_int8_t)*4));
	    
	    if( (cNode->gid == sElement->gid))
	    {
		switch(sElement->ss_type)
		{
		case SS_SINGLE:
		    switch(cNode->ss_type)
		    {
		    case SS_SINGLE:
			if( ((cNode->ss_min == sElement->ss_min)  &&
			     (cNode->ss_max == sElement->ss_max)))
			{
			    DEBUG_WRAP(DebugMessage(DEBUG_SID_SUPPRESS,"[%s()], Signature Suppress configuration entry type:[SINGLE] gid:[%d] sid:[%d] was not added because it is already in present.\n",
						    __FUNCTION__,
						    sElement->gid,
						    sElement->ss_min););
			    return 0;
			}
			break;
			
		    case SS_RANGE:
			if( ((cNode->ss_min <= sElement->ss_min) &&
                             (cNode->ss_max >= sElement->ss_max)))
                        {
			    DEBUG_WRAP(DebugMessage(DEBUG_SID_SUPPRESS,
						    "[%s()], Signature Suppress configuration entry gid:[%d] sid[%d] already covered by\n"
						    "Signature Suppress configuration list element type:[RANGE] gid:[%d] sid min:[%d] sid max:[%d].\n",
						    __FUNCTION__,
						    sElement->gid,
						    sElement->ss_min,
						    cNode->gid,
						    cNode->ss_min,
						    cNode->ss_max););
			    return 0;
			}
			break;

		    default:
			/* XXX */
			return 1;
			break;
		    }
		    break;
		    
		case SS_RANGE:
		    switch(cNode->ss_type)
                    {
		    case SS_SINGLE:
			if( ((sElement->ss_min <= cNode->ss_min) &&
			     (sElement->ss_max >= cNode->ss_max)))
			{
			    DEBUG_WRAP(DebugMessage(DEBUG_SID_SUPPRESS,
						    "[%s()], Signature Suppress configuration gid:[%d] sid:[%d] flagged for deletion from list,\n"
						    "Element is intersecting with Signature Suppress list  range gid[%d] sid min:[%d] sid max:[%d]\n\n",
						    __FUNCTION__,
						    cNode->gid,
						    cNode->ss_min,
						    sElement->gid,
						    sElement->ss_min,
						    sElement->ss_max););
			    cNode->flag = 1;
			    has_flag = 1;
			}
			break;
			
		    case SS_RANGE:
			if(sElement->ss_min <= cNode->ss_min)
			    comp_set[0] = 1;
			
			if(sElement->ss_min >= cNode->ss_max)
			    comp_set[1] = 1;
			
			if(sElement->ss_max >= cNode->ss_min)
			    comp_set[2] = 1;
			
			if(sElement->ss_max <= cNode->ss_max)
			    comp_set[3] = 1;
			
			DEBUG_WRAP(DebugMessage(DEBUG_SID_SUPPRESS,
						"[%s()]: Comparing Signature intersection comp0:[%d] comp1:[%d] comp2:[%d] comp3:[%d]\n"
						"Signature Suppress configuration entry: gid:[%d] sid min:[%d] sid max:[%d]\n"
                                                "Signature Suppress list entry:          gid:[%d] sid min:[%d] sid max:[%d]\n\n",
						__FUNCTION__,
						comp_set[0],comp_set[1],comp_set[2],comp_set[3],
						sElement->gid,sElement->ss_min,sElement->ss_max,
						cNode->gid,cNode->ss_min,cNode->ss_max););
			
			if( (comp_set[0] && !comp_set[1] && comp_set[2] && comp_set[3]) ||
			    (!comp_set[0] && !comp_set[1] && comp_set[2] && comp_set[3]))
			{
			    DEBUG_WRAP(DebugMessage(DEBUG_SID_SUPPRESS,
						    "[%s()]: Signature Suppress configuration entry  gid:[%d] sid min:[%d] sid max:[%d] is INCLUDED in \n"
						    "Signature Suppress list entry gid:[%d] sid min:[%d] sid max:[%d]\n\n",
						    __FUNCTION__,
						    sElement->gid,sElement->ss_min,sElement->ss_max,
						    cNode->gid,cNode->ss_min,cNode->ss_max););
			    
			    no_add = 1;
			}
			else if( (comp_set[0] && comp_set[1] && !comp_set[2] && comp_set[3]) || 
				 (!comp_set[0] && !comp_set[1] && comp_set[2] && !comp_set[3]))
			{
			    
			    DEBUG_WRAP(DebugMessage(DEBUG_SID_SUPPRESS,
						    "[%s()]: Signature Suppress list entry  gid:[%d] sid min:[%d] sid max:[%d] and\n"
						    "Signature Suppress configuration entry  gid:[%d] sid min:[%d] sid max:[%d] share some intesection, altering list entry. \n\n",
						    __FUNCTION__,
						    cNode->gid,cNode->ss_min,cNode->ss_max,
						    sElement->gid,sElement->ss_min,sElement->ss_max););
			    
			    if(sElement->ss_min <= cNode->ss_min)
			    {
				cNode->ss_min = sElement->ss_min;
			    }

			    if(sElement->ss_max >= cNode->ss_max)
			    {
				cNode->ss_max = sElement->ss_max;
			    }

			    DEBUG_WRAP(DebugMessage(DEBUG_SID_SUPPRESS,
						    "[%s()]: Modified Signature Suppress list entry gid:[%d] sid min:[%d] sid max:[%d] \n",
						    __FUNCTION__,
						    cNode->gid,cNode->ss_min,cNode->ss_max););
				       
			    no_add = 1;
			}
			break;
			
		    default:
			FatalError("[%s()]: Unknown type[%d] for Signature Suppress configuration entry gid:[%d] sid min:[%d] max sid:[%d] \n",
				   __FUNCTION__,
				   cNode->ss_type,
				   cNode->gid,
				   cNode->ss_min,
				   cNode->ss_max);
			return 1;
			break;
			
		    }
		    break;
		    
		default:
		    FatalError("[%s()]: Unknown type[%d] for Signature Suppress configuration entry gid:[%d] sid min:[%d] max sid:[%d] \n",
			       __FUNCTION__,
			       sElement->ss_type,
			       sElement->gid,
			       sElement->ss_min,
			       sElement->ss_max);
		    return 1;
		    break;
		}
	    }
	    
	    pNode = cNode;	    
	    cNode = cNode->next;
	}
	
	/* We could keep an index, but rolling is way faster isin't ;) */
	if(has_flag)
	{
	    cNode = *sHead;
	    pNode = cNode;
	    
	    while(cNode)
	    {
		if(cNode->flag)
		{
		    DEBUG_WRAP(DebugMessage(DEBUG_SID_SUPPRESS,
					    "[%s(), unlinking Signature Suppress list entry type:[%d] gid:[%d] sid_min:[%d] sid_max:[%d] \n",
					    __FUNCTION__,
					    cNode->ss_type,
					    cNode->gid,
					    cNode->ss_min,
					    cNode->ss_max););
			       
		    if( SigSuppressUnlinkNode(sHead,&cNode,&pNode))
		    {
			return 1;
		    }
		}
		
		if(cNode)
		{
		    pNode = cNode;
		    cNode = cNode->next;
		}
	    }
	}
	
	if(!no_add)
	{
	    if( (newNode = calloc(1,sizeof(SigSuppress_list))) == NULL)
	    {
		return 1;
	    }
	    
	    memcpy(newNode,sElement,sizeof(SigSuppress_list));
	    
	    pNode->next = newNode;
	    
	    DEBUG_WRAP(DebugMessage(DEBUG_SID_SUPPRESS,
				    "[%s()], Signature Suppress configuration entry type:[%s] gid:[%d] sid min:[%d] sid max:[%d] added to Signature Suppress list.\n",
				    __FUNCTION__,
				    (newNode->ss_type & SS_SINGLE) ? "SINGLE" : "RANGE",		       
				    newNode->gid,
				    newNode->ss_min,
				    newNode->ss_max););
	}
    }    
    

    return 0;
}

void ConfigSigSuppress(Barnyard2Config *bc, char *args)
{
    char **toks = NULL;
    int num_toks = 0;
    int ptoks = 0;
    
    char gid_string[256] = {0};

    char **range_toks = NULL;
    int range_num_toks = 0;
    
    char **gid_toks = NULL;
    char *gid_sup_toks = NULL;
    int gid_num_toks = 0;
    
    SigSuppress_list t_supp_elem = {0};

    if( (bc == NULL) || (args == NULL))
    {
	return;
    }

    toks = mSplit(args, ",", 0, &num_toks, 0);
    
    while(ptoks < num_toks)
    {
	memset(gid_string,'\0',256);
	
	gid_toks = mSplit(toks[ptoks], ":", 2, &gid_num_toks, 0);
	
	if(gid_num_toks == 1)
	{
	    DEBUG_WRAP(DebugMessage(DEBUG_SID_SUPPRESS_PARSE,"Defaulting gid 1 for toks [%s]\n",
				    toks[ptoks]););
	    t_supp_elem.gid = 1;    
	    gid_sup_toks = toks[ptoks];
	}
	else if(gid_num_toks == 2)
	{
	    memcpy(gid_string,gid_toks[0],strlen(gid_toks[0]));
	    
	    if( BY2Strtoul(gid_string,&t_supp_elem.gid))
	    {
		FatalError("[%s] \n",__FUNCTION__);
	    }
	    
	    DEBUG_WRAP(DebugMessage(DEBUG_SID_SUPPRESS_PARSE,"Using gid [%d] for toks [%s]\n",
				    t_supp_elem.gid,
				    toks[ptoks]););
	    
	    gid_sup_toks = gid_toks[1];
	}
	else
	{
	    FatalError("[%s()]: Invalid gid split value for [%s]\n",
		       __FUNCTION__,
		       toks[ptoks]);
	}
	
	range_toks = mSplit(gid_sup_toks, "-", 0, &range_num_toks, 0);
	
	if(range_num_toks == 1)
	{
	    t_supp_elem.ss_type = SS_SINGLE;
	    
	    if( BY2Strtoul(gid_sup_toks,&t_supp_elem.ss_min))
            {
                FatalError("[%s] \n",__FUNCTION__);
            }

	    t_supp_elem.ss_max = t_supp_elem.ss_min;
	    
	    DEBUG_WRAP(DebugMessage(DEBUG_SID_SUPPRESS_PARSE,"Single element gid[%d] sid[%d] \n",
				    t_supp_elem.gid,
				    t_supp_elem.ss_min););
	}
	else if(range_num_toks == 2)
	{
	    DEBUG_WRAP(DebugMessage(DEBUG_SID_SUPPRESS_PARSE,"Got range [%s] : [%s] [%s] \n",
				    gid_sup_toks,
				    range_toks[0],
				    range_toks[1]););
	    
	    t_supp_elem.ss_type = SS_RANGE;
	    
	    if( BY2Strtoul(range_toks[0],&t_supp_elem.ss_min))
            {
                FatalError("[%s] \n",__FUNCTION__);
            }
	    
	    if( BY2Strtoul(range_toks[1],&t_supp_elem.ss_max))
            {
                FatalError("[%s] \n",__FUNCTION__);
            }
	    
	    if(t_supp_elem.ss_min > t_supp_elem.ss_max)
	    {
		FatalError("[%s()], Min greater than max, invalid range [%s] \n",
			   __FUNCTION__,
			   gid_sup_toks);
	    }
	    
	    if(t_supp_elem.ss_min == t_supp_elem.ss_max)
	    {
		FatalError("[%s()], Min equal than max, invalid range [%s] \n",
			   __FUNCTION__,
			   gid_sup_toks);
	    }
	}
	else
	{
	    FatalError("element[%s] is an invalid range \n",gid_sup_toks);
	}
	
       	mSplitFree(&range_toks, range_num_toks);
	mSplitFree(&gid_toks, gid_num_toks);
	
	if(SigSuppressAddElement(BCGetSigSuppressHead(),&t_supp_elem))
	{
	    FatalError("[%s()], unrecoverable call to SigSuppressAddElement() \n",
		       __FUNCTION__);
	}
	
	ptoks++;
    }
    
    mSplitFree(&toks, num_toks);
    return;
}




#ifdef MPLS
void ConfigMaxMplsLabelChain(Barnyard2Config *bc, char *args)
{
    char *endp;
    long val = 0;

    if (bc == NULL)
        return;

    if (args != NULL)
    {
        val = strtol(args, &endp, 0);
        if ((args == endp) || *endp || (val < -1))
            val = DEFAULT_LABELCHAIN_LENGTH;
    } 
    else 
    {
        val = DEFAULT_LABELCHAIN_LENGTH;
    }

    bc->mpls_stack_depth = val;
}

void ConfigMplsPayloadType(Barnyard2Config *bc, char *args)
{
    if (bc == NULL)
        return;

    if (args != NULL)
    {
        if (strcasecmp(args, MPLS_PAYLOAD_OPT__IPV4) == 0)
        {
            bc->mpls_payload_type = MPLS_PAYLOADTYPE_IPV4;
        } 
        else if (strcasecmp(args, MPLS_PAYLOAD_OPT__IPV6) == 0)
        {
            bc->mpls_payload_type = MPLS_PAYLOADTYPE_IPV6;
        } 
        else if (strcasecmp(args, MPLS_PAYLOAD_OPT__ETHERNET) == 0)
        {
            bc->mpls_payload_type = MPLS_PAYLOADTYPE_ETHERNET;
        } 
        else 
        {
            ParseError("Non supported mpls payload type: %s.", args);
        }
    } 
    else 
    {
        bc->mpls_payload_type = DEFAULT_MPLS_PAYLOADTYPE;
    }
}
#endif

#ifdef SUP_IP6
static void ParseIpVar(Barnyard2Config *bc, char *args)
{
    char **toks;
    int num_toks;

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, "IpVar\n"););

    toks = mSplit(args, " \t", 0, &num_toks, 0);
    if (num_toks != 2)
    {
        ParseError("Missing argument to %s", toks[0]);
    }

    /* Check command line variables to see if this has already
     * been defined */
    if (cmd_line_var_list != NULL)
    {
        VarNode *tmp = cmd_line_var_list;

        while (tmp != NULL)
        {
            /* Already defined this via command line */
            if (strcasecmp(toks[0], tmp->name) == 0)
            {
                mSplitFree(&toks, num_toks);
                return;
            }

            tmp = tmp->next;
        }
    }

    DisallowCrossTableDuplicateVars(bc, toks[0], VAR_TYPE__IPVAR);
    sfvt_define(bc->ip_vartable, toks[0], toks[1]);

    mSplitFree(&toks, num_toks);
}
#else
static void ParseIpVar(Barnyard2Config *bc, char *args)
{
    ParseError("Unknown rule type: %s.", "ipvar");
}
#endif

static void ParseVar(Barnyard2Config *bc, char *args)
{
    char **toks;
    int num_toks;

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Variable\n"););

    toks = mSplit(args, " \t", 0, &num_toks, 0);
    if (num_toks != 2)
    {
        ParseError("Missing argument to %s", toks[0]);
    }

    /* Check command line variables to see if this has already
     * been defined */
    if (cmd_line_var_list != NULL)
    {
        VarNode *tmp = cmd_line_var_list;

        while (tmp != NULL)
        {
           // Already defined this via command line 
            if (strcasecmp(toks[0], tmp->name) == 0)
            {
                mSplitFree(&toks, num_toks);
                return;
            }

            tmp = tmp->next;
        }
    } 

    AddVarToTable(bc, toks[0], toks[1]);
    mSplitFree(&toks, num_toks);
}

static void AddVarToTable(Barnyard2Config *bc, char *name, char *value)
{
    VarDefine(bc, name, value);
}

void VarTablesFree(Barnyard2Config *bc)
{
    if (bc == NULL)
        return;

    if (bc->var_table != NULL)
    {
        DeleteVars(bc->var_table);
        bc->var_table = NULL;
    }

#ifdef SUP_IP6
    if (bc->ip_vartable != NULL)
    {
        sfvt_free_table(bc->ip_vartable);
        bc->ip_vartable = NULL;
    }
#endif
}

NORETURN void ParseError(const char *format, ...)
{
    char buf[STD_BUF+1];
    va_list ap;

    va_start(ap, format);
    vsnprintf(buf, STD_BUF, format, ap);
    va_end(ap);

    buf[STD_BUF] = '\0';

    if (file_name != NULL)
        FatalError("%s(%d) %s\n", file_name, file_line, buf);
    else
        FatalError("%s\n", buf);
}

void ParseMessage(const char *format, ...)
{
    char buf[STD_BUF+1];
    va_list ap;

    va_start(ap, format);
    vsnprintf(buf, STD_BUF, format, ap);
    va_end(ap);

    buf[STD_BUF] = '\0';

    if (file_name != NULL)
        LogMessage("%s(%d) %s\n", file_name, file_line, buf);
    else
        LogMessage("%s\n", buf);
}

// the presence of ip lists exceeds mSplit's one-level parsing
// so we transform rule string into something that mSplit can
// handle by changing ',' to c outside ip lists.
// we also strip the leading keyword.
char* FixSeparators (char* rule, char c, const char* err)
{
    int list = 0;
    char* p = strchr(rule, c); 

    if ( p && err )
    {   
        FatalError("%s(%d) => %s: '%c' not allowed in argument\n",
            file_name, file_line, err, c); 
    }   
    while ( isspace((int)*rule) ) rule++;

    p = rule;

    while ( *p ) { 
        if ( *p == '[' ) list++;
        else if ( *p == ']' ) list--;
        else if ( *p == ',' && !list ) *p = c;
        p++;
    }   
    return rule;
}

void GetNameValue (char* arg, char** nam, char** val, const char* err)
{
    while ( isspace((int)*arg) ) arg++;
    *nam = arg;

    while ( *arg && !isspace((int)*arg) ) arg++;
    if ( *arg ) *arg++ = '\0';
    *val = arg;

    if ( err && !**val )
    {   
        FatalError("%s(%d) => %s: name value pair expected: %s\n",
            file_name, file_line, err, *nam);
    }   
}

