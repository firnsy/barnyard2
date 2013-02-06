#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "barnyard2.h"
#include "debug.h"
#include "plugbase.h"
#include "unified2.h"
#include "util.h"

typedef struct spo_u2_cfg_s spo_u2_cfg_t;
typedef struct spo_u2_s     spo_u2_t;

struct spo_u2_cfg_s {
    char   basedir[PATH_MAX];
    char   filefmt[NAME_MAX]; /* file can be in TIME(1) format */
    size_t max_size;          /* maximum size the output file can grow before it rolls over */
};

struct spo_u2_s {
    spo_u2_cfg_t * config;
    FILE         * fp;
};

static int spo_u2_reload(spo_u2_t *);

static int
spo_u2_should_reload(spo_u2_t * u2) {
    struct stat statb;
    int         lock_res;
    int         res;

    if (u2->config->max_size == 0) {
        return 0;
    }

    res      = 0;

    /* attempt to flock the file, if it's already locked we don't want to reload
     * the file yet. We only reload once all processes have.
     */
    lock_res = flock(fileno(u2->fp), LOCK_EX | LOCK_NB);

    if (lock_res == EWOULDBLOCK) {
        return 0;
    }

    fstat(fileno(u2->fp), &statb);

    if (statb.st_size >= u2->config->max_size) {
        res = 1;
    }

    flock(fileno(u2->fp), LOCK_UN);

    return res;
}

static void
unified2_spo_alert(Packet * p, void * ev, u_int32_t evtype, void * arg) {
    FILE               * ofile;
    spo_u2_t           * u2;
    Unified2RecordHeader u2_hdr;

    if (!(u2 = (spo_u2_t *)arg)) {
        return;
    }

    if (spo_u2_should_reload(u2) == 1) {
        spo_u2_reload(u2);
    }

    flock(fileno(u2->fp), LOCK_EX);

    ofile       = u2->fp;
    u2_hdr.type = htonl(evtype);

    switch (evtype) {
        case UNIFIED2_PACKET:
        {
            Unified2Packet * u2pkt = (Unified2Packet *)ev;

            if (p == NULL) {
                return;
            }

            u2_hdr.length = htonl(sizeof(Unified2Packet) - 4 + ntohl(u2pkt->packet_length));

            fwrite((void *)&u2_hdr, sizeof(u2_hdr), 1, u2->fp);
            fwrite((void *)u2pkt, sizeof(Unified2Packet), 1, u2->fp);
            fwrite((void *)p->pkt, p->pkth->caplen, 1, ofile);

            return;
        }

        break;
        case UNIFIED2_IDS_EVENT:
        case UNIFIED2_IDS_EVENT_MPLS:
        case UNIFIED2_IDS_EVENT_VLAN:
        {
            Unified2IDSEvent * u2ev = (Unified2IDSEvent *)ev;

            u2_hdr.length = htonl(sizeof(Unified2IDSEvent));

            fwrite((void *)&u2_hdr, sizeof(u2_hdr), 1, ofile);
            fwrite((void *)u2ev, sizeof(Unified2IDSEvent), 1, ofile);
        }

        break;
        case UNIFIED2_IDS_EVENT_IPV6:
        case UNIFIED2_IDS_EVENT_IPV6_MPLS:
        case UNIFIED2_IDS_EVENT_IPV6_VLAN:
        {
            Unified2IDSEventIPv6 * u2ev = (Unified2IDSEventIPv6 *)ev;

            u2_hdr.length = htonl(sizeof(Unified2IDSEventIPv6));

            fwrite((void *)&u2_hdr, sizeof(u2_hdr), 1, ofile);
            fwrite((void *)u2ev, sizeof(Unified2IDSEvent), 1, ofile);
        }

        break;
        default:
            break;
    } /* switch */

    if (p != NULL) {
        Unified2Packet        u2pkt = { 0 };
        Unified2EventCommon * u2comm;

        u2comm                   = (Unified2EventCommon *)ev;

        u2pkt.sensor_id          = u2comm->sensor_id;
        u2pkt.event_id           = u2comm->event_id;
        u2pkt.event_second       = u2comm->event_second;
        u2pkt.packet_second      = htonl((uint32_t)p->pkth->ts.tv_sec);
        u2pkt.packet_microsecond = htonl((uint32_t)p->pkth->ts.tv_usec);
        u2pkt.linktype           = htonl((uint32_t)p->linktype);
        u2pkt.packet_length      = htonl((uint32_t)p->pkth->caplen);

        u2_hdr.type              = htonl(UNIFIED2_PACKET);
        u2_hdr.length            = htonl(sizeof(Unified2Packet) - 4 + p->pkth->caplen);

        fwrite((void *)&u2_hdr, sizeof(u2_hdr), 1, ofile);
        fwrite((void *)&u2pkt, sizeof(u2pkt) - 4, 1, ofile);
        fwrite((void *)p->pkt, p->pkth->caplen, 1, ofile);
    }

    fflush(ofile);
    flock(fileno(ofile), LOCK_UN);
} /* unified2_spo_alert */

static spo_u2_cfg_t *
spo_u2_cfg_new(void) {
    return (spo_u2_cfg_t *)calloc(sizeof(spo_u2_cfg_t), 1);
}

static void
spo_u2_cfg_free(spo_u2_cfg_t * cfg) {
    if (!cfg) {
        return;
    }

    free(cfg->basedir);
    free(cfg->filefmt);
    free(cfg);
}

static spo_u2_cfg_t *
unified2_spo_cfg_parse(const char * args) {
    spo_u2_cfg_t * cfg;
    char         * argcpy;
    char         * tok;
    char         * saveptr;

    if (!(cfg = spo_u2_cfg_new())) {
        return NULL;
    }

    if (args == NULL) {
        return cfg;
    }

    /* arguments are space delim key/val:
     * basedir=/tmp filefmt=strftime_fmt max_size=n
     */
    if (!(argcpy = strdup(args))) {
        spo_u2_cfg_free(cfg);
        return NULL;
    }

    tok = strtok_r(argcpy, " ", &saveptr);

    while (tok != NULL) {
        char * key;
        char * val;

        key = tok;

        if (!(val = strchr(tok, '='))) {
            /* TODO: error here */
            tok = strtok_r(NULL, " ", &saveptr);
            continue;
        }

        /* skip past the '=' and \0 terminate it so we can parse the key */
        *val++ = '\0';

        if (strcasecmp(key, "basedir") == 0) {
            if (strlen(val) >= sizeof(cfg->basedir)) {
                errno = ENAMETOOLONG;
                spo_u2_cfg_free(cfg);
                return NULL;
            }

            strncpy(cfg->basedir, val, sizeof(cfg->basedir));
        } else if (strcasecmp(key, "filefmt") == 0) {
            if (strlen(val) >= sizeof(cfg->filefmt)) {
                errno = ENAMETOOLONG;
                spo_u2_cfg_free(cfg);
                return NULL;
            }

            strncpy(cfg->filefmt, val, sizeof(cfg->filefmt));
        } else if (strcasecmp(key, "max_size") == 0) {
            cfg->max_size = (size_t)atoll(val);
        } else {
            /* TODO: error here */
        }

        tok = strtok_r(NULL, " ", &saveptr);
    }

    free(argcpy);

    if (strlen(cfg->basedir) == 0 && strlen(cfg->filefmt) == 0) {
        /* we default to /dev/stdout */
        strncpy(cfg->basedir, "/dev", sizeof(cfg->basedir));
        strncpy(cfg->filefmt, "stdout", sizeof(cfg->filefmt));
    }

    return cfg;
} /* unified2_spo_cfg_parse */

static spo_u2_t *
spo_u2_new(spo_u2_cfg_t * config) {
    spo_u2_t * u2;

    if (!config) {
        return NULL;
    }

    if (!(u2 = calloc(sizeof(spo_u2_t), 1))) {
        return NULL;
    }

    u2->config = config;

    return u2;
}

static void
spo_u2_free(spo_u2_t * u2) {
    if (!u2) {
        return;
    }

    spo_u2_cfg_free(u2->config);

    if (u2->fp) {
        fclose(u2->fp);
    }

    free(u2);
}

static void
unified2_spo_init(char * args) {
    spo_u2_cfg_t * config;
    spo_u2_t     * u2;

    if (!(config = unified2_spo_cfg_parse(args))) {
        /* TODO: OMG ERROR */
        return;
    }

    if (!(u2 = spo_u2_new(config))) {
        spo_u2_cfg_free(config);
        /* TODO: OMG ERROR */
        return;
    }

    if (spo_u2_reload(u2) == -1) {
        /* TODO: OMG ERROR */
    }

    AddFuncToOutputList(unified2_spo_alert, OUTPUT_TYPE__ALERT, u2);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Output: Unified2 initialized\n"); );
}

void
unified2_spo_setup(void) {
    RegisterOutputPlugin("unified2_output",
                         OUTPUT_TYPE_FLAG__ALERT,
                         unified2_spo_init);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Output: Unified2 is setup\n"); );
}

static int
spo_u2_reload(spo_u2_t * u2) {
    FILE      * old_fp;
    FILE      * new_fp;
    char      * outfile;
    time_t      ctime;
    struct tm * ltime;
    char        fname[NAME_MAX];
    size_t      outsz;
    int         sres;

    if (!u2) {
        return -1;
    }

    ctime         = time(NULL);
    ltime         = localtime(&ctime);

    /* we want to write files just by the epoch minus minute/second */
    ltime->tm_sec = 0;
    ltime->tm_min = 0;

    /* create the proper filename from the format */
    strftime(fname, sizeof(fname), u2->config->filefmt, ltime);

    /* concat basedir with file <basedir>/<filename>\0 */
    outsz = strlen(u2->config->basedir) + 1 + strlen(fname) + 1;

    if (!(outfile = malloc(outsz))) {
        /* TODO: error here, don't rotate for now */
        return 0;
    }

    sres = snprintf(outfile, outsz, "%s/%s", u2->config->basedir, fname);

    if (sres >= outsz || sres < 0) {
        /* TODO error here, just don't rotate for now */
        free(outfile);
        return -1;
    }

    old_fp = u2->fp;
    new_fp = fopen(outfile, "a");

    if (new_fp == NULL) {
        /* TODO error here, just don't rotate for now */
        free(outfile);
        return -1;
    }

    if (old_fp) {
        fclose(old_fp);
    }

    u2->fp = new_fp;

    return 0;
} /* spo_u2_reload */

