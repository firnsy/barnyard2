/****************************************************************************
 *
 * Copyright (C) 2003-2009 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 ****************************************************************************/
 
/**
 * @file   sf_kafka.c
 * @author Russ Combs <rcombs@sourcefire.com>
 * @date   
 * 
 * @brief  implements buffered text stream for logging
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "sf_kafka.h"
#include "log.h"
#include "util.h"

#include "barnyard2.h"

/* some reasonable minimums */
#define MIN_BUF  (1*K_BYTES)
#define MIN_FILE (MIN_BUF)



/*-------------------------------------------------------------------
 * TextLog_Open/Close: open/close associated log file
 *-------------------------------------------------------------------
 */
rd_kafka_t* KafkaLog_Open (const char* name)
{
    if ( !name ) return NULL;
    rd_kafka_t * kafka_handle = rd_kafka_new(RD_KAFKA_PRODUCER, name, NULL);
    if(NULL == kafka_handle){
        perror("kafka_new producer");
        FatalError("There was impossible to allocate a kafka handle.");
    }
    return kafka_handle;
}

static void KafkaLog_Close (rd_kafka_t* handle)
{
    if ( !handle ) return;

    /* Wait for messaging to finish. */
    while (rd_kafka_outq_len(handle) > 0)
        usleep(50000);

    /* Since there is no ack for produce messages in 0.7 
     * we wait some more for any packets to be sent.
     * This is fixed in protocol version 0.8 */
    //if (sendcnt > 0)
        usleep(500000);

    /* Destroy the handle */
    rd_kafka_destroy(handle);
}

/*
static size_t KafkaLog_Size (rd_kafka_t* file)
{
    
    struct stat sbuf;
    int fd = fileno(file);
    int err = fstat(fd, &sbuf);
    return err ? 0 : sbuf.st_size;
}
*/

/*-------------------------------------------------------------------
 * KafkaLog_Init: constructor
 * If open=1, will create kafka handler. If not, KafkaLog->handler returned from this function
 * will be null
 *-------------------------------------------------------------------
 */
KafkaLog* KafkaLog_Init (
    const char* broker, unsigned int maxBuf, const char * topic, const int partition, bool open
) {
    KafkaLog* this;

    this = (KafkaLog*)malloc(sizeof(KafkaLog));
    this->buf = malloc(sizeof(char)*maxBuf);

    if ( !this || !this->buf)
    {
        FatalError("Unable to allocate a KafkaLog(%u)!\n", maxBuf);
    }
    this->broker = broker ? SnortStrdup(broker) : NULL;
    this->topic = topic ? SnortStrdup(topic) : NULL;
    this->handler = open ? KafkaLog_Open(this->broker):NULL;

    this->maxBuf = maxBuf;
    KafkaLog_Reset(this);

    return this;
}

/*-------------------------------------------------------------------
 * KafkaLog_Term: destructor
 *-------------------------------------------------------------------
 */
void KafkaLog_Term (KafkaLog* this)
{
    if ( !this ) return;

    KafkaLog_Flush(this);
    KafkaLog_Close(this->handler);

    if ( this->broker ) free(this->broker);
    free(this);
}

/*-------------------------------------------------------------------
 * KafkaLog_Flush: start writing to new file
 * but don't roll over stdout or any sooner
 * than resolution of filename discriminator
 *-------------------------------------------------------------------
 */



/*-------------------------------------------------------------------
 * KafkaLog_Flush: write buffered stream to file
 *-------------------------------------------------------------------
 */
bool KafkaLog_Flush(KafkaLog* this)
{

    if ( !this->pos ) return FALSE;

    // In daemon mode, we must start the handler here
    if(this->handler==NULL && BcDaemonMode()){
        this->handler = KafkaLog_Open(this->broker);
    }
    if(this->handler->rk_state == RD_KAFKA_STATE_DOWN)
	free(this->buf);
    else
        rd_kafka_produce(this->handler, this->topic, 0, RD_KAFKA_OP_F_FREE, this->buf, this->pos);
    this->buf = malloc(sizeof(char)*this->maxBuf);

    KafkaLog_Reset(this);
    return TRUE;
}

/*-------------------------------------------------------------------
 * KafkaLog_Putc: append char to buffer
 *-------------------------------------------------------------------
 */
bool KafkaLog_Putc (KafkaLog* this, char c)
{
    if ( KafkaLog_Avail(this) < 1 )
    {
        KafkaLog_Flush(this);
    }
    this->buf[this->pos++] = c;
    this->buf[this->pos] = '\0';

    return TRUE;
}

/*-------------------------------------------------------------------
 * KafkaLog_Write: append string to buffer
 *-------------------------------------------------------------------
 */
bool KafkaLog_Write (KafkaLog* this, const char* str, int len)
{
    int avail = KafkaLog_Avail(this);

    if ( len >= avail )
    {
        KafkaLog_Flush(this);
        avail = KafkaLog_Avail(this);
    }
    len = snprintf(this->buf+this->pos, avail, "%s", str);

    if ( len >= avail )
    {
        this->pos = this->maxBuf - 1;
        this->buf[this->pos] = '\0';
        return FALSE;
    }
    else if ( len < 0 )
    {
        return FALSE;
    }
    this->pos += len;
    return TRUE;
}

/*-------------------------------------------------------------------
 * KafkaLog_Printf: append formatted string to buffer
 *-------------------------------------------------------------------
 */
bool KafkaLog_Print (KafkaLog* this, const char* fmt, ...)
{
    int avail = KafkaLog_Avail(this);
    int len;
    va_list ap;

    va_start(ap, fmt);
    len = vsnprintf(this->buf+this->pos, avail, fmt, ap);
    va_end(ap);

    if ( len >= avail )
    {
        KafkaLog_Flush(this);
        avail = KafkaLog_Avail(this);

        va_start(ap, fmt);
        len = vsnprintf(this->buf+this->pos, avail, fmt, ap);
        va_end(ap);
    }
    if ( len >= avail )
    {
        this->pos = this->maxBuf - 1;
        this->buf[this->pos] = '\0';
        return FALSE;
    }
    else if ( len < 0 )
    {
        return FALSE;
    }
    this->pos += len;
    return TRUE;
}

/*-------------------------------------------------------------------
 * KafkaLog_Quote: write string escaping quotes
 * FIXTHIS could be smarter by counting required escapes instead of
 * checking for 3
 *-------------------------------------------------------------------
 */
bool KafkaLog_Quote (KafkaLog* this, const char* qs)
{
    int pos = this->pos;

    if ( KafkaLog_Avail(this) < 3 )
    {
        KafkaLog_Flush(this);
    }
    this->buf[pos++] = '"';

    while ( *qs && (this->maxBuf - pos > 2) )
    {
        if ( *qs == '"' || *qs == '\\' )
        {
            this->buf[pos++] = '\\';
        }
        this->buf[pos++] = *qs++;
    }
    if ( *qs ) return FALSE;

    this->buf[pos++] = '"';
    this->pos = pos;

    return TRUE;
}

