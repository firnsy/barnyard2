/****************************************************************************
 *
 * Copyright (C) 2013 Eneo Tecnologia S.L.
 * Author: Eugenio Perez <eupm90@gmail.com>
 * Based on sf_text source. 
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
 * @author Eugenio Perez <eupm90@gmail.com>
 * based on the Russ Combs's sf_kafka.c <rcombs@sourcefire.com>
 * @date   
 * 
 * @brief  implements buffered text stream for logging
 *
 * Api for buffered logging and send to an Apache Kafka
 * Server. This allows unify the way to write json in a file and sending to
 * kafka using TextLog_sf.
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

#define KAFKA_MESSAGES_QUEUE_MAXLEN (25*1024*1024)

/*-------------------------------------------------------------------
 * TextLog_Open/Close: open/close associated log file
 *-------------------------------------------------------------------
 */
#ifdef JSON_KAFKA
rd_kafka_t* KafkaLog_Open (const char* name)
{
    if ( !name ) return NULL;
    rd_kafka_t * kafka_handle = rd_kafka_new(RD_KAFKA_PRODUCER, name, NULL);
    if(NULL == kafka_handle){
        perror("kafka_new producer");
        FatalError("There was impossible to allocate a kafka handle.");
    }else{
        kafka_handle->rk_conf.producer.max_outq_msg_cnt = KAFKA_MESSAGES_QUEUE_MAXLEN;
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
#endif

/*-------------------------------------------------------------------
 * KafkaLog_Init: constructor
 * If open=1, will create kafka handler. If not, KafkaLog->handler returned from this function
 * will be null. 
 * This is useful for the rd_kafka_new work way, cause it throws a new thread
 * to queue messages. If we are in daemon mode, the thread will be created before the fork(),
 * and we cannot communicate the message to the queue again.
 *-------------------------------------------------------------------
 */
KafkaLog* KafkaLog_Init (
    const char* broker, unsigned int maxBuf, const char * topic, const int partition, bool open,
    const char*filename
) {
    KafkaLog* this;

    this = (KafkaLog*)malloc(sizeof(KafkaLog));
    #ifdef JSON_KAFKA
    if(this){
        this->buf = malloc(sizeof(char)*maxBuf);

        if ( !this->buf)
        {
            FatalError("Unable to allocate a buffer for KafkaLog(%u)!\n", maxBuf);
        }
    }else{
        FatalError("Unable to allocate KafkaLog!\n");
    }
    this->broker = broker ? SnortStrdup(broker) : NULL;
    this->topic = topic ? SnortStrdup(topic) : NULL;
    this->handler = open ? KafkaLog_Open(this->broker):NULL;

    this->maxBuf = maxBuf;
    #endif
    this->textLog = NULL; /* Force NULL by now */
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
    #ifdef JSON_KAFKA
    KafkaLog_Close(this->handler);
    free(this->buf);

    if ( this->broker ) free(this->broker);
    #endif

    if(this->textLog) TextLog_Term(this->textLog);
    free(this);
}


/*-------------------------------------------------------------------
 * KafkaLog_Flush: send buffered stream to a kafka server 
 *-------------------------------------------------------------------
 */
bool KafkaLog_Flush(KafkaLog* this)
{
    #if JSON_KAFKA
    if ( !this->pos ) return FALSE;

    // In daemon mode, we must start the handler here
    if(this->handler==NULL && BcDaemonMode()){
	this->handler = KafkaLog_Open(this->broker);
	if(!this->handler)
	   FatalError("There was not possible to solve %s direction",this->broker);
    }

    /* This if prevent the memory overflow if the server is down */
    if(this->handler->rk_state == RD_KAFKA_STATE_DOWN)
	free(this->buf);
    else
        rd_kafka_produce(this->handler, this->topic, 0, RD_KAFKA_OP_F_FREE, this->buf, this->pos);
    this->buf = malloc(sizeof(char)*this->maxBuf);

    #endif
    if(this->textLog) TextLog_Flush(this->textLog);

    KafkaLog_Reset(this);
    return TRUE;
}

/*-------------------------------------------------------------------
 * KafkaLog_Putc: append char to buffer
 *-------------------------------------------------------------------
 */
bool KafkaLog_Putc (KafkaLog* this, char c)
{
    #ifdef JSON_KAFKA
    if ( KafkaLog_Avail(this) < 1 )
    {
        KafkaLog_Flush(this);
    }
    this->buf[this->pos++] = c;
    this->buf[this->pos] = '\0';
    #endif // JSON_KAFKA

    if(this->textLog) TextLog_Putc(this->textLog,c);
    return TRUE;
}

/*-------------------------------------------------------------------
 * KafkaLog_Write: append string to buffer
 *-------------------------------------------------------------------
 */
bool KafkaLog_Write (KafkaLog* this, const char* str, int len)
{
    #ifdef JSON_KAFKA
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

    #endif // JSON_KAFKA
    if(this->textLog) TextLog_Write(this->textLog,str,len);
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
    #ifdef JSON_KAFKA
    int currentLenght = this->maxBuf;
    #endif

    va_start(ap, fmt);
    #ifdef JSON_KAFKA
    len = vsnprintf(this->buf+this->pos, avail, fmt, ap);
    #endif
    if(this->textLog)
        vsnprintf(this->textLog->buf+this->textLog->pos, avail, fmt, ap);
    va_end(ap);

    #ifdef JSON_KAFKA
    while(len >= avail){
        // Send a half json message to Kafka has no sense, so we will try to
	// increase the buffer's lenght to allocate the full message.
	// TextLog's print will be not changed, just inlined here.
        currentLenght*=2;
	this->buf = realloc(this->buf,currentLenght);
	if(!this->buf)
	    FatalError("It was not possible to allocate a buffer");
        va_start(ap, fmt);
        len = vsnprintf(this->buf+this->pos, avail, fmt, ap);
        va_end(ap);
    }
    #endif


    // TextLog's TextLog_Print
    if ( len >= avail )
    {
        if(this->textLog) TextLog_Flush(this->textLog);
        avail = KafkaLog_Avail(this);

        va_start(ap, fmt);
        if(this->textLog)
           len = vsnprintf(this->textLog->buf+this->textLog->pos, avail, fmt, ap);
        va_end(ap);
    }
    if ( len >= avail )
    {
        if(this->textLog){
            this->textLog->pos = this->textLog->maxBuf - 1;
            this->textLog->buf[this->textLog->pos] = '\0';
        }
        // NOPE! return FALSE;
    }
    else if ( len < 0 )
    {
        // NOPE! return FALSE;
    }
    #ifdef JSON_KAFKA
    this->pos += len;
    #endif
    if(this->textLog) this->textLog->pos += len;
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
    #ifdef JSON_KAFKA
    int pos = this->pos;

    if ( KafkaLog_Avail(this) < 3 )
    {
        this->buf = realloc(this->buf,KafkaLog_Avail(this)+3); 
        if(!this->buf)
            FatalError("Could not allocate memory for KafkaLog");
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
    #endif

    if(this->textLog) TextLog_Quote(this->textLog,qs);

    return TRUE;
}

