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
 * @file   rb_kafka.c
 * @author Eugenio Perez <eupm90@gmail.com>
 * based on the Russ Combs's sf_textlog.c <rcombs@sourcefire.com>
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
#include <errno.h>

#include "rb_kafka.h"
#include "log.h"
#include "util.h"
#include "assert.h"
#include "unistd.h"

#include "barnyard2.h"

/* branch predictions */
#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

#define RB_UNUSED __attribute__((unused))


#ifdef HAVE_LIBRDKAFKA

/*-------------------------------------------------------------------
 * msg_delivered: callback function for every message.
 *-------------------------------------------------------------------
 */
 
static inline void msg_delivered (rd_kafka_t *rk RB_UNUSED,
               void *payload RB_UNUSED, size_t len,
               int error_code,
               void *opaque RB_UNUSED, void *msg_opaque RB_UNUSED) {

    if (unlikely(error_code))
        ErrorMessage("rdkafka Message delivery failed: %s\n",rd_kafka_err2str(error_code));
    else if (unlikely(BcLogVerbose()))
        LogMessage("rdkafka Message delivered (%zd bytes)\n", len);
}

/*-------------------------------------------------------------------
 * TextLog_Open/Close: open/close associated log file
 *-------------------------------------------------------------------
 */
static void KafkaLog_Open (KafkaLog *this)
{
    char errstr[256];
    
    if(!this->rk_conf)
        FatalError("KafkaLog_Open called with NULL==this->rk_conf\n");

    if(!this->rkt_conf)
        FatalError("KafkaLog_Open called with NULL==this->rkt_conf\n");
    
    rd_kafka_conf_set_dr_cb(this->rk_conf,msg_delivered);
    this->handler = rd_kafka_new(RD_KAFKA_PRODUCER, this->rk_conf, errstr, sizeof(errstr));

    if(NULL==this->handler)
        FatalError("Failed to create new producer: %s\n",errstr);

    if (rd_kafka_brokers_add(this->handler, this->broker) == 0) 
        FatalError("Kafka: No valid brokers specified in %s\n",this->broker);

    this->rkt = rd_kafka_topic_new(this->handler, this->topic, this->rkt_conf);

    if(NULL==this->rkt)
        FatalError("It was not possible create a kafka topic %s\n",this->topic);
}

static void KafkaLog_Close (rd_kafka_t* handle)
{
    if ( !handle ) return;

    /* Wait for messaging to finish. */
    unsigned throw_msg_count = 10;
    unsigned msg_left,prev_msg_left = 0;
    while((msg_left = rd_kafka_outq_len (handle) > 0) && throw_msg_count)
    {
        if(prev_msg_left == msg_left) /* Send no messages in a second? probably, the broker has fall down */
            throw_msg_count--;
        else
            throw_msg_count = 10;
        DEBUG_WRAP(DebugMessage(DEBUG_OUTPUT_PLUGIN, 
            "[Thread %u] Waiting for messages to send. Still %u messages to be exported. %u retries left.\n"););
        prev_msg_left = msg_left;
        rd_kafka_poll(handle,100);
    }

    /* Destroy the handle */
    rd_kafka_destroy(handle);
}

#endif /* HAVE_LIBRDKAFKA */

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
    const char* broker, unsigned int bufLen, const char * topic, const char*filename
    #ifdef HAVE_LIBRDKAFKA
    ,rd_kafka_conf_t *rk_conf,rd_kafka_topic_conf_t *rkt_conf
    #endif
) {
    KafkaLog* this;

    this = (KafkaLog*)SnortAlloc(sizeof(KafkaLog));
    #ifdef HAVE_LIBRDKAFKA
    if(this){
        this->buf = SnortAlloc(sizeof(char)*bufLen);

        if ( !this->buf)
        {
            FatalError("Unable to allocate a buffer for KafkaLog(%u)!\n", bufLen);
        }
    }else{
        FatalError("Unable to allocate KafkaLog!\n");
    }
    this->broker = broker ? SnortStrdup(broker) : NULL;
    this->topic  = topic ? SnortStrdup(topic) : NULL;

    this->rk_conf  = rk_conf;
    this->rkt_conf = rkt_conf;

    this->bufLen = this->start_bufLen = bufLen;
    #endif /* HAVE_LIBRDKAFKA */
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
    #ifdef HAVE_LIBRDKAFKA
    KafkaLog_Close(this->handler);
    free(this->buf);

    if ( this->broker ) free(this->broker);
    if ( this->topic ) free(this->topic);
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
#if HAVE_LIBRDKAFKA
    if ( !this->pos ) return FALSE;

    // In daemon mode, we must start the handler here
    if(unlikely(this->handler==NULL && this->broker && this->topic))
    {
        KafkaLog_Open(this);
        if(!this->handler)
            FatalError("It was not possible create a kafka handler\n",this->broker);
    }

    /* rd_kafka_dump(stdout,this->handler); */
    int retried = 0;
    do{
        const int produce_rc = rd_kafka_produce(this->rkt, RD_KAFKA_PARTITION_UA,
                         RD_KAFKA_MSG_F_FREE,
                         /* Payload and length */
                         this->buf, this->pos,
                         /* Optional key and its length */
                         NULL, 0,
                         /* Message opaque, provided in
                          * delivery report callback as
                          * msg_opaque. */
                         NULL);
        
        if(likely(produce_rc) != -1){
            break;
        }else{
            rd_kafka_resp_err_t err = rd_kafka_errno2err(errno);
            if(err != RD_KAFKA_RESP_ERR__QUEUE_FULL || retried){
                ErrorMessage("Failed to produce message: %s",rd_kafka_err2str(err));
                free(this->buf);
                this->buf = NULL;
                break;
            }else{
                // Queue full. Backpressure.
                rd_kafka_poll(this->handler,5);
            }
        }
    }while(1);
    /* Poll to handle delivery reports */
    rd_kafka_poll(this->handler, 0);

    this->buf = SnortAlloc(sizeof(char)*this->start_bufLen);
    this->bufLen = this->start_bufLen;

#endif /* HAVE_LIBRDKAFKA */

    if(this->textLog) TextLog_Flush(this->textLog);

    KafkaLog_Reset(this);
    return TRUE;
}

bool KafkaLog_FlushAll(KafkaLog* this)
{
#if HAVE_LIBRDKAFKA
    while (rd_kafka_outq_len(this->handler) > 0)
        rd_kafka_poll(this->handler, 100);
#endif /* HAVE_LIBRDKAFKA */

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
    #ifdef HAVE_LIBRDKAFKA
    if ( KafkaLog_Avail(this) < 1 )
    {
        KafkaLog_Flush(this);
    }
    this->buf[this->pos++] = c;
    this->buf[this->pos] = '\0';
    #endif // HAVE_LIBRDKAFKA

    if(this->textLog) TextLog_Putc(this->textLog,c);
    return TRUE;
}

/*-------------------------------------------------------------------
 * KafkaLog_Write: append string to buffer
 *-------------------------------------------------------------------
 */
bool KafkaLog_Write (KafkaLog* this, const char* str, int len)
{
#ifdef HAVE_LIBRDKAFKA
    while ( len >= KafkaLog_Avail(this) )
    {
        this->bufLen*=2;
        this->buf = realloc(this->buf,this->bufLen);
        if(NULL==this->buf)
            return FALSE;
    }
    this->buf[this->pos]='\0'; /* just in case */
    strncat(this->buf+this->pos, str, len);
    this->pos += len;
    assert(this->buf[this->pos] == '\0');

#endif // HAVE_LIBRDKAFKA
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

    va_start(ap, fmt);
#ifdef HAVE_LIBRDKAFKA
    len = vsnprintf(this->buf+this->pos, avail, fmt, ap);
#endif
    if(this->textLog)
        vsnprintf(this->textLog->buf+this->textLog->pos, avail, fmt, ap);
    va_end(ap);

#ifdef HAVE_LIBRDKAFKA
    while(len >= avail){
        // Send a half json message to Kafka has no sense, so we will try to
        // increase the buffer's lenght to allocate the full message.
        // TextLog's print will be not changed, just inlined here.
        this->bufLen*=2;
        this->buf = realloc(this->buf,this->bufLen);
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
#ifdef HAVE_LIBRDKAFKA
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
#ifdef HAVE_LIBRDKAFKA
    int pos = this->pos;

    if ( KafkaLog_Avail(this) < 3 )
    {
        this->buf = realloc(this->buf,KafkaLog_Avail(this)+3); 
        if(!this->buf)
            FatalError("Could not allocate memory for KafkaLog");
    }
    this->buf[pos++] = '"';

    while ( *qs && (this->bufLen - pos > 2) )
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

