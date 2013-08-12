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

#include "rb_kafka.h"
#include "log.h"
#include "util.h"
#include "assert.h"

#include "barnyard2.h"

/* some reasonable minimums */
#define MIN_BUF  (1*K_BYTES)
#define MIN_FILE (MIN_BUF)

#define KAFKA_MESSAGES_QUEUE_MAXLEN (25*1024*1024)


#ifdef HAVE_LIBRDKAFKA

/*-------------------------------------------------------------------
 * msg_delivered: just a debug function. See rdkafka library example
 *-------------------------------------------------------------------
 */
static inline void msg_delivered (rd_kafka_t *rk,
               void *payload, size_t len,
               int error_code,
               void *opaque, void *msg_opaque) {

    if (error_code)
        fprintf(stderr,"%% Message delivery failed: %s\n",
               rd_kafka_err2str(rk, error_code));
    else
        fprintf(stderr,"%% Message delivered (%zd bytes)\n", len);
}

/*-------------------------------------------------------------------
 * TextLog_Open/Close: open/close associated log file
 *-------------------------------------------------------------------
 */
#if RD_KAFKA_VERSION == 0x00080000
rd_kafka_t* KafkaLog_Open ()
#else
rd_kafka_t* KafkaLog_Open (const char* brokers)
#endif /* RD_KAFKA_VERSION */
{
    #if RD_KAFKA_VERSION == 0x00080000

    char errstr[256];
    rd_kafka_conf_t conf;
    rd_kafka_defaultconf_set(&conf);
    conf.producer.dr_cb = msg_delivered; /* debug */
    rd_kafka_t * kafka_handle = rd_kafka_new(RD_KAFKA_PRODUCER, &conf, errstr, sizeof(errstr));
    /*rd_kafka_set_log_level (kafka_handle, LOG_DEBUG);*/
    if(NULL==kafka_handle)
    {
        perror("kafka_new producer");
        FatalError("Failed to create new producer: %s\n",errstr);
    }

    #else
    if ( !brokers ) return NULL;
    rd_kafka_t * kafka_handle = rd_kafka_new(RD_KAFKA_PRODUCER, brokers, NULL);
    if(NULL == kafka_handle)
    {
        perror("kafka_new producer");
        FatalError("There was impossible to allocate a kafka handle.");
    }else{
        kafka_handle->rk_conf.producer.max_outq_msg_cnt = KAFKA_MESSAGES_QUEUE_MAXLEN;
    }

    #endif

    return kafka_handle;
}

static void KafkaLog_Close (rd_kafka_t* handle)
{
    if ( !handle ) return;

    /* Wait for messaging to finish. */
    #if RD_KAFKA_VERSION == 0x00080000
    rd_kafka_poll(handle, 0);
    #else
    while (rd_kafka_outq_len(handle) > 0 && handle->rk_state!=RD_KAFKA_STATE_DOWN)
        usleep(50000);

    /* Since there is no ack for produce messages in 0.7 
     * we wait some more for any packets to be sent.
     * This is fixed in protocol version 0.8 */
    //if (sendcnt > 0)
        usleep(500000);
    #endif

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
    const char* broker, unsigned int bufLen, const char * topic, const int start_partition, 
    const int end_partition, bool open,  const char*filename
) {
    KafkaLog* this;

    this = (KafkaLog*)SnortAlloc(sizeof(KafkaLog));
    #ifdef HAVE_LIBRDKAFKA
    if(this){
        this->buf = malloc(sizeof(char)*bufLen);

        if ( !this->buf)
        {
            FatalError("Unable to allocate a buffer for KafkaLog(%u)!\n", bufLen);
        }
    }else{
        FatalError("Unable to allocate KafkaLog!\n");
    }
    this->broker = broker ? SnortStrdup(broker) : NULL;
    this->topic = topic ? SnortStrdup(topic) : NULL;
    #ifndef RD_KAFKA_VERSION 
    this->handler = open ? KafkaLog_Open(this->broker):NULL; /* will always start in Flush */
    #endif
    
    #if RD_KAFKA_VERSION < 0x00080000

    this->start_partition = this->actual_partition = start_partition;
    this->end_partition = end_partition;


    if(this->start_partition > this->end_partition){
        FatalError("alert_json: start_partition > end_partition");
    }

    #endif

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
    if(this->handler==NULL && this->broker && this->topic)
    {
#if RD_KAFKA_VERSION == 0x00080000

        this->handler = KafkaLog_Open();
        if(!this->handler)
            FatalError("It was not possible create a kafka handler\n",this->broker);
        rd_kafka_topic_conf_t topic_conf;
        rd_kafka_topic_defaultconf_set(&topic_conf);
        this->rkt = rd_kafka_topic_new(this->handler, this->topic, &topic_conf);
	if(NULL==this->rkt)
            FatalError("It was not possible create a kafka topic %s\n",this->topic);
        if (rd_kafka_brokers_add(this->handler, this->broker) == 0) 
            FatalError("Kafka: No valid brokers specified in %s\n",this->broker);

#else

        this->handler = KafkaLog_Open(this->broker);
        if(!this->handler)
           FatalError("There was not possible to solve %s direction",this->broker);

#endif /* RD_KAFKA_VERSION*/
    }

    /* rd_kafka_dump(stdout,this->handler); */

    #if RD_KAFKA_VERSION == 0x00080000


    rd_kafka_produce(this->rkt, RD_KAFKA_PARTITION_UA,
                     RD_KAFKA_MSG_F_FREE,
                     /* Payload and length */
                     this->buf, this->pos,
                     /* Optional key and its length */
                     NULL, 0,
                     /* Message opaque, provided in
                      * delivery report callback as
                      * msg_opaque. */
                     NULL);
    /* Poll to handle delivery reports */
    rd_kafka_poll(this->handler, 10);

    #else

    this->actual_partition++;
    if(this->actual_partition>this->end_partition)
        this->actual_partition=this->start_partition;
    /* This if prevent the memory overflow if the server is down */
    if(this->handler->rk_state == RD_KAFKA_STATE_DOWN)
        free(this->buf);
    else
        rd_kafka_produce(this->handler, this->topic, this->actual_partition, RD_KAFKA_OP_F_FREE, this->buf, this->pos);

    #endif

    this->buf = SnortAlloc(sizeof(char)*this->start_bufLen);
    this->bufLen = this->start_bufLen;

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

