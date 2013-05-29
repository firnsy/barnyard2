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
 * @file   sf_kafka.h
 * @author Eugenio Pérez <eupm90@gmail.com>
 * @date   Wed May 29 2013
 * 
 * @brief  declares buffered text stream for logging
 * Based on sf_text source.
 * 
 * Declares a KafkaLog_*() api for buffered logging and send to an Apache Kafka
 * Server. This allows unify the way to write json in a file and sending to
 * kafka using TextLog_sf.
 */

#ifndef _SF_KAFKA_LOG_H
#define _SF_KAFKA_LOG_H

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "debug.h" /* for INLINE */
#include "sf_textlog.h"
#ifdef JSON_KAFKA
#include "kafka/rdkafka.h"
#endif


#include <stdio.h>
#include <string.h>
#include <time.h>

#include "debug.h" /* for INLINE */

#ifndef _SF_TEXT_LOG_H // already defined in
typedef int bool;
#define TRUE 1
#define FALSE 0

#define K_BYTES (1024)
#define M_BYTES (K_BYTES*K_BYTES)
#define G_BYTES (K_BYTES*M_BYTES)
#endif


#define KAFKA_AUXBUF_SIZE 4096

/*
 * DO NOT ACCESS STRUCT MEMBERS DIRECTLY
 * EXCEPT FROM WITHIN THE IMPLEMENTATION!
 */
typedef struct _KafkaLog
{
#ifdef JSON_KAFKA
/* private: */
/* broker attributes: */
    rd_kafka_t * handler;
    char* broker;
    char * topic;
    int partition;


/* buffer attributes: */
    unsigned int pos;
    unsigned int maxBuf;
    char * buf;
#endif
/* TextLog helper. Useful for loggind and just send data to a json file */
    TextLog * textLog;
} KafkaLog;

KafkaLog* KafkaLog_Init (
    const char* broker, unsigned int maxBuf, const char * topic, const int partition, bool open, const char *filename
);
void KafkaLog_Term (KafkaLog* this);

bool KafkaLog_Putc(KafkaLog*, char);
bool KafkaLog_Quote(KafkaLog*, const char*);
bool KafkaLog_Write(KafkaLog*, const char*, int len);
bool KafkaLog_Print(KafkaLog*, const char* format, ...);

bool KafkaLog_Flush(KafkaLog*);

/*-------------------------------------------------------------------
  * helper functions
  *-------------------------------------------------------------------
  */
 static INLINE int KafkaLog_Tell (KafkaLog* this)
 {
    #ifndef JSON_KAFKA
    return this->textLog?this->textLog->pos:0;
    #else
    return this->pos;
    #endif
 }
 
 static INLINE int KafkaLog_Avail (KafkaLog* this)
 {
    #ifndef JSON_KAFKA
    return this->textLog?TextLog_Avail(this->textLog):0;
    #else
    return this->maxBuf - this->pos - 1;
    #endif
 }
 
 static INLINE void KafkaLog_Reset (KafkaLog* this)
 {
    if(this->textLog)
        TextLog_Reset(this->textLog);
    #ifdef JSON_KAFKA
    this->pos = 0;
    this->buf[this->pos] = '\0';
    #endif
 }

static INLINE bool KafkaLog_NewLine (KafkaLog* this)
{
    return KafkaLog_Putc(this, '\n');
}

static INLINE bool KafkaLog_Puts (KafkaLog* this, const char* str)
{
    return KafkaLog_Write(this, str, strlen(str));
}

#endif /* _SF_KAFKA_LOG_H */

