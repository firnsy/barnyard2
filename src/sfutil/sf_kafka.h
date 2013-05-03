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
 * @file   sf_kafka.h
 * @author Russ Combs <cmg@sourcefire.com>
 * @date   Fri Jun 27 10:34:37 2003
 * 
 * @brief  declares buffered text stream for logging
 * 
 * Declares a TextLog_*() api for buffered logging.  This allows
 * relatively painless transition from fprintf(), fwrite(), etc.
 * to a buffer that is formatted in memory and written with one
 * fwrite().
 *
 * Additionally, the file is capped at a maximum size.  Beyond
 * that, the file is closed, renamed, and reopened.  The current
 * file always has the same name.  Old files are renamed to that
 * name plus a timestamp.
 */

#ifndef _SF_KAFKA_LOG_H
#define _SF_KAFKA_LOG_H

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "debug.h" /* for INLINE */
#include "kafka/rdkafka.h"


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
/* private: */
/* broker attributes: */
    rd_kafka_t * handler;
    char* broker;
    char * topic;
    int partition;


/* buffer attributes: */
    unsigned int pos;
    unsigned int maxBuf;
    char auxbuf[KAFKA_AUXBUF_SIZE];
    char * buf;
} KafkaLog;

KafkaLog* KafkaLog_Init (
    const char* broker, unsigned int maxBuf, const char * topic, const int partition, bool open
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
     return this->pos;
 }
 
 static INLINE int KafkaLog_Avail (KafkaLog* this)
 {
     return this->maxBuf - this->pos - 1;
 }
 
 static INLINE void KafkaLog_Reset (KafkaLog* this)
 {   
     this->pos = 0;
     this->buf[this->pos] = '\0';
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

