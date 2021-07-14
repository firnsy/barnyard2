/* $Id$ */
/*
** Copyright (C) 2002-2009 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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


#ifndef DEBUG_H
#define DEBUG_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WIN32
#define INLINE __inline
#else /* WIN32 */
#define INLINE inline
#endif /* WIN32 */

#include <ctype.h>
#ifdef HAVE_WCHAR_H
/* ISOC99 is defined to get required prototypes */
#ifndef __USE_ISOC99
#define __USE_ISOC99
#endif
#include <wchar.h>
#endif

#define DEBUG_VARIABLE "BARNYARD2_DEBUG"

#define DEBUG_ALL                   0xffffffff  /* 4294967295 */
#define DEBUG_INIT                  0x00000001  /* 1 */
#define DEBUG_CONFIGRULES           0x00000002  /* 2 */
#define DEBUG_PLUGIN                0x00000004  /* 4 */
#define DEBUG_VARS                  0x00000010  /* 16 */
#define DEBUG_LOG                   0x00000020  /* 32 */
#define DEBUG_FLOW		    0x00000040
#define DEBUG_DECODE		    0x00000080
#define DEBUG_DATALINK		    0x00000100
#define DEBUG_INPUT_PLUGIN	    0x00000200
#define DEBUG_OUTPUT_PLUGIN	    0x00000400
#define DEBUG_SPOOLER		    0x00000800
#define DEBUG_MAPS                  0x00001000  
#define DEBUG_MAPS_DEEP             0x00002000  
#define DEBUG_PATTERN_MATCH         0x00080000  
#define DEBUG_SID_SUPPRESS          0x00100000
#define DEBUG_SID_SUPPRESS_PARSE    0x00200000

void DebugMessageFunc(int dbg,char *fmt, ...);
#ifdef HAVE_WCHAR_H
void DebugWideMessageFunc(int dbg,wchar_t *fmt, ...);
#endif

#ifdef DEBUG

    extern char *DebugMessageFile;
    extern int DebugMessageLine;

    #define    DebugMessage    DebugMessageFile = __FILE__; DebugMessageLine = __LINE__; DebugMessageFunc
    #define    DebugWideMessage    DebugMessageFile = __FILE__; DebugMessageLine = __LINE__; DebugWideMessageFunc

    int GetDebugLevel (void);
    int DebugThis(int level);
#else 

#ifdef WIN32
/* Visual C++ uses the keyword "__inline" rather than "__inline__" */
         #define __inline__ __inline
#endif

#endif /* DEBUG */


#ifdef DEBUG
#define DEBUG_WRAP(code) code
void DebugMessageFunc(int dbg,char *fmt, ...);
#ifdef HAVE_WCHAR_H
void DebugWideMessageFunc(int dbg,wchar_t *fmt, ...);
#endif
#else
#define DEBUG_WRAP(code)
/* I would use DebugMessage(dbt,fmt...) but that only works with GCC */

#endif

#endif /* DEBUG_H */
