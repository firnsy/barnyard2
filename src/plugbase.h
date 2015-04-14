
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

/* $Id$ */
#ifndef __PLUGBASE_H__
#define __PLUGBASE_H__

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

//#include "rules.h"
#include "sf_types.h"
#include "debug.h"

#ifndef WIN32
#  include <sys/ioctl.h>
#endif  /* !WIN32 */

#ifdef ENABLE_SSL
#  ifdef Free
/* Free macro in radix.h if defined, will conflict with OpenSSL definition */
#    undef Free
#  endif
#endif

#if defined(FREEBSD) || defined(OPENBSD)
#  include <sys/socket.h>
#endif

#if !defined(__SOLARIS__) && !defined(__CYGWIN32__) && !defined(__CYGWIN__) && \
    !defined( __CYGWIN64__)
#include <net/route.h>
#endif

#ifdef ENABLE_SSL
#  undef Free
#endif

#if defined(SOLARIS) || defined(FREEBSD) || defined(OPENBSD)
#  include <sys/param.h>
#endif

#if defined(FREEBSD) || defined(OPENBSD) || defined(NETBSD) || defined(OSF1)
#  include <sys/mbuf.h>
#endif

#ifndef IFNAMSIZ /* IFNAMSIZ is defined in all platforms I checked.. */
#  include <net/if.h>
#endif

#include "decode.h"

#define SMALLBUFFER 32

typedef enum _InputType
{
    INPUT_TYPE__UNIFIED_LOG = 1,
    INPUT_TYPE__UNIFIED_ALERT,
	INPUT_TYPE__UNIFIED,
    INPUT_TYPE__UNIFIED2,
	INPUT_TYPE__MAX

} InputType;

typedef enum _OutputType
{
    OUTPUT_TYPE__ALERT = 1,
    OUTPUT_TYPE__LOG,
	OUTPUT_TYPE__SPECIAL,
#ifdef RB_EXTRADATA
    OUTPUT_TYPE__MAX,
    OUTPUT_TYPE__EXTRA_DATA
#else
    OUTPUT_TYPE__MAX
#endif

} OutputType;

typedef enum _OutputTypeFlag
{
    OUTPUT_TYPE_FLAG__ALERT = 0x00000001,
    OUTPUT_TYPE_FLAG__LOG   = 0x00000002,
    OUTPUT_TYPE_FLAG__ALL   = 0x7fffffff

} OutputTypeFlag;


/***************************** Input Plugin API  ******************************/
typedef void (*InputConfigFunc)(char *);
typedef int (*InputReadHeaderFunc)(void *);
typedef int (*InputReadRecordFunc)(void *);

typedef struct _InputConfigFuncNode
{
    char *keyword;
    InputConfigFunc func;
    struct _InputConfigFuncNode *next;

} InputConfigFuncNode;

typedef struct _InputFuncNode
{
    char *keyword;
	int					        configured_flag;

    void *arg;
	int (*readRecordHeader)(void *);
	int (*readRecord)(void *);

    struct _InputFuncNode   *next;
} InputFuncNode;

void RegisterInputPlugins(void);
void InitInputPlugins();
int ActivateInputPlugin(char *plugin_name, char *plugin_options);
void RegisterInputPlugin(char *, InputConfigFunc);
InputConfigFunc GetInputConfigFunc(char *);
InputFuncNode *GetInputPlugin(char *);
void DumpInputPlugins();
int AddArgToInputList(char *plugin_name, void *arg);

int AddReadRecordHeaderFuncToInputList(char *plugin_name, int (*readRecordHeader)(void *));
int AddReadRecordFuncToInputList(char *plugin_name, int (*readRecord)(void *));

int InputFuncNodeConfigured(InputFuncNode *ifn);


/***************************** Output Plugin API  *****************************/
typedef void (*OutputConfigFunc)(char *);
typedef void (*OutputFunc)(Packet *, void *, uint32_t, void *);

typedef struct _OutputConfigFuncNode
{
    char *keyword;
    int output_type_flags;
    OutputConfigFunc func;
    struct _OutputConfigFuncNode *next;

} OutputConfigFuncNode;

typedef struct _OutputFuncNode
{
    void *arg;
    OutputFunc func;
    struct _OutputFuncNode *next;

} OutputFuncNode;

void RegisterOutputPlugins(void);
void RegisterOutputPlugin(char *, int, OutputConfigFunc);
OutputConfigFunc GetOutputConfigFunc(char *);
int GetOutputTypeFlags(char *);
void DumpOutputPlugins(void);
void AddFuncToOutputList(OutputFunc, OutputType, void *);
void FreeOutputConfigFuncs(void);
void FreeOutputList(OutputFuncNode *);
void CallOutputPlugins(OutputType, Packet *, void *, uint32_t);


/*************************** Miscellaneous  API  ***************************/
typedef void (*PluginSignalFunc)(int, void *);

typedef struct _PluginSignalFuncNode
{
    void *arg;
    PluginSignalFunc func;
    struct _PluginSignalFuncNode *next;

} PluginSignalFuncNode;

/* Used for both rule options and output.  Preprocessors have their own */
void AddFuncToRestartList(PluginSignalFunc, void *);
void AddFuncToCleanExitList(PluginSignalFunc, void *);
void AddFuncToShutdownList(PluginSignalFunc, void *);
void AddFuncToPostConfigList(PluginSignalFunc, void *);
void AddFuncToSignalList(PluginSignalFunc, void *, PluginSignalFuncNode **);
void PostConfigInitPlugins(PluginSignalFuncNode *);
void FreePluginSigFuncs(PluginSignalFuncNode *);
void FreeInputPlugins(void);
#endif /* __PLUGBASE_H__ */

