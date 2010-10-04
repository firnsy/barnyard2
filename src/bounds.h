#ifndef _BOUNDS_H
#define _BOUNDS_H
/*
** Copyright (C) 2003-2009 Sourcefire, Inc.
**               Chris Green <cmg@sourcefire.com>
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
**
*/


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef OSF1
#include <sys/bitypes.h>
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <assert.h>
#include <unistd.h>

#define SAFEMEM_ERROR 0
#define SAFEMEM_SUCCESS 1

#include "debug.h"
#ifndef DEBUG
    #define ERRORRET return SAFEMEM_ERROR;
#else
    #define ERRORRET assert(0==1)
#endif /* DEBUG */

#include "sf_types.h"


/*
 * Check to make sure that p is less than or equal to the ptr range
 * pointers
 *
 * 1 means it's in bounds, 0 means it's not
 */
static INLINE int inBounds(const uint8_t *start, const uint8_t *end, const uint8_t *p)
{
    if(p >= start && p < end)
    {
        return 1;
    }
    
    return 0;
}

/** 
 * A Safer Memcpy
 * 
 * @param dst where to copy to
 * @param src where to copy from
 * @param n number of bytes to copy
 * @param start start of the dest buffer
 * @param end end of the dst buffer
 * 
 * @return 0 on failure, 1 on success
 */
static INLINE int SafeMemcpy(void *dst, const void *src, size_t n, const void *start, const void *end)
{
    void *tmp;

    if(n < 1)
    {
        ERRORRET;
    }

    if (!dst || !src || !start || !end)                                                                         
    {
        ERRORRET;
    }

    tmp = ((uint8_t*)dst) + (n-1);
    if (tmp < dst)
    {
        ERRORRET;
    }

    if(!inBounds(start,end, dst) || !inBounds(start,end,tmp))
    {
        ERRORRET;
    }

    memcpy(dst, src, n);

    return SAFEMEM_SUCCESS;
}

/**
 * A Safer Memmove
 * dst and src can be in the same buffer
 *
 * @param dst where to copy to
 * @param src where to copy from
 * @param n number of bytes to copy
 * @param start start of the dest buffer
 * @param end end of the dst buffer
 *
 * @return 0 on failure, 1 on success
 */
static INLINE int SafeMemmove(void *dst, const void *src, size_t n, const void *start, const void *end)         
{
    void *tmp;
    
    if(n < 1)
    {
        ERRORRET;
    }

    if (!dst || !src || !start || !end)
    {
        ERRORRET;
    }

    tmp = ((uint8_t*)dst) + (n-1);
    if (tmp < dst)
    {
        ERRORRET;
    }

    if(!inBounds(start,end, dst) || !inBounds(start,end,tmp))
    {
        ERRORRET;
    }

    memmove(dst, src, n);

    return SAFEMEM_SUCCESS;
}

/** 
 * A Safer *a = *b
 * 
 * @param start start of the dst buffer
 * @param end end of the dst buffer
 * @param dst the location to write to
 * @param src the source to read from
 * 
 * @return 0 on failure, 1 on success
 */
static INLINE int SafeWrite(uint8_t *start, uint8_t *end, uint8_t *dst, uint8_t *src)
{
    if(!inBounds(start, end, dst))
    {
        ERRORRET;
    }
     
    *dst = *src;        
    return 1;
}

static INLINE int SafeRead(uint8_t *start, uint8_t *end, uint8_t *src, uint8_t *read)
{
    if(!inBounds(start,end, src))
    {
        ERRORRET;
    }
    
    *read = *start;
    return 1;
}

#endif /* _BOUNDS_H */
