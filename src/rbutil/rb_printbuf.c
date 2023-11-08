/*
 * $Id: printbuf.c,v 1.5 2006/01/26 02:16:28 mclark Exp $
 *
 * Copyright (c) 2004, 2005 Metaparadigm Pte. Ltd.
 * Michael Clark <michael@metaparadigm.com>
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See COPYING for details.
 *
 *
 * Copyright (c) 2008-2009 Yahoo! Inc.  All rights reserved.
 * The copyrights to the contents of this file are licensed under the MIT License
 * (http://www.opensource.org/licenses/mit-license.php)
 */

 /*
  * REDBORDER MODS:
  *  + Changed default starting buffer (from 32 to 2048)
  */

#define _GNU_SOURCE /* vasprintf */

#include "config.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdarg.h>

//#include "bits.h"
#ifndef _bits_h_
#define _bits_h_

#ifndef json_min
#define json_min(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef json_max
#define json_max(a,b) ((a) > (b) ? (a) : (b))
#endif

#define hexdigit(x) (((x) <= '9') ? (x) - '0' : ((x) & 7) + 9)
#define error_ptr(error) ((void*)error)
#define error_description(error) (json_tokener_errors[error])
#define is_error(ptr) (ptr == NULL)

#endif

//#include "debug.h"
#include "rb_printbuf.h"


static int printbuf_extend(struct printbuf *p, int min_size);

struct printbuf* printbuf_new(struct printbuf *p)
{
  p->size = 4096;
  p->bpos = 0;
  if(!(p->buf = (char*)malloc(p->size))) {
    return NULL;
  }
  return p;
}


/**
 * Extend the buffer p so it has a size of at least min_size.
 *
 * If the current size is large enough, nothing is changed.
 *
 * Note: this does not check the available space!  The caller
 *  is responsible for performing those calculations.
 */
static int printbuf_extend(struct printbuf *p, int min_size)
{
	char *t;
	int new_size;

	if (p->size >= min_size)
		return 0;

	new_size = json_max(p->size * 2, min_size + 8);
#ifdef PRINTBUF_DEBUG
	MC_DEBUG("printbuf_memappend: realloc "
	  "bpos=%d min_size=%d old_size=%d new_size=%d\n",
	  p->bpos, min_size, p->size, new_size);
#endif /* PRINTBUF_DEBUG */
	if(!(t = (char*)realloc(p->buf, new_size)))
		return -1;
	p->size = new_size;
	p->buf = t;
	return 0;
}

int printbuf_memappend(struct printbuf *p, const char *buf, int size)
{
  if (p->size <= p->bpos + size + 1) {
    if (printbuf_extend(p, p->bpos + size + 1) < 0)
      return -1;
  }
  memcpy(p->buf + p->bpos, buf, size);
  p->bpos += size;
  p->buf[p->bpos]= '\0';
  return size;
}

int printbuf_memappend_escaped(struct printbuf *p, const char *buf, int size)
{
	const int bsize = p->bpos;
	/// @TODO we can avoid this copy if we don't use strcspn
	char *aux_buf = calloc(size + 1,1);
	if (NULL == aux_buf) {
		return 0; /* We did our best! */
	}

	memcpy(aux_buf, buf, size);

	static const char escape_this[] = "\\\""
		"\x19\x18\x17\x16\x15\x14\x13\x12\x11\x10"
		"\x09\x08\x07\x06\x05\x04\x03\x02\x01";
	const char *cursor = aux_buf;
	while (1) {
		const size_t span = strcspn(cursor, escape_this);
		printbuf_memappend_fast(p, cursor, span);
		cursor += span;
		if (!(cursor < aux_buf + size)) {
			break;
		}

		/* We are in a character we need to escape */
		printbuf_memappend_fast_str(p, "\\");
		switch(cursor[0]) {
		case '\\':
		case '"':
			printbuf_memappend_fast(p, cursor, 1);
			break;
		default: /* Control code */
			printbuf_memappend_fast_str(p, "u00");
			printbuf_memappend_fast_n16(p, cursor[0]);
			break;
		};
		cursor++;
	}

	free(aux_buf);

	return p->bpos - bsize;
}


int printbuf_memset(struct printbuf *pb, int offset, int charvalue, int len)
{
	int size_needed;

	if (offset == -1)
		offset = pb->bpos;
	size_needed = offset + len;
	if (pb->size < size_needed)
	{
		if (printbuf_extend(pb, size_needed) < 0)
			return -1;
	}

	memset(pb->buf + offset, charvalue, len);
	if (pb->bpos < size_needed)
		pb->bpos = size_needed;

	return 0;
}

int sprintbuf(struct printbuf *p, const char *msg, ...)
{
  va_list ap;
  char *t;
  int size;
  char buf[128];

  /* user stack buffer first */
  va_start(ap, msg);
  size = vsnprintf(buf, 128, msg, ap);
  va_end(ap);
  /* if string is greater than stack buffer, then use dynamic string
     with vasprintf.  Note: some implementation of vsnprintf return -1
     if output is truncated whereas some return the number of bytes that
     would have been written - this code handles both cases. */
  if(size == -1 || size > 127) {
    va_start(ap, msg);
    if((size = vasprintf(&t, msg, ap)) < 0) { va_end(ap); return -1; }
    va_end(ap);
    printbuf_memappend(p, t, size);
    free(t);
    return size;
  } else {
    printbuf_memappend(p, buf, size);
    return size;
  }
}

void printbuf_reset(struct printbuf *p)
{
  p->buf[0] = '\0';
  p->bpos = 0;
}

void printbuf_free(struct printbuf *p)
{
  if(p) {
    free(p->buf);
    free(p);
  }
}
