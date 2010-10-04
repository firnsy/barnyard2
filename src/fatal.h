/* $Id$ */
/*
** Copyright (C) 2002-2008 Sourcefire, Inc.
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

#ifndef __FATAL_H__
#define __FATAL_H__


/*
 * in debugging mode print out the filename and the line number where the
 * failure have occured
 */


#ifdef DEBUG
	#define	FATAL(msg) 	{ printf("%s:%d: ", __FILE__, __LINE__); FatalError( (char *) msg); }
#else
	#define	FATAL(msg)	FatalError( (char *) msg)
#endif



#endif	/* __FATAL_H__ */
