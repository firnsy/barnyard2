/*

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

/*
 *  Maintainers : The Barnyard2 Team <firnsy@gmail.com> <beenph@gmail.com> 2011-2012
 *
 *    Special thanks to: Rusell Fuleton <russell.fulton@gmail.com> for helping us stress test
 *                       this in production for us.
 *
 *
 */



#ifndef __SPO_DATABASE_CACHE_H__
#define __SPO_DATABASE_CACHE_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "barnyard2.h"
#include "debug.h"
#include "map.h"
#include "unified2.h"


#ifndef CLASS_NAME_LEN
#define CLASS_NAME_LEN 60
#endif  /* CLASS_NAME_LEN */

#ifndef SYSTEM_NAME_LEN 
#define SYSTEM_NAME_LEN 20
#endif /* SYSTEM_NAME_LEN */

#ifndef SYSTEM_URL_LEN 
#define SYSTEM_URL_LEN 255 /* Use a shortener if your not happy ;) */
#endif /* SYSTEM_URL_LEN */

#ifndef REF_TAG_LEN 
#define REF_TAG_LEN 255 /* fix some issue with some ruleset */
#endif /* REF_TAG_LEN */

#ifndef SIG_NAME_LEN
#define SIG_NAME_LEN 42
#endif /* SIG_NAME_LEN */

#ifndef SIG_MSG_LEN
#define SIG_MSG_LEN 255
#endif /* SIG_MSG_LEN */

#ifndef MAX_REF_OBJ
#define MAX_REF_OBJ 255
#endif /* MAX_REF_OBJ */

#ifndef CACHE_SQL_QUERY
#define CACHE_SQL_QUERY 

#define NUM_ROW_SIGREF 3
#define NUM_ROW_REFERENCE_SYSTEM 2
#define NUM_ROW_REF 3
#define NUM_ROW_CLASSIFICATION 2
#define NUM_ROW_SIGNATURE 7

/*
#if defined(ENABLE_POSTGRESQL)

** Note : ELZ
**
** Initially i tought that using E'' would escape some issue. 
** It turns out it would also create other issue like automatically
** encode special sequence and its not a good thing since in initial testing non of the signature has such char, but it turned out
** some had and it would wreck logical havock, so to prevent bugs Queries have been keept commented but the code has been reverted to normal behavior.
** Ref: http://www.postgresql.org/docs/9.1/static/datatype-binary.html

#define PGSQL_SQL_INSERT_SPECIFIC_REFERENCE_SYSTEM "INSERT INTO reference_system (ref_system_name) VALUES (E'%s');"
#define PGSQL_SQL_SELECT_SPECIFIC_REFERENCE_SYSTEM "SELECT `ref_system_id` FROM reference_system WHERE ref_system_name = E'%s';"
#define PGSQL_SQL_INSERT_SPECIFIC_REF  "INSERT INTO reference (`ref_system_id`,ref_tag) VALUES ('%u',E'%s');"
#define PGSQL_SQL_SELECT_SPECIFIC_REF  "SELECT ref_id FROM reference WHERE `ref_system_id` = '%u' AND ref_tag = E'%s';"
#define PGSQL_SQL_INSERT_CLASSIFICATION "INSERT INTO sig_class (sig_class_name) VALUES (E'%s');"
#define PGSQL_SQL_SELECT_SPECIFIC_CLASSIFICATION "SELECT sig_class_id FROM sig_class WHERE sig_class_name = E'%s';"
#define PGSQL_SQL_INSERT_SIGNATURE "INSERT INTO signature (sig_sid, sig_gid, sig_rev, sig_class_id, sig_priority, sig_name) VALUES ('%u','%u','%u','%u','%u',E'%s');"
#define PGSQL_SQL_SELECT_SPECIFIC_SIGNATURE "SELECT sig_id FROM signature WHERE " \
    "(sig_sid  = '%u') AND "						\
    "(sig_gid  = '%u') AND "						\
    "(sig_rev  = '%u') AND "						\
    "(sig_class_id = '%u') AND "					\
    "(sig_priority = '%u') AND "					\
    "(sig_name = E'%s'); "						\
#endif 
*/  

//#if defined(ENABLE_MYSQL) || defined (ENABLE_ODBC) || defined (ENABLE_ORACLE) || defined (ENABLE_MSSQL)    
//#endif


#define SQL_INSERT_SPECIFIC_REFERENCE_SYSTEM "INSERT INTO reference_system (ref_system_name) VALUES ('%s');"
#define SQL_SELECT_SPECIFIC_REFERENCE_SYSTEM "SELECT `ref_system_id` FROM reference_system WHERE ref_system_name = '%s';"
#define SQL_INSERT_SPECIFIC_REF  "INSERT INTO reference (`ref_system_id`,ref_tag) VALUES ('%u','%s');"
#define SQL_SELECT_SPECIFIC_REF  "SELECT ref_id FROM reference WHERE `ref_system_id` = '%u' AND ref_tag = '%s';"
#define SQL_INSERT_CLASSIFICATION "INSERT INTO sig_class (sig_class_name) VALUES ('%s');"
#define SQL_SELECT_SPECIFIC_CLASSIFICATION "SELECT sig_class_id FROM sig_class WHERE sig_class_name = '%s';"
#define SQL_INSERT_SIGNATURE "INSERT INTO signature (sig_sid, sig_gid, sig_rev, sig_class_id, sig_priority, sig_name) VALUES ('%u','%u','%u','%u','%u','%s');"
#define SQL_SELECT_SPECIFIC_SIGNATURE "SELECT sig_id FROM signature WHERE " \
    "(sig_sid  = '%u') AND "						\
    "(sig_gid  = '%u') AND "						\
    "(sig_rev  = '%u') AND "						\
    "(sig_class_id = '%u') AND "					\
    "(sig_priority = '%u') AND "					\
    "(sig_name = '%s'); "						\


/* Used for backward compatibility with older barnyard process */
#define SQL_SELECT_SPECIFIC_SIGNATURE_WITHOUT_MESSAGE "SELECT sig_id FROM signature WHERE " \
    "(sig_sid  = '%u') AND "                                            \
    "(sig_gid  = '%u') AND "                                            \
    "(sig_rev  = '%u') AND "                                            \
    "(sig_class_id = '%u') AND "                                        \
    "(sig_priority = '%u');"						\
/* Used for backward compatibility with older barnyard process */


#define SQL_SELECT_ALL_SIGREF "SELECT ref_id, sig_id, ref_seq FROM sig_reference ORDER BY sig_id,ref_seq;"
#define SQL_INSERT_SIGREF "INSERT INTO sig_reference (ref_id,sig_id,ref_seq) VALUES ('%u','%u','%u');"
#define SQL_SELECT_SPECIFIC_SIGREF "SELECT ref_id FROM sig_reference WHERE (ref_id = '%u') AND (sig_id = '%u') AND (ref_seq='%u');"
#define SQL_SELECT_ALL_REFERENCE_SYSTEM  "SELECT `ref_system_id`, ref_system_name FROM reference_system;"
#define SQL_SELECT_ALL_REF "SELECT ref_id, `ref_system_id`, ref_tag FROM reference; "
#define SQL_SELECT_ALL_CLASSIFICATION "SELECT sig_class_id, sig_class_name FROM sig_class ORDER BY sig_class_id ASC; "
#define SQL_SELECT_ALL_SIGNATURE "SELECT sig_id, sig_sid, sig_gid,sig_rev, sig_class_id, sig_priority, sig_name FROM signature;"
#define SQL_UPDATE_SPECIFIC_SIGNATURE "UPDATE signature SET "		\
    "sig_class_id = '%u',"						\
    "sig_priority = '%u',"						\
    "sig_rev = '%u' "						\
    "WHERE sig_id = '%u'; "

#endif /* CACHE_SQL_QUERY */


#ifndef CACHE_FLAGS
#define CACHE_FLAGS 
#define CACHE_INTERNAL_ONLY 0x00000001
#define CACHE_DATABASE_ONLY 0x00000010
#define CACHE_BOTH          0x00000100 /* Digging a grave */
#endif /* CACHE_FLAGS */


#ifndef CACHE_FLUSH_FLAGS 
#define CACHE_FLUSH_SIGNATURE      0x00000001
#define CACHE_FLUSH_CLASSIFICATION 0x00000002
#define CACHE_FLUSH_SYSTEM_REF     0x00000004
#define CACHE_FLUSH_SIGREF         0x00000008
#define CACHE_FLUSH_ALL            0xFFFFFFFF
#endif /* CACHE_FLUSH_FLAGS*/



#endif /*__SPO_DATABASE_CACHE_H__ */

