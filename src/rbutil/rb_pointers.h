/****************************************************************************
 *
 * Copyright (C) 2013 Eneo Tecnologia S.L.
 * Author: Eugenio Perez <eupm90@gmail.com>
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
 * @file   rb_pointers.h
 * @author Eugenio Pérez <eupm90@gmail.com>
 * @date   Wed May 29 2013
 * 
 * @brief  Declares a few utilities to work with pointers.
 */

#ifndef RB_POINTERS
#define RB_POINTERS

#include "fatal.h"

/*
 * Macro: Perform an action only if the pointer is NULL.
 *
 * Purpose: Check if a ponter is clean. If not, it raise a fatal error.
 * Arguments:    P => Pointer to ckeck.
 *            CODE => Code is pointer was not NULL.
 *              VA => Message to raise.
 *
 */
#define RB_IF_CLEAN(P,CODE,...) do{if(P) FatalError(__VA_ARGS__); CODE;}while(0)

#endif // RB_POINTERS
