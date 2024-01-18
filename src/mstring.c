/* $Id$ */
/*
** Copyright (C) 2002-2009 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>

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

/***************************************************************************
 *
 * File: MSTRING.C
 *
 * Purpose: Provide a variety of string functions not included in libc.  Makes
 *          up for the fact that the libstdc++ is hard to get reference
 *          material on and I don't want to write any more non-portable c++
 *          code until I have solid references and libraries to use.
 *
 * History:
 *
 * Date:      Author:  Notes:
 * ---------- ------- ----------------------------------------------
 *  08/19/98    MFR    Initial coding begun
 *  03/06/99    MFR    Added Boyer-Moore pattern match routine, don't use
 *                     mContainsSubstr() any more if you don't have to
 *  12/31/99	JGW    Added a full Boyer-Moore implementation to increase
 *                     performance. Added a case insensitive version of mSearch
 *  07/24/01    MFR    Fixed Regex pattern matcher introduced by Fyodor
 *
 **************************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "mstring.h"
#include "debug.h"
#include "plugbase.h" /* needed for fasthex() */
#include "util.h"

static char * mSplitAddTok(const char *, const int, const char *, const char);

#ifdef TEST_MSTRING

int main()
{
    char test[] = "\0\0\0\0\0\0\0\0\0CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0";
    char find[] = "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0";

/*   char test[] = "\x90\x90\x90\x90\x90\x90\xe8\xc0\xff\xff\xff/bin/sh\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
     char find[] = "\xe8\xc0\xff\xff\xff/bin/sh";  */
    int i;
    int toks;
    int *shift;
    int *skip;

/*   shift=make_shift(find,sizeof(find)-1);
     skip=make_skip(find,sizeof(find)-1); */

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,"%d\n",
			    mSearch(test, sizeof(test) - 1, find,
				    sizeof(find) - 1, shift, skip)););

    return 0;
}

#endif

/****************************************************************
 *
 * Function: mSplit()
 *
 * Purpose: Splits a string into tokens non-destructively.
 *
 * Parameters:
 *  char *
 *      The string to be split
 *  char *
 *      A string of token seperaters
 *  int
 *      The maximum number of tokens to be returned. A value
 *      of 0 means to get them all.
 *  int *
 *      Place to store the number of tokens returned
 *  char
 *      The "escape metacharacter", treat the character after
 *      this character as a literal and "escape" a seperator.
 *
 *  Note if max_toks is reached, the last tok in the returned
 *  token array will possibly have separator characters in it.
 *
 *  Returns:
 *      2D char array with one token per "row" of the returned
 *      array.
 *
 ****************************************************************/
char ** mSplit(const char *str, const char *sep_chars, const int max_toks,
               int *num_toks, const char meta_char)
{
    size_t cur_tok = 0;  /* current token index into array of strings */
    size_t tok_start;    /* index to start of token */
    size_t i, j;
    int escaped = 0;
    /* It's rare we'll need more than this even if max_toks is set really
     * high.  Store toks here until finished, then allocate.  If more than
     * this is necessary, then allocate max toks */
    char *toks_buf[TOKS_BUF_SIZE];
    size_t toks_buf_size = TOKS_BUF_SIZE;
    int toks_buf_size_increment = 10;
    char **toks_alloc = NULL;   /* Used if the static buf isn't enough */
    char **toks = toks_buf;     /* Pointer to one of the two above */
    char **retstr;
    char *whitespace = " \t";

    if (num_toks == NULL)
        return NULL;

    *num_toks = 0;

    if ((str == NULL) || (strlen(str) == 0) ||
        ((sep_chars != NULL) && (strlen(sep_chars) == 0)))
    {
        return NULL;
    }

    if (sep_chars == NULL)
        sep_chars = whitespace;

    /* Meta char cannot also be a separator char */
    for (i = 0; i < strlen(sep_chars); i++)
    {
        if (sep_chars[i] == meta_char)
            return NULL;
    }

    /* Move past initial separator characters and whitespace */
    for (i = 0; i < strlen(str); i++)
    {
        for (j = 0; j < strlen(sep_chars); j++)
        {
            if ((str[i] == sep_chars[j]) ||
                isspace((int)str[i]))
            {
                break;
            }
        }

        /* Not a separator character or whitespace */
        if (j == strlen(sep_chars))
            break;
    }

    if (i == strlen(str))
    {
        /* Nothing but separator characters or whitespace in string */
        return NULL;
    }

    /* User only wanted one tok so return the rest of the string in
     * one tok */
    if ((cur_tok + 1) == (size_t)max_toks)
    {
        retstr = (char **)SnortAlloc(sizeof(char *));
        retstr[cur_tok] = SnortStrndup(&str[i], strlen(str) - i);
        if (retstr[cur_tok] == NULL)
        {
            mSplitFree(&retstr, cur_tok + 1);
            return NULL;
        }

        *num_toks = cur_tok + 1;
        return retstr;
    }

    /* Mark the beginning of the next tok */
    tok_start = i;
    for (; i < strlen(str); i++)
    {
        if (!escaped)
        {
            /* Got an escape character.  Don't include it now, but
             * must be a character after it. */
            if (str[i] == meta_char)
            {
                escaped = 1;
                continue;
            }

            /* See if the current character is a separator */
            for (j = 0; j < strlen(sep_chars); j++)
            {
                if (str[i] == sep_chars[j])
                    break;
            }

            /* It's a normal character */
            if (j == strlen(sep_chars))
                continue;

            /* Current character matched a separator character.  Trim off
             * whitespace previous to the separator.  If we get here, there
             * is at least one savable character */
            for (j = i; j > tok_start; j--)
            {
                if (!isspace((int)str[j - 1]))
                    break;
            }
             
            /* Allocate a buffer.  The length will not have included the
             * meta char of escaped separators */
            toks[cur_tok] = mSplitAddTok(&str[tok_start], j - tok_start, sep_chars, meta_char);

            /* Increment current token index */
            cur_tok++;

            /* Move past any more separator characters or whitespace */
            for (; i < strlen(str); i++)
            {
                for (j = 0; j < strlen(sep_chars); j++)
                {
                    if ((str[i] == sep_chars[j]) ||
                        isspace((int)str[i]))
                    {
                        break;
                    }
                }

                /* Not a separator character or whitespace */
                if (j == strlen(sep_chars))
                    break;
            }

            /* Nothing but separator characters or whitespace left in the string */
            if (i == strlen(str))
            {
                *num_toks = cur_tok;

                if (toks != toks_alloc)
                {
                    retstr = (char **)SnortAlloc(sizeof(char *) * cur_tok);
                    memcpy(retstr, toks, (sizeof(char *) * cur_tok));
                }
                else
                {
                    retstr = toks;
                }

                return retstr;
            }

            /* Reached the size of our current string buffer and need to
             * allocate something bigger.  Only get here once if max toks
             * set to something other than 0 because we'll just allocate
             * max toks in that case. */
            if (cur_tok == toks_buf_size)
            {
                char **tmp;

                if (toks_alloc != NULL)
                    tmp = toks_alloc;
                else
                    tmp = toks_buf;

                if (max_toks != 0)
                    toks_buf_size = max_toks;
                else
                    toks_buf_size = cur_tok + toks_buf_size_increment;

                toks_alloc = (char **)SnortAlloc(sizeof(char *) * toks_buf_size);
                memcpy(toks_alloc, tmp, (sizeof(char *) * cur_tok));
                toks = toks_alloc;

                if (tmp != toks_buf)
                    free(tmp);
            }

            if ((max_toks != 0) && ((cur_tok + 1) == (size_t)max_toks))
            {
                /* Return rest of string as last tok */
                *num_toks = cur_tok + 1;

                /* Already got a ret string */
                if (toks != toks_alloc)
                {
                    retstr = (char **)SnortAlloc(sizeof(char *) * (cur_tok + 1));
                    memcpy(retstr, toks, (sizeof(char *) * (cur_tok + 1)));
                }
                else
                {
                    retstr = toks;
                }

                /* Trim whitespace at end of last tok */
                for (j = strlen(str); j > tok_start; j--)
                {
                    if (!isspace((int)str[j - 1]))
                        break;
                }

                retstr[cur_tok] = SnortStrndup(&str[i], j - i);
                if (retstr[cur_tok] == NULL)
                {
                    mSplitFree(&retstr, cur_tok + 1);
                    return NULL;
                }

                return retstr;
            }

            tok_start = i;
        }
        else
        {
            /* This character is escaped with the meta char */
            escaped = 0;
        }
    }

    /* Last character was an escape character */
    if (escaped)
    {
        for (i = 0; i < cur_tok; i++)
            free(toks[i]);

        if (toks == toks_alloc)
            free(toks_alloc);

        return NULL;
    }
    
    /* Trim whitespace at end of last tok */
    for (j = i; j > tok_start; j--)
    {
        if (!isspace((int)str[j - 1]))
            break;
    }

    /* Last character was not a separator character so we've got
     * one more tok.  Unescape escaped sepatator charactors */
    if (toks != toks_alloc)
    {
        retstr = (char **)SnortAlloc(sizeof(char *) * (cur_tok + 1));
        memcpy(retstr, toks, (sizeof(char *) * (cur_tok + 1)));
    }
    else
    {
        retstr = toks;
    }

    retstr[cur_tok] = mSplitAddTok(&str[tok_start], j - tok_start, sep_chars, meta_char);

    /* Just add one to cur_tok index instead of incrementing
     * since we're done */
    *num_toks = cur_tok + 1;
    return retstr;
}

/****************************************************************
 *
 *  Function: mSplitSpecial()
 *
 *  Purpose: Splits a string into tokens non-destructively. The token can be
 *  a multi-character token.
 *
 *  Parameters:
 *      char *str => the string to be split
 *      char *sep => a string of token separator
 *      int max_toks => how many tokens should be returned
 *      int *toks => place to store the number of tokens found in str
 *      char meta => the "escape metacharacter", treat the character
 *                   after this character as a literal and "escape" a
 *                   seperator
 *
 *  Returns:
 *      2D char array with one token per "row" of the returned
 *      array.
 *
 ****************************************************************/
char **mSplitSpecial(char *str, const char *sep, int max_toks,
                     int *toks, const char meta)
{
    char **retstr;      /* 2D array which is returned to caller */
    char *idx;          /* index pointer into str */
    char *end;          /* ptr to end of str */
    char *last_match_idx;          /* index pointer into str */
    const char *sep_end;/* ptr to end of separator string */
    const char *sep_idx;/* index ptr into separator string */
    int len = 0;        /* length of current token string */
    int sep_len = 0;        /* length of seperator string */
    int curr_str = 0;       /* current index into the 2D return array */
    unsigned char last_char = 0xFF;  /* initialize to something that won't be in meta */


    int matched = 0;

    if(!toks) return NULL;

    *toks = 0;

    if (!str || !*str) return NULL;

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                "[*] Splitting string: %s\n", str);
            DebugMessage(DEBUG_PATTERN_MATCH, "curr_str = %d\n", curr_str););

    /*
     * find the ends of the respective passed strings so our while() loops
     * know where to stop
     */
    sep_len = strlen(sep);
    sep_end = sep + sep_len;
    end = str + strlen(str);

    /* remove trailing whitespace */
    while(isspace((int) *(end - 1)) && ((end - 1) >= str))
        *(--end) = '\0';    /* -1 because of NULL */

    /* set our indexing pointers */
    idx = str;

    /*
     * alloc space for the return string, this is where the pointers to the
     * tokens will be stored
     */
    retstr = (char **) SnortAlloc( sizeof(char **) * max_toks );

    max_toks--;

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                "max_toks = %d  curr_str = %d\n", 
                max_toks, curr_str););

    /* loop thru each letter in the string being tokenized */
    while(idx < end)
    {
        /*
         * if the current string-indexed char matches the initial
         * seperator char...
         */
        if((*idx == *sep) && (last_char != meta))
        {
            /* assume we have a complete match and determine otherwise */
            matched = 1;

            /* check length of remaining string */
            if (idx + sep_len < end)
            {
                /* we suspect a complete match and save pointer */
                last_match_idx = idx;

                /* check that the next chars match the remainder of the separator */
                for ( sep_idx = sep; sep_idx < sep_end; sep_idx++, idx++ )
                {
                    if (*idx != *sep_idx)
                        matched = 0;
                }

                /* reset the check pointer */
                idx = last_match_idx;
            }
            else
                matched = 0;

            if ( matched )
            {
                /* if there's something to store... */
                if(len > 0)
                {
                    DEBUG_WRAP(
                            DebugMessage(DEBUG_PATTERN_MATCH, 
                                "Allocating %d bytes for token ", len + 1););
                    if(curr_str <= max_toks)
                    {
                        /* allocate space for the new token */
                        retstr[curr_str] = (char *)SnortAlloc((len + 1) * sizeof(char));

                        /* copy the token into the return string array */
                        memcpy(retstr[curr_str], (idx - len), len);
                        retstr[curr_str][len] = 0;
                        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "tok[%d]: %s\n", curr_str, 
                                    retstr[curr_str]););

                        /* twiddle the necessary pointers and vars */
                        len = 0;
                        curr_str++;
                        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "curr_str = %d\n", curr_str);
                                DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "max_toks = %d  curr_str = %d\n", 
                                    max_toks, curr_str););

                        last_char = *idx;
                        idx+=sep_len;
                    }

                    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                "Checking if curr_str (%d) >= max_toks (%d)\n",
                               curr_str, max_toks););

                    /*
                     * if we've gotten all the tokens requested, return the
                     * list
                     */
                    if(curr_str >= max_toks)
                    {
                        while(isspace((int) *idx))
                            idx++;

                        len = end - idx;
                        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "Finishing up...\n");
                                DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "Allocating %d bytes "
                                    "for last token ", len + 1););
                        fflush(stdout);

                        retstr[curr_str] = (char *)SnortAlloc((len + 1) * sizeof(char));

                        memcpy(retstr[curr_str], idx, len);
                        retstr[curr_str][len] = 0;

                        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "tok[%d]: %s\n", curr_str, 
                                    retstr[curr_str]););

                        *toks = curr_str + 1;
                        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "max_toks = %d  curr_str = %d\n", 
                                    max_toks, curr_str);
                                DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "mSplit got %d tokens!\n", *toks););

                        return retstr;
                    }
                }
                else
                    /*
                     * otherwise, the previous char was a seperator as well,
                     * and we should just continue
                     */
                {
                    last_char = *idx;
                    idx+=sep_len;
                    /* make sure to reset this so we test all the sep. chars */
                    sep_idx = sep;
                    len = 0;
                }
            }
        }

        sep_idx = sep;
        len++;
        last_char = *idx;
        idx++;
    }

    /* put the last string into the list */

    if(len > 0)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                    "Allocating %d bytes for last token ", len + 1););

        retstr[curr_str] = (char *)SnortAlloc((len + 1) * sizeof(char));

        memcpy(retstr[curr_str], (idx - len), len);
        retstr[curr_str][len] = 0;

        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,"tok[%d]: %s\n", curr_str, 
                    retstr[curr_str]););
        *toks = curr_str + 1;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                "mSplitSpecial got %d tokens!\n", *toks););

    /* return the token list */
    return retstr;
}

/* Will not return NULL.  SnortAlloc will fatal if it fails */
static char * mSplitAddTok(const char *str, const int len, const char *sep_chars, const char meta_char)
{
    size_t i, j, k;
    char *tok;
    int tok_len = 0;
    int got_meta = 0;

    /* Get the length of the returned tok
     * Could have a maximum token length and use a fixed sized array and
     * fill it in as we go but don't want to put on that constraint */
    for (i = 0; (int)i < len; i++)
    {
        if (!got_meta)
        {
            if (str[i] == meta_char)
            {
                got_meta = 1;
                continue;
            }
        }
        else
        {
            /* See if the current character is a separator */
            for (j = 0; j < strlen(sep_chars); j++)
            {
                if (str[i] == sep_chars[j])
                    break;
            }

            /* It's a non-separator character, so include
             * the meta character in the return tok */
            if (j == strlen(sep_chars))
                tok_len++;

            got_meta = 0;
        }

        tok_len++;
    }

    /* Allocate it and fill it in */
    tok = (char *)SnortAlloc(tok_len + 1);
    for (i = 0, k = 0; (int)i < len; i++)
    {
        if (!got_meta)
        {
            if (str[i] == meta_char)
            {
                got_meta = 1;
                continue;
            }
        }
        else
        {
            /* See if the current character is a separator */
            for (j = 0; j < strlen(sep_chars); j++)
            {
                if (str[i] == sep_chars[j])
                    break;
            }

            /* It's a non-separator character, so include
             * the meta character in the return tok */
            if (j == strlen(sep_chars))
                tok[k++] = meta_char;

            got_meta = 0;
        }

        tok[k++] = str[i];
    }

    return tok;
}

/****************************************************************
 *
 * Free the buffer allocated by mSplit().
 *
 * char** toks = NULL;
 * int num_toks = 0;
 * toks = (str, " ", 2, &num_toks, 0);
 * mSplitFree(&toks, num_toks);
 *
 * At this point, toks is again NULL.
 *
 ****************************************************************/
void mSplitFree(char ***pbuf, int num_toks)
{
    int i;
    char** buf;  /* array of string pointers */

    if( pbuf==NULL || *pbuf==NULL )
    {
        return;
    }

    buf = *pbuf;

    for( i=0; i<num_toks; i++ )
    {
        if( buf[i] != NULL )
        {
            free( buf[i] );
            buf[i] = NULL;
        }
    }

    free(buf);
    *pbuf = NULL;
}

/****************************************************************
 *
 *  Function: mContainsSubstr(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (non-regex)
 *           substring.
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      b_len => data buffer length
 *      pat => pattern to find
 *      p_len => length of the data in the pattern buffer
 *
 *  Returns:
 *      Integer value, 1 on success (str constains substr), 0 on
 *      failure (substr not in str)
 *
 ****************************************************************/
int mContainsSubstr(const char *buf, int b_len, const char *pat, int p_len)
{
    const char *b_idx;  /* index ptr into the data buffer */
    const char *p_idx;  /* index ptr into the pattern buffer */
    const char *b_end;  /* ptr to the end of the data buffer */
    int m_cnt = 0;      /* number of pattern matches so far... */
#ifdef DEBUG
    unsigned long loopcnt = 0;
#endif

    /* mark the end of the strs */
    b_end = (char *) (buf + b_len);

    /* init the index ptrs */
    b_idx = buf;
    p_idx = pat;

    do
    {
#ifdef DEBUG
        loopcnt++;
#endif

        if(*p_idx == *b_idx)
        {

            if(m_cnt == (p_len - 1))
            {
		DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
					"\n%ld compares for match\n", loopcnt););
                return 1;
            }
            m_cnt++;
            b_idx++;
            p_idx++;
        }
        else
        {
            if(m_cnt == 0)
            {
                b_idx++;
            }
            else
            {
                b_idx = b_idx - (m_cnt - 1);
            }

            p_idx = pat;

            m_cnt = 0;
        }

    } while(b_idx < b_end);


    /* if we make it here we didn't find what we were looking for */
    return 0;
}




/****************************************************************
 *
 *  Function: make_skip(char *, int)
 *
 *  Purpose: Create a Boyer-Moore skip table for a given pattern
 *
 *  Parameters:
 *      ptrn => pattern
 *      plen => length of the data in the pattern buffer
 *
 *  Returns:
 *      int * - the skip table
 *
 ****************************************************************/
int *make_skip(char *ptrn, int plen)
{
    int  i;
    int *skip = (int *) SnortAlloc(256* sizeof(int));

    for ( i = 0; i < 256; i++ )
        skip[i] = plen + 1;

    while(plen != 0)
        skip[(unsigned char) *ptrn++] = plen--;

    return skip;
}



/****************************************************************
 *
 *  Function: make_shift(char *, int)
 *
 *  Purpose: Create a Boyer-Moore shift table for a given pattern
 *
 *  Parameters:
 *      ptrn => pattern
 *      plen => length of the data in the pattern buffer
 *
 *  Returns:
 *      int * - the shift table
 *
 ****************************************************************/
int *make_shift(char *ptrn, int plen)
{
    int *shift = (int *) SnortAlloc(plen * sizeof(int));
    int *sptr = shift + plen - 1;
    char *pptr = ptrn + plen - 1;
    char c;

     c = ptrn[plen - 1];

    *sptr = 1;

    while(sptr-- != shift)
    {
        char *p1 = ptrn + plen - 2, *p2, *p3;

        do
        {
            while(p1 >= ptrn && *p1-- != c);

            p2 = ptrn + plen - 2;
            p3 = p1;

            while(p3 >= ptrn && *p3-- == *p2-- && p2 >= pptr);
        }
        while(p3 >= ptrn && p2 >= pptr);

        *sptr = shift + plen - sptr + p2 - p3;

        pptr--;
    }

    return shift;
}



/****************************************************************
 *
 *  Function: mSearch(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (non-regex)
 *           substring.
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      blen => data buffer length
 *      ptrn => pattern to find
 *      plen => length of the data in the pattern buffer
 *      skip => the B-M skip array
 *      shift => the B-M shift array
 *
 *  Returns:
 *      Integer value, 1 on success (str constains substr), 0 on
 *      failure (substr not in str)
 *
 ****************************************************************/
int mSearch(const char *buf, int blen, const char *ptrn, int plen, int *skip, int *shift)
{
    int b_idx = plen;

#ifdef DEBUG
    char *hexbuf;
    int cmpcnt = 0;
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,"buf: %p  blen: %d  ptrn: %p  "
                "plen: %d\n", buf, blen, ptrn, plen););

#ifdef DEBUG
    hexbuf = fasthex((const u_char *)buf, blen);
    DebugMessage(DEBUG_PATTERN_MATCH,"buf: %s\n", hexbuf);
    free(hexbuf);
    hexbuf = fasthex((const u_char *)ptrn, plen);
    DebugMessage(DEBUG_PATTERN_MATCH,"ptrn: %s\n", hexbuf);
    free(hexbuf);
    DebugMessage(DEBUG_PATTERN_MATCH,"buf: %p  blen: %d  ptrn: %p  "
                 "plen: %d\n", buf, blen, ptrn, plen);
#endif /* DEBUG */
    if(plen == 0)
        return 1;

    while(b_idx <= blen)
    {
        int p_idx = plen, skip_stride, shift_stride;

        while(buf[--b_idx] == ptrn[--p_idx])
        {
#ifdef DEBUG
            cmpcnt++;
#endif
            if(b_idx < 0)
                return 0;

            if(p_idx == 0)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                            "match: compares = %d.\n", cmpcnt););

                return 1;
            }
        }

        skip_stride = skip[(unsigned char) buf[b_idx]];
        shift_stride = shift[p_idx];

        b_idx += (skip_stride > shift_stride) ? skip_stride : shift_stride;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                "no match: compares = %d.\n", cmpcnt););

    return 0;
}



/****************************************************************
 *
 *  Function: mSearchCI(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (non-regex)
 *           substring matching is case insensitive
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      blen => data buffer length
 *      ptrn => pattern to find
 *      plen => length of the data in the pattern buffer
 *      skip => the B-M skip array
 *      shift => the B-M shift array
 *
 *  Returns:
 *      Integer value, 1 on success (str constains substr), 0 on
 *      failure (substr not in str)
 *
 ****************************************************************/
int mSearchCI(const char *buf, int blen, const char *ptrn, int plen, int *skip, int *shift)
{
    int b_idx = plen;
#ifdef DEBUG
    int cmpcnt = 0;
#endif

    if(plen == 0)
        return 1;

    while(b_idx <= blen)
    {
        int p_idx = plen, skip_stride, shift_stride;

        while((unsigned char) ptrn[--p_idx] == 
                toupper((unsigned char) buf[--b_idx]))
        {
#ifdef DEBUG
            cmpcnt++;
#endif
            if(p_idx == 0)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                            "match: compares = %d.\n", 
                            cmpcnt););
                return 1;
            }
        }

        skip_stride = skip[toupper((unsigned char) buf[b_idx])];
        shift_stride = shift[p_idx];

        b_idx += (skip_stride > shift_stride) ? skip_stride : shift_stride;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "no match: compares = %d.\n", cmpcnt););

    return 0;
}


/****************************************************************
 *
 *  Function: mSearchREG(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (regex)
 *           substring.
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      blen => data buffer length
 *      ptrn => pattern to find
 *      plen => length of the data in the pattern buffer
 *      skip => the B-M skip array
 *      shift => the B-M shift array
 *
 *  Returns:
 *      Integer value, 1 on success (str constains substr), 0 on
 *      failure (substr not in str)
 *
 ****************************************************************/
int mSearchREG(const char *buf, int blen, const char *ptrn, int plen, int *skip, int *shift)
{
    int b_idx = plen;
    int literal = 0;
    int regexcomp = 0;
#ifdef DEBUG
    int cmpcnt = 0;
#endif /*DEBUG*/
    
    DEBUG_WRAP(
	       DebugMessage(DEBUG_PATTERN_MATCH, "buf: %p  blen: %d  ptrn: %p "
			    " plen: %d b_idx: %d\n", buf, blen, ptrn, plen, b_idx);
	       DebugMessage(DEBUG_PATTERN_MATCH, "packet data: \"%s\"\n", buf);
	       DebugMessage(DEBUG_PATTERN_MATCH, "matching for \"%s\"\n", ptrn);
	       );
	       
    if(plen == 0)
        return 1;

    while(b_idx <= blen)
    {
        int p_idx = plen, skip_stride, shift_stride;

	DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Looping... "
				"([%d]0x%X (%c) -> [%d]0x%X(%c))\n",
				b_idx, buf[b_idx-1], 
				buf[b_idx-1], 
				p_idx, ptrn[p_idx-1], ptrn[p_idx-1]););

        while(buf[--b_idx] == ptrn[--p_idx]
              || (ptrn[p_idx] == '?' && !literal)
              || (ptrn[p_idx] == '*' && !literal)
              || (ptrn[p_idx] == '\\' && !literal))
        {
	    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "comparing: b:%c -> p:%c\n", 
				    buf[b_idx], ptrn[p_idx]););
#ifdef DEBUG
            cmpcnt++;
#endif

            if(literal)
                literal = 0;
            if(!literal && ptrn[p_idx] == '\\')
                literal = 1;
            if(ptrn[p_idx] == '*')
            {
		DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,"Checking wildcard matching...\n"););
                while(p_idx != 0 && ptrn[--p_idx] == '*'); /* fool-proof */

                while(buf[--b_idx] != ptrn[p_idx])
                {
		    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "comparing: b[%d]:%c -> p[%d]:%c\n",
					    b_idx, buf[b_idx], p_idx, ptrn[p_idx]););

                   regexcomp++;
                    if(b_idx == 0)
                    {
			DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
						"b_idx went to 0, returning 0\n");)
                        return 0;
                    }
                }

		DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "got wildcard final char match! (b[%d]: %c -> p[%d]: %c\n", b_idx, buf[b_idx], p_idx, ptrn[p_idx]););
            }

            if(p_idx == 0)
            {
		DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "match: compares = %d.\n", 
					cmpcnt););
                return 1;
            }

            if(b_idx == 0)
                break;
        }

	DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "skip-shifting...\n"););
	skip_stride = skip[(unsigned char) buf[b_idx]];
	shift_stride = shift[p_idx];
	
	b_idx += (skip_stride > shift_stride) ? skip_stride : shift_stride;
	DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "b_idx skip-shifted to %d\n", b_idx););
	b_idx += regexcomp;
	DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
				"b_idx regex compensated %d steps, to %d\n", regexcomp, b_idx););
	regexcomp = 0;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "no match: compares = %d, b_idx = %d, "
			    "blen = %d\n", cmpcnt, b_idx, blen););

    return 0;
}

