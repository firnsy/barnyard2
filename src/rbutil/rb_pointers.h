
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
