
/* This file holds common functions amongst the output plugins
 */

#ifndef __SPO_COMMON_H__
#define __SPO_COMMON_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>

void syslog_timestamp(uint32_t, uint32_t, char *);

#endif /* __SPO_COMMON_H__ */

