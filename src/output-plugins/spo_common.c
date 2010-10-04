
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <string.h>
#include <time.h>

#include "barnyard2.h"
#include "debug.h"
#include "util.h"

#include "spo_common.h"

/****************************************************************************
 *
 * Function: ts_print2(uint32_t, uint32_t, char *)
 *
 * Purpose: Generate a time stamp and stuff it in a buffer.  This one has
 *          millisecond precision. Oh yeah, I ripped this code off from
 *          TCPdump, props to those guys.
 *
 * Arguments: timeval => clock struct coming out of libpcap
 *            timebuf => buffer to stuff timestamp into
 *
 * Returns: void function
 *
 ****************************************************************************/
void syslog_timestamp(uint32_t sec, uint32_t usec, char *timebuf)
{
    register int		s;
    int					localzone;
    time_t				Time;
    struct tm			*lt;    /* place to stick the adjusted clock data */
	char				*arr_month[] = {"Jan", "Feb", "Mar", "Apr", "May",
										"Jun", "Jul", "Aug", "Sep", "Oct",
										"Nov", "Dec"};
    localzone = barnyard2_conf->thiszone;
   
    /*
    **  If we're doing UTC, then make sure that the timezone is correct.
    */
    if(BcOutputUseUtc())
        localzone = 0;
        
    s = (sec + localzone) % 86400;
    Time = (sec + localzone) - s;

    lt = gmtime(&Time);

    SnortSnprintf(timebuf, TIMEBUF_SIZE, "%s %2d %02d:%02d:%02d",
		arr_month[lt->tm_mon], lt->tm_mday, s / 3600, (s % 3600) / 60, s % 60);
}
