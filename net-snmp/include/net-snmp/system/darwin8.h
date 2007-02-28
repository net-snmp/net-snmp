#include <stdint.h>
#include "darwin7.h"


/*
 * these apparently used to be in netinet/tcp_timers.h, but went away in
 * 10.4.2. Define them here til we find out a way to get the real values.
 */
#define TCPTV_MIN       (  1*PR_SLOWHZ)         /* minimum allowable value */
#define TCPTV_REXMTMAX  ( 64*PR_SLOWHZ)         /* max allowable REXMT value */

