#include "generic.h"
#undef HAVE_WINSOCK_H
#undef bsdlike

#define	timerisset(tvp)		((tvp)->tv_sec || (tvp)->tv_usec)
#define	timercmp(tvp, uvp, cmp)	\
    (((tvp)->tv_sec == (uvp)->tv_sec && (tvp)->tv_usec cmp (uvp)->tv_usec) \
    || (tvp)->tv_sec cmp (uvp)->tv_sec)
#define	timerclear(tvp)		((tvp)->tv_sec = (tvp)->tv_usec = 0)

/* struct nlist lifted shamelessly from linux:/usr/include/elf.h */

struct nlist
{
  char			*n_name;	/* symbol name */
  long			n_value;	/* value of symbol */
  short			n_scnum;	/* section number */
  unsigned short	n_type;		/* type and derived type */
  char			n_sclass;	/* storage class */
  char			n_numaux;	/* number of aux. entries */
};

#undef TCPSTAT_SYMBOL

/* save the calculation rework for later */
#undef TCPTV_MIN
#undef TCPTV_REXMTMAX
#undef PR_SLOWHZ
#define TCPTV_MIN 1
#define TCPTV_REXMTMAX 1
#define PR_SLOWHZ 1
