#include "generic.h"
#undef HAVE_WINSOCK_H
#undef bsdlike

#define	timerisset(tvp)		((tvp)->tv_sec || (tvp)->tv_usec)
#define	timercmp(tvp, uvp, cmp)	\
    (((tvp)->tv_sec == (uvp)->tv_sec && (tvp)->tv_usec cmp (uvp)->tv_usec) \
    || (tvp)->tv_sec cmp (uvp)->tv_sec)
#define	timerclear(tvp)		((tvp)->tv_sec = (tvp)->tv_usec = 0)

