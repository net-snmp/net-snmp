#include <config.h>

/* needed by util_funcs.h */
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

/* mibincl.h contains all the snmp specific headers to define the
   return types and various defines and structures. */
#include "mibincl.h"

/* header_generic() comes from here */
#include "util_funcs.h"

/* include our .h file */
#include "diskio.h"

/* parse config file */
#include "agent_read_config.h"

#define CACHE_TIMEOUT 10
static time_t cache_time=0;

#ifdef solaris2
#include <kstat.h>

#define MAX_DISKS 20

static kstat_ctl_t *kc;
static kstat_t *ksp;
static kstat_io_t kio;
static int cache_disknr=-1;
#endif /* solaris2 */

#if defined(bsdi3) || defined(bsdi4)
#include <string.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/diskstats.h>
#endif /* bsdi */

#if defined (freebsd4)
#include <sys/dkstat.h>
#include <devstat.h>
#endif /* freebsd */


         /*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/


/* this is an optional function called at the time the agent starts up
   to do any initilizations you might require.  You don't have to
   create it, as it is optional. */

/* IMPORTANT: If you add or remove this function, you *must* re-run
   the configure script as it checks for its existance. */

void init_diskio(void)
{
/* Define a 'variable' structure that is a representation of our mib. */

/* first, we have to pick the variable type.  They are all defined in
   the var_struct.h file in the agent subdirectory.  I'm picking the
   variable2 structure since the longest sub-component of the oid I
   want to load is .2.1 and .2.2 so I need at most 2 spaces in the
   last entry. */

  struct variable2 diskio_variables[] = {
    { DISKIO_INDEX,  ASN_INTEGER, RONLY, var_diskio, 1, {1}},
    { DISKIO_DEVICE,  ASN_OCTET_STR, RONLY, var_diskio, 1, {2}},
    { DISKIO_NREAD,  ASN_COUNTER, RONLY, var_diskio, 1, {3}},
    { DISKIO_NWRITTEN,  ASN_COUNTER, RONLY, var_diskio, 1, {4}},
    { DISKIO_READS,  ASN_COUNTER, RONLY, var_diskio, 1, {5}},
    { DISKIO_WRITES,  ASN_COUNTER, RONLY, var_diskio, 1, {6}},
  };

  /* Define the OID pointer to the top of the mib tree that we're
   registering underneath. */
  oid diskio_variables_oid[] = { 1,3,6,1,4,1,2021,13,15,1,1 };

  /* register ourselves with the agent to handle our mib tree

   This is a macro defined in ../../snmp_vars.h.  The arguments are:

   descr:   A short description of the mib group being loaded.
   var:     The variable structure to load.
   vartype: The variable structure used to define it (variable2, variable4, ...)
   theoid:  A *initialized* *exact length* oid pointer.
            (sizeof(theoid) *must* return the number of elements!)  
  */
  REGISTER_MIB("diskio", diskio_variables, variable2, diskio_variables_oid);

#ifdef solaris2
  kc=kstat_open();

  if (kc==NULL) 
    snmp_log(LOG_ERR, "diskio: Couln't open kstat\n");
#endif
}

#ifdef solaris2
int get_disk(int disknr) {
  time_t now;
  int i=0;
  now=time(NULL);
  if (disknr==cache_disknr && cache_time + CACHE_TIMEOUT > now) {
    return 1;
  }

  /* could be optimiced by checking if cache_disknr<=disknr
     if so, just reread the data - not going through the whole chain
     from kc->kc_chain */

  for (ksp = kc->kc_chain; ksp != NULL; ksp = ksp->ks_next) {
    if (ksp->ks_type==KSTAT_TYPE_IO && !strcmp(ksp->ks_class, "disk")) {
      if (i==disknr) {
        if (kstat_read(kc, ksp, &kio)==-1)
	  snmp_log(LOG_ERR, "diskio: kstat_read failed\n");
        cache_time=now;
	cache_disknr=disknr;
	return 1;
      } else {
        i++;
      }
    }
  }
  return 0;
}


u_char	*
var_diskio(struct variable *vp,
	   oid *name,
	    size_t *length,
	    int exact,
	    size_t *var_len,
	    WriteMethod **write_method)
{
  /* define any variables we might return as static! */
  static long long_ret;

  if (header_simple_table(vp, name, length, exact, var_len, write_method, MAX_DISKS))
    return NULL;


  if (get_disk(name[*length-1]-1)==0)
    return NULL;


  /* We can now simply test on vp's magic number, defined in diskio.h */
  switch (vp->magic){
    case DISKIO_INDEX:
      long_ret = (long)name[*length-1];
      return (u_char *) &long_ret;
    case DISKIO_DEVICE:
      *var_len = strlen(ksp->ks_name);
      return (u_char *) ksp->ks_name;
    case DISKIO_NREAD:
      long_ret = (signed long)kio.nread;
      return (u_char *) &long_ret;
    case DISKIO_NWRITTEN:
      long_ret = (signed long)kio.nwritten;
      return (u_char *) &long_ret;
    case DISKIO_READS:
      long_ret = (signed long)kio.reads;
      return (u_char *) &long_ret;
    case DISKIO_WRITES:
      long_ret = (signed long)kio.writes;
      return (u_char *) &long_ret;

    default:
      ERROR_MSG("diskio.c: don't know how to handle this request.");
  }
  /* if we fall to here, fail by returning NULL */
  return NULL;
}
#endif /* solaris2 */

#if defined(bsdi3) || defined(bsdi4)
static int ndisk;
static struct diskstats *dk;
static char **dkname;

static int
getstats(void)
{
  time_t now;
  int mib[2];
  char *t, *tp;
  int size, dkn_size, i;

  now = time(NULL);
  if (cache_time + CACHE_TIMEOUT > now) {
    return 1;
  }
  mib[0] = CTL_HW;
  mib[1] = HW_DISKSTATS;
  size = 0;
  if (sysctl(mib, 2, NULL, &size, NULL, 0) < 0) {
    perror("Can't get size of HW_DISKSTATS mib");
    return 0;
  }
  if (ndisk != size / sizeof(*dk)) {
    if (dk)
      free(dk);
    if (dkname) {
      for (i = 0; i < ndisk; i++)
	if (dkname[i])
	  free(dkname[i]);
      free(dkname);
    }
    ndisk = size / sizeof(*dk);
    if (ndisk == 0)
      return 0;
    dkname = malloc(ndisk * sizeof(char *));
    mib[0] = CTL_HW;
    mib[1] = HW_DISKNAMES;
    if (sysctl(mib, 2, NULL, &dkn_size, NULL, 0) < 0) {
      perror("Can't get size of HW_DISKNAMES mib");
      return 0;
    }
    tp = t = malloc(dkn_size);
    if (sysctl(mib, 2, t, &dkn_size, NULL, 0) < 0) {
      perror("Can't get size of HW_DISKNAMES mib");
      return 0;
    }
    for (i = 0; i < ndisk; i++) {
      dkname[i] = strdup(tp);
      tp += strlen(tp) + 1;
    }
    free(t);
    dk = malloc(ndisk * sizeof(*dk));
  }
  mib[0] = CTL_HW;
  mib[1] = HW_DISKSTATS;
  if (sysctl(mib, 2, dk, &size, NULL, 0) < 0) {
    perror("Can't get HW_DISKSTATS mib");
    return 0;
  }
  cache_time = now;
  return 1;
}

u_char *
var_diskio(struct variable * vp,
	   oid * name,
	   size_t * length,
	   int exact,
	   size_t * var_len,
	   WriteMethod ** write_method)
{
  static long long_ret;
  unsigned int indx;

  if (getstats() == 0)
    return 0;

  if (header_simple_table(vp, name, length, exact, var_len, write_method, ndisk))
    return NULL;

  indx = (unsigned int) (name[*length - 1] - 1);
  if (indx >= ndisk)
    return NULL;

  switch (vp->magic) {
    case DISKIO_INDEX:
      long_ret = (long) indx + 1;
      return (u_char *) & long_ret;
    case DISKIO_DEVICE:
      *var_len = strlen(dkname[indx]);
      return (u_char *) dkname[indx];
    case DISKIO_NREAD:
      long_ret = (signed long) (dk[indx].dk_sectors * dk[indx].dk_secsize);
      return (u_char *) & long_ret;
    case DISKIO_NWRITTEN:
      return NULL;		/* Sigh... BSD doesn't keep seperate track */
    case DISKIO_READS:
      long_ret = (signed long) dk[indx].dk_xfers;
      return (u_char *) & long_ret;
    case DISKIO_WRITES:
      return NULL;		/* Sigh... BSD doesn't keep seperate track */

    default:
      ERROR_MSG("diskio.c: don't know how to handle this request.");
  }
  return NULL;
}
#endif /* bsdi */

#if defined(freebsd4)
static int ndisk;
static struct statinfo *stat;

static int
getstats(void)
{
  time_t now;

  now = time(NULL);
  if (cache_time + CACHE_TIMEOUT > now) {
    return 0;
  }
  if (stat == NULL) {
    stat = (struct statinfo*)malloc(sizeof(struct statinfo));
    stat->dinfo = (struct devinfo*)malloc(sizeof(struct devinfo));
  }
  memset(stat->dinfo, 0, sizeof(struct devinfo));

  if ((getdevs(stat)) == -1){
	fprintf (stderr,"Can't get devices:%s\n", devstat_errbuf);
  	return 1;
  }
  ndisk=stat->dinfo->numdevs;
  cache_time = now;
  return 0;
}

u_char *
var_diskio(struct variable * vp,
	   oid * name,
	   size_t * length,
	   int exact,
	   size_t * var_len,
	   WriteMethod ** write_method)
{
  static long long_ret;
  unsigned int indx;

  if (getstats() == 1){
    return NULL;
  } 


 if (header_simple_table(vp, name, length, exact, var_len, write_method, ndisk))
    {
	return NULL;
    }

  indx = (unsigned int) (name[*length - 1] - 1);

  if (indx >= ndisk)
    return NULL;

  switch (vp->magic) {
    case DISKIO_INDEX:
      long_ret = (long) indx+1;;
      return (u_char *) &long_ret;
    case DISKIO_DEVICE:
      *var_len = strlen(stat->dinfo->devices[indx].device_name);
      return (u_char *) stat->dinfo->devices[indx].device_name;
    case DISKIO_NREAD:
      long_ret = (signed long) stat->dinfo->devices[indx].bytes_read;
      return (u_char *) & long_ret;
    case DISKIO_NWRITTEN:
      long_ret = (signed long) stat->dinfo->devices[indx].bytes_written;
      return (u_char *) & long_ret;
    case DISKIO_READS:
      long_ret = (signed long) stat->dinfo->devices[indx].num_reads;
      return (u_char *) & long_ret;
    case DISKIO_WRITES:
      long_ret = (signed long) stat->dinfo->devices[indx].num_writes;
      return (u_char *) & long_ret;

    default:
      ERROR_MSG("diskio.c: don't know how to handle this request.");
  }
  return NULL;
}
#endif /* freebsd4 */

