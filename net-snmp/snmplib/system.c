/*
 * system.c
 */
/***********************************************************
        Copyright 1992 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/
/*
 * System dependent routines go here
 */
#include <config.h>
#include <stdio.h>

#if HAVE_UNISTD_H
#	include <unistd.h>
#endif

#if HAVE_STDLIB_H
#	include <stdlib.h>
#endif

#if TIME_WITH_SYS_TIME
# ifdef WIN32
#  include <sys/timeb.h>
# else
#  include <sys/time.h>
# endif
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <sys/types.h>

#if HAVE_NETINET_IN_H
#	include <netinet/in.h>
#endif

#if HAVE_WINSOCK_H
#	include <winsock.h>
#else
#	include <sys/socket.h>
#	include <net/if.h>
#endif

#if HAVE_SYS_SOCKIO_H
#	include <sys/sockio.h>
#endif

#if HAVE_SYS_IOCTL_H
#	include <sys/ioctl.h>
#endif

#ifndef WIN32
#	ifdef HAVE_NLIST_H
#	include <nlist.h>
#	endif
#endif

#if HAVE_SYS_FILE_H
#	include <sys/file.h>
#endif

#if HAVE_KSTAT_H
#	include <kstat.h>
#endif

#if HAVE_SYS_PARAM_H
#	include <sys/param.h>
#endif

#if HAVE_SYS_SYSCTL_H
#	include <sys/sysctl.h>
#endif

#include "asn1.h"
#include "snmp_api.h"
#include "system.h"

#define NUM_NETWORKS    32   /* max number of interfaces to check */

#ifndef IFF_LOOPBACK
#	define IFF_LOOPBACK 0
#endif

#define LOOPBACK    0x7f000001



/* ********************************************* */
#ifdef							WIN32
#	define WIN32_LEAN_AND_MEAN
#	define WIN32IO_IS_STDIO
#	define PATHLEN	1024

#	include <tchar.h>
#	include <windows.h>
#	include <sys/stat.h>


/* The idea here is to read all the directory names into a string table
 * (separated by nulls) and when one of the other dir functions is called
 * return the pointer to the current file name.
 */
DIR *
opendir(char *filename)
{
    DIR            *p;
    long            len;
    long            idx;
    char            scannamespc[PATHLEN];
    char       *scanname = scannamespc;
    struct stat     sbuf;
    WIN32_FIND_DATA FindData;
    HANDLE          fh;

    /* check to see if filename is a directory */
    if (stat(filename, &sbuf) < 0 || sbuf.st_mode & S_IFDIR == 0) {
	return NULL;
    }

    /* get the file system characteristics */
/*  if(GetFullPathName(filename, MAX_PATH, root, &dummy)) {
 *	if(dummy = strchr(root, '\\'))
 *	    *++dummy = '\0';
 *	if(GetVolumeInformation(root, volname, MAX_PATH, &serial,
 *				&maxname, &flags, 0, 0)) {
 *	    downcase = !(flags & FS_CASE_IS_PRESERVED);
 *	}
 *  }
 *  else {
 *	downcase = TRUE;
 *  }
 */
    /* Get us a DIR structure */
    p = (DIR*)malloc(sizeof(DIR));
    /* Newz(1303, p, 1, DIR); */
    if(p == NULL)
	return NULL;

    /* Create the search pattern */
    strcpy(scanname, filename);

    if(index("/\\", *(scanname + strlen(scanname) - 1)) == NULL)
	strcat(scanname, "/*");
    else
	strcat(scanname, "*");

    /* do the FindFirstFile call */
    fh = FindFirstFile(scanname, &FindData);
    if(fh == INVALID_HANDLE_VALUE) {
	return NULL;
    }

    /* now allocate the first part of the string table for
     * the filenames that we find.
     */
    idx = strlen(FindData.cFileName)+1;
    p->start = (char*)malloc(idx * sizeof(char));
    /* New(1304, p->start, idx, char);*/
    if(p->start == NULL) {
	return NULL;
    }
    strcpy(p->start, FindData.cFileName);
/*  if(downcase)
 *	strlwr(p->start);
 */
    p->nfiles++;

    /* loop finding all the files that match the wildcard
     * (which should be all of them in this directory!).
     * the variable idx should point one past the null terminator
     * of the previous string found.
     */
    while (FindNextFile(fh, &FindData)) {
	len = strlen(FindData.cFileName);
	/* bump the string table size by enough for the
	 * new name and it's null terminator
	 */
	p->start = (char*)realloc((void*)p->start,
			idx+len+1 * sizeof(char));
	/* Renew(p->start, idx+len+1, char);*/
	if(p->start == NULL) {
	    return NULL;
	}
	strcpy(&p->start[idx], FindData.cFileName);
/*	if (downcase) 
 *	    strlwr(&p->start[idx]);
 */
		p->nfiles++;
		idx += len+1;
	}
	FindClose(fh);
	p->size = idx;
	p->curr = p->start;
	return p;
}


/* Readdir just returns the current string pointer and bumps the
 * string pointer to the nDllExport entry.
 */
struct direct *
readdir(DIR *dirp)
{
    int         len;
    static int  dummy = 0;

    if (dirp->curr) {
	/* first set up the structure to return */
	len = strlen(dirp->curr);
	strcpy(dirp->dirstr.d_name, dirp->curr);
	dirp->dirstr.d_namlen = len;

	/* Fake an inode */
	dirp->dirstr.d_ino = dummy++;

	/* Now set up for the nDllExport call to readdir */
	dirp->curr += len + 1;
	if (dirp->curr >= (dirp->start + dirp->size)) {
	    dirp->curr = NULL;
	}

	return &(dirp->dirstr);
    } 
    else
	return NULL;
}

/* free the memory allocated by opendir */
int
closedir(DIR *dirp)
{
    free(dirp->start);
    free(dirp);
    return 1;
}

#ifndef HAVE_GETTIMEOFDAY

int gettimeofday(tv, tz)
struct timeval *tv;
struct timezone *tz;
{
    struct _timeb timebuffer;

    _ftime(&timebuffer);
    tv->tv_usec = timebuffer.millitm;
    tv->tv_sec = timebuffer.time;
    return(1);
}
#endif	/* !HAVE_GETTIMEOFDAY */


in_addr_t get_myaddr()
{
  char local_host[130];
  int result;
  LPHOSTENT lpstHostent;
  SOCKADDR_IN in_addr, remote_in_addr;
  SOCKET hSock;
  int nAddrSize = sizeof(SOCKADDR);

  in_addr.sin_addr.s_addr = INADDR_ANY;

  result = gethostname(local_host, 130);
  if (result == 0)
  {
	lpstHostent = gethostbyname((LPSTR)local_host);
	if (lpstHostent)
	{
	  in_addr.sin_addr.s_addr = *((u_long FAR *) (lpstHostent->h_addr));
	  return((in_addr_t)in_addr.sin_addr.s_addr);
	}
  }

  /* if we are here, than we don't have host addr */
  hSock = socket(AF_INET, SOCK_DGRAM, 0);
  if (hSock != INVALID_SOCKET)
  {
	  /* connect to any port and address */
	  remote_in_addr.sin_family = AF_INET;
	  remote_in_addr.sin_port = htons(IPPORT_ECHO);
	  remote_in_addr.sin_addr.s_addr = inet_addr("128.22.33.11");
	  result=connect(hSock,(LPSOCKADDR)&remote_in_addr,sizeof(SOCKADDR)); 
	  if (result != SOCKET_ERROR)
	  {
	      /* get local ip address */
	      getsockname(hSock, (LPSOCKADDR)&in_addr,(int FAR *)&nAddrSize);
	  }
	  closesocket(hSock);
  }
  return((in_addr_t)in_addr.sin_addr.s_addr);
}

long get_uptime __P((void))
{
    return (0); /* not implemented */
}

char *
winsock_startup __P((void))
{
 WORD VersionRequested;
 WSADATA stWSAData;
 int i;
 static char errmsg[100];

 VersionRequested = MAKEWORD(1,1);
 i = WSAStartup(VersionRequested, &stWSAData); 
 if (i != 0)
 {
  if (i == WSAVERNOTSUPPORTED)
    sprintf(errmsg,"Unable to init. socket lib, does not support 1.1");
  else
  {
    sprintf(errmsg,"Socket Startup error %d", i);
  }
  return(errmsg);
 }
 return(NULL);
}

void winsock_cleanup __P((void))
{
   WSACleanup();
}

#else							/* WIN32 */

/*
 * XXX	What if we have multiple addresses?
 * XXX	Could it be computed once then cached?
 */
in_addr_t
get_myaddr __P((void))
{
    int sd;
    struct ifconf ifc;
    struct ifreq conf[NUM_NETWORKS], *ifrp, ifreq;
    struct sockaddr_in *in_addr;
    int count;
    int interfaces;             /* number of interfaces returned by ioctl */

    if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        return 0;
    ifc.ifc_len = sizeof(conf);
    ifc.ifc_buf = (caddr_t)conf;
    if (ioctl(sd, SIOCGIFCONF, (char *)&ifc) < 0){
        close(sd);
        return 0;
    }
    ifrp = ifc.ifc_req;
    interfaces = ifc.ifc_len / sizeof(struct ifreq);
    for(count = 0; count < interfaces; count++, ifrp++){
        ifreq = *ifrp;
        if (ioctl(sd, SIOCGIFFLAGS, (char *)&ifreq) < 0)
            continue;
        in_addr = (struct sockaddr_in *)&ifrp->ifr_addr;
        if ((ifreq.ifr_flags & IFF_UP)
          && (ifreq.ifr_flags & IFF_RUNNING)
          && !(ifreq.ifr_flags & IFF_LOOPBACK)
          && in_addr->sin_addr.s_addr != LOOPBACK){
#ifdef SYS_IOCTL_H_HAS_SIOCGIFADDR
	    if (ioctl(sd, SIOCGIFADDR, (char *)&ifreq) < 0)
		continue;
	    in_addr = (struct sockaddr_in *)&(ifreq.ifr_addr);
#endif
	    close(sd);
	    return in_addr->sin_addr.s_addr;
	}
    }
    close(sd);
    return 0;
}


/*
 * Returns uptime in centiseconds(!).
 */
long get_uptime __P((void))
{
#if defined(bsdlike) && !defined(solaris2) && !defined(linux)
    struct timeval boottime, now, diff;
#ifndef						CAN_USE_SYSCTL
    int kmem;
    static struct nlist nl[] = {
#if					!defined(hpux)
	    { "_boottime" },
#else
	    { "boottime" },
#endif					/* !defined(hpux) */
	    { "" }
	};

    if ((kmem = open("/dev/kmem", 0)) < 0)
	return 0;
    nlist(KERNEL_LOC, nl);
    if (nl[0].n_type == 0){
	close(kmem);
	return 0;
    }

    lseek(kmem, (long)nl[0].n_value, L_SET);
    read(kmem, &boottime, sizeof(boottime));
    close(kmem);
#else						/* CAN_USE_SYSCTL */
    int                 mib[2];
    size_t              len;

    mib[0] = CTL_KERN;
    mib[1] = KERN_BOOTTIME;

    len = sizeof(boottime);

    sysctl(mib, 2, &boottime, &len, NULL, NULL);
#endif						/* CAN_USE_SYSCTL */

    gettimeofday(&now,(struct timezone *)0);

    now.tv_sec--;
    now.tv_usec += 1000000L;
    diff.tv_sec = now.tv_sec - boottime.tv_sec;
    diff.tv_usec = now.tv_usec - boottime.tv_usec;
    if (diff.tv_usec > 1000000L){
	diff.tv_usec -= 1000000L;
	diff.tv_sec++;
    }
    return ((diff.tv_sec * 100) + (diff.tv_usec / 10000));
#endif /* bsdlike */

#ifdef solaris2
    kstat_ctl_t *ksc = kstat_open();
    kstat_t *ks;
    kid_t kid;
    kstat_named_t *named;
    u_long lbolt;

    if (ksc == NULL) return 0;
    ks = kstat_lookup (ksc, "unix", -1, "system_misc");
    if (ks == NULL) return 0;
    kid = kstat_read (ksc, ks, NULL);
    if (kid == -1) return 0;
    named = kstat_data_lookup(ks, "lbolt");
    if (named == NULL) return 0;
    lbolt = named->value.ul;
    kstat_close(ksc);
    return lbolt;
#endif /* solaris2 */

#ifdef linux
   FILE *in = fopen ("/proc/uptime", "r");
   long uptim = 0, a, b;
   if (in) {
       if (2 == fscanf (in, "%ld.%ld", &a, &b))
	   uptim = a * 100 + b;
       fclose (in);
   }
   return uptim;
#endif /* linux */
}
#endif							/* WIN32 */



#ifndef HAVE_STRDUP
char *
strdup(src)
    char *src;
{
    int len;
    char *dst;

    len = strlen(src) + 1;
    if ((dst = (char *)malloc(len)) == NULL)
	return(NULL);
    strcpy(dst, src);
    return(dst);
}
#endif	/* HAVE_STRDUP */

#ifndef HAVE_SETENV
int setenv(name, value, overwrite)
    char *name;
    char *value;
    int overwrite;
{
    char *cp;
    int ret;

    if (overwrite == 0) {
	if (getenv(name)) return 0;
    }
    cp = malloc(strlen(name)+strlen(value)+2);
    if (cp == NULL) return -1;
    sprintf(cp, "%s=%s", name, value);
    ret = putenv(cp);
    return ret;
}
#endif /* HAVE_SETENV */

int
calculate_time_diff(struct timeval *now, struct timeval *then)
{
  struct timeval tmp, diff;
  memcpy(&tmp, now, sizeof(struct timeval));
  tmp.tv_sec--;
  tmp.tv_usec += 1000000L;
  diff.tv_sec = tmp.tv_sec - then->tv_sec;
  diff.tv_usec = tmp.tv_usec - then->tv_usec;
  if (diff.tv_usec > 1000000L){
    diff.tv_usec -= 1000000L;
    diff.tv_sec++;
  }
  return ((diff.tv_sec * 100) + (diff.tv_usec / 10000));
}

