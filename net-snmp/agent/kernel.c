
/*
 *  13 Jun 91  wsak (wk0x@andrew) added mips support
 */

#include <config.h>

#ifdef CAN_USE_NLIST

#include <sys/types.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <errno.h>
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_KVM_H
#include <kvm.h>
#endif

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_impl.h"

#include "kernel.h"

#ifndef NULL
#define NULL 0
#endif


#if HAVE_KVM_H
static kvm_t *kd;

void
init_kmem(char *file)
{
#if HAVE_KVM_OPENFILES
    char err[4096];
    kd = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, err);
    if (kd == NULL) {
	fprintf(stderr, "init_kmem: kvm_openfiles failed: %s\n", err);
    }
#else
    kd = kvm_open(NULL, NULL, NULL, O_RDONLY, "kvm_open");
#endif
}


/*
 *  klookup:
 *
 *  It seeks to the location  off  in kmem
 *  It does a read into  target  of  siz  bytes.
 *
 *  Return 0 on failure and 1 on sucess.
 *
 */


int
klookup(unsigned long off,
	char   *target,
	int     siz)
{
    int result;
    result = kvm_read(kd, off, target, siz);
    if (result != siz) {
#if HAVE_KVM_OPENFILES
	fprintf(stderr,"kvm_read(*, %lx, %p, %d) = %d: %s\n", off, target, siz,
		result, kvm_geterr(kd));
#else
	fprintf(stderr,"kvm_read(*, %lx, %p, %d) = %d: ", off, target, siz,
		result);
	perror(NULL);
#endif
	return 0;
    }
    return 1;
}

#else /* HAVE_KVM_H */

static off_t klseek (off_t);
static int klread (char *, int);
int swap, mem, kmem;

void
init_kmem(char *file)
{
  kmem = open(file, O_RDONLY);
  if (kmem < 0){
    fprintf(stderr, "cannot open %s: ",file);
    perror(NULL);
#ifndef NO_ROOT_ACCESS
    exit(1);
#endif
  }
  fcntl(kmem,F_SETFD,1);
  mem = open("/dev/mem",O_RDONLY);    
  if (mem < 0){
    fprintf(stderr, "cannot open /dev/mem: ");
    perror(NULL);
#ifndef NO_ROOT_ACCESS
    exit(1);
#endif
  }
  fcntl(mem,F_SETFD,1);
#ifdef DMEM_LOC
  swap = open(DMEM_LOC,O_RDONLY);
  if (swap < 0){
    fprintf(stderr, "cannot open %s: ",DMEM_LOC);
    perror(NULL);
#ifndef NO_ROOT_ACCESS
    exit(1);
#endif
  }
  fcntl(swap,F_SETFD,1);
#endif
}


/*
 *  Seek into the kernel for a value.
 */
static off_t
klseek(off_t base)
{
  return (lseek(kmem, (off_t)base, SEEK_SET));
}


/*
 *  Read from the kernel 
 */
static int
klread(char *buf,
       int buflen)
{
  return (read(kmem, buf, buflen));
}


/*
 *  klookup:
 *
 *  It seeks to the location  off  in kmem
 *  It does a read into  target  of  siz  bytes.
 *
 *  Return 0 on failure and 1 on sucess.
 *
 */


int
klookup(unsigned long off,
	char   *target,
	int     siz)
{
  long retsiz;

  if ((retsiz = klseek((off_t) off)) != off) {
    fprintf (stderr, "klookup(%lx, %p, %d): ", off, target, siz);
    perror("klseek");
#ifdef EXIT_ON_BAD_KLREAD
    exit(1);
#endif
    return (0);
  }
  if ((retsiz = klread(target, siz)) != siz ) {
    if (snmp_get_do_debugging()) {
    /* these happen too often on too many architectures to print them
       unless we're in debugging mode. People get very full log files. */
      fprintf (stderr, "klookup(%lx, %p, %d): ", off, target, siz);
      perror("klread");
      ERROR_MSG("klread");
    }
#ifdef EXIT_ON_BAD_KLREAD
    exit(1);
#endif
    return(0);
  }
  return (1);
}

#endif /* HAVE_KVM_H */

#endif /* CAN_USE_NLIST */
