
/*
 *  13 Jun 91  wsak (wk0x@andrew) added mips support
 */

#include <config.h>

#ifndef linux

#include <sys/types.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <errno.h>
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include "asn1.h"
#include "snmp_impl.h"

#include "kernel.h"

#ifndef NULL
#define NULL 0
#endif

off_t klseek __P((off_t));
int klread __P((char *, int));

int swap, mem, kmem;

void
init_kmem(file)
    char *file;
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
off_t
klseek(base)
     off_t base;
{
  return (lseek(kmem, (off_t)base, SEEK_SET));
}


/*
 *  Read from the kernel 
 */
int
klread(buf, buflen)
    char *buf;
    int buflen;
{
  return (read(kmem, buf, buflen));
}



/*
 *  klookup:
 *
 *  It seeks to the location  off  in kmem
 *  It does a read into  target  of  siz  bytes.
 *
 *  Return NULL on failure and 1 on sucess.
 *
 */


int
klookup(off, target, siz) 
     unsigned long off;
     char   *target;
     int     siz;
{

  long retsiz;

  if ((retsiz = klseek((off_t) off)) != off) {
    fprintf (stderr, "klookup(%lx, %p, %d): ", off, target, siz);
    perror("klseek");
#ifdef EXIT_ON_BAD_KLREAD
    exit(-1);
#endif
    return (0);
  }
  if ((retsiz = klread(target, siz)) != siz ) { 
    fprintf (stderr, "klookup(%lx, %p, %d): ", off, target, siz);
    perror("klread");
    ERROR_MSG("klread");
#ifdef EXIT_ON_BAD_KLREAD
    exit(-1);
#endif
    return(0);
  }
  return (1);
}

#endif /* linux */
