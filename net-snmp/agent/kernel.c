
/*
 *  13 Jun 91  wsak (wk0x@andrew) added mips support
 */

#include <sys/types.h>
#include <stdio.h>
#include "asn1.h"
#include "snmp_impl.h"

#ifndef NULL
#define NULL 0
#endif


static int kmem;
int swap, mem;

init_kmem(file)
    char *file;
{
    kmem = open(file, 0);
    if (kmem < 0){
	fprintf(stderr, "cannot open ");
	perror(file);
	exit(1);
    }

    mem = open("/dev/mem",0);    
    if (mem < 0){
	fprintf(stderr, "cannot open ");
	perror(file);
	exit(1);
    }
    swap = open("/dev/drum",0);
    if (swap < 0){
	fprintf(stderr, "cannot open ");
	perror(file);
	exit(1);
    }

}


/*
 *  Seek into the kernel for a value.
 */
off_t
klseek(base)
     off_t base;
{
  return (lseek(kmem, (off_t)base, 0));
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



klookup(off, target, siz) 
     int     off;
     char   *target;
     int     siz;
{

  klseek(off);      
  if (siz != klread(target, siz)) {
    ERROR("klread\n");
    exit(-1);
    return(NULL);
  }

  return (1);

}

