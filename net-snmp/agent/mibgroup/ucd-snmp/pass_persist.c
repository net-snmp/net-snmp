#include <config.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <stdio.h>
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <sys/types.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
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

#include <signal.h>
#include <errno.h>

#include "mibincl.h"
#include "struct.h"
#include "pass_persist.h"
#include "extensible.h"
#include "util_funcs.h"
#include "read_config.h"
#include "../../../snmplib/system.h"

struct extensible *persistpassthrus=NULL;
int numpersistpassthrus=0;
struct persist_pipe_type {
  FILE *fIn, *fOut;
  int fdIn, fdOut;
  int pid;
} *persist_pipes = ( struct persist_pipe_type * ) NULL;
static int init_persist_pipes __P((void));
static int close_persist_pipe __P((int index));
static int open_persist_pipe __P((int index, char *command));
static void destruct_persist_pipes __P((void));
static int write_persist_pipe __P(( int index, char *data ));

/* the relocatable extensible commands variables */
struct variable2 extensible_persist_passthru_variables[] = {
  /* bogus entry.  Only some of it is actually used. */
  {MIBINDEX, ASN_INTEGER, RWRITE, var_extensible_pass_persist, 0, {MIBINDEX}},
};

void pass_persist_parse_config(word,cptr)
  char *word;
  char *cptr;
{
  struct extensible **ppass = &persistpassthrus, **etmp, *ptmp;
  char *tcptr;
  int i;

  if (*cptr == '.') cptr++;
  if (!isdigit(*cptr)) {
    config_perror("second token is not a OID");
    return;
  }
  numpersistpassthrus++;

  while(*ppass != NULL)
    ppass = &((*ppass)->next);
  (*ppass) = (struct extensible *) malloc(sizeof(struct extensible));
  (*ppass)->type = PASSTHRU_PERSIST;

  (*ppass)->miblen = parse_miboid(cptr,(*ppass)->miboid);
  while (isdigit(*cptr) || *cptr == '.') cptr++;
  /* name */
  cptr = skip_white(cptr);
  if (cptr == NULL) {
    config_perror("No command specified on pass_persist line");
    (*ppass)->command[0] = 0;
  } else {
    for(tcptr=cptr; *tcptr != 0 && *tcptr != '#' && *tcptr != ';';
        tcptr++);
    strncpy((*ppass)->command,cptr,tcptr-cptr);
    (*ppass)->command[tcptr-cptr] = 0;
  }
  strcpy((*ppass)->name, (*ppass)->command);
  (*ppass)->next = NULL;

  register_mib("pass_persist", (struct variable *) extensible_persist_passthru_variables,
               sizeof(struct variable2),
               1, (*ppass)->miboid, (*ppass)->miblen);

  /* argggg -- pasthrus must be sorted */
  if (numpersistpassthrus > 0) {
    etmp = (struct extensible **)
      malloc(((sizeof(struct extensible *)) * numpersistpassthrus));
    for(i=0,ptmp = (struct extensible *) persistpassthrus;
        i < numpersistpassthrus && ptmp != 0;
        i++, ptmp = ptmp->next)
      etmp[i] = ptmp;
    qsort(etmp, numpersistpassthrus, sizeof(struct extensible *),
#ifdef __STDC__
         (int (*)(const void *, const void *)) pass_persist_compare
#else
          pass_persist_compare
#endif
      );
    persistpassthrus = (struct extensible *) etmp[0];
    ptmp = (struct extensible *) etmp[0];

    for(i=0; i < numpersistpassthrus-1; i++) {
      ptmp->next = etmp[i+1];
      ptmp = ptmp->next;
    }
    ptmp->next = NULL;
    free(etmp);
  }
}

void pass_persist_free_config __P((void)) {
  struct extensible *etmp, *etmp2;

  /* Close any open pipes to any programs */
  destruct_persist_pipes();

  for (etmp = persistpassthrus; etmp != NULL;) {
    etmp2 = etmp;
    etmp = etmp->next;
    unregister_mib(etmp2->miboid, etmp2->miblen);
    free(etmp2);
  }
  persistpassthrus = NULL;
  numpersistpassthrus = 0;
}

unsigned char *var_extensible_pass_persist(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
/* IN - pointer to variable entry that points here */
    register oid        *name;
/* IN/OUT - input name requested, output name found */
    register int        *length;
/* IN/OUT - length of input and output oid's */
    int                 exact;
/* IN - TRUE if an exact match was requested. */
    int                 *var_len;
/* OUT - length of variable or 0 if function returned. */
    int                 (**write_method) __P((int, u_char *, u_char, int, u_char *,oid *, int));
/* OUT - pointer to function to set variable, otherwise 0 */
{

  oid newname[30];
  int i, j, rtest=0, newlen, last;
  static long long_ret;
  static char buf[300], buf2[300];
  static oid  objid[30];
  struct extensible *persistpassthru;
  FILE *file;

  /* Make sure that our basic pipe structure is malloced */
  init_persist_pipes();

  long_ret = *length;
  for(i=1; i<= numpersistpassthrus; i++) {
    persistpassthru = get_exten_instance(persistpassthrus,i);
    last = persistpassthru->miblen;
    if (persistpassthru->miblen > *length)
      last = *length;
    for(j=0,rtest=0; j < last && !rtest; j++) {
      if (name[j] != persistpassthru->miboid[j]) {
        if (name[j] < persistpassthru->miboid[j])
          rtest = -1;
        else
          rtest = 1;
      }
    }
    if ((exact && rtest == 0) || (!exact && rtest <= 0)) {
      /* setup args */
      if (persistpassthru->miblen >= *length || rtest < 0)
        sprint_mib_oid(buf, persistpassthru->miboid, persistpassthru->miblen);
      else
        sprint_mib_oid(buf, name, *length);

      /* Open our pipe if necessary */
      if( ! open_persist_pipe( i, persistpassthru->name ) ) {
        return(NULL);
      }

      if (exact)
        sprintf(persistpassthru->command,"get\n%s\n",buf);
      else
        sprintf(persistpassthru->command,"getnext\n%s\n",buf);

      DEBUGP("persistpass-sending:\n%s",persistpassthru->command);
      if( ! write_persist_pipe( i, persistpassthru->command ) ) {
        *var_len = 0;
        /* close_persist_pipes is called in write_persist_pipe */
        return(NULL);
      }

      /* valid call.  Exec and get output */
      if ((file = persist_pipes[i].fIn)) {
        if (fgets(buf,STRMAX,file) == NULL) {
          *var_len = 0;
          close_persist_pipe(i);
          return(NULL);
        }
        /* persistant scripts return "NONE\n" on invalid items */
        if( ! strncmp( buf, "NONE", 4 ) ) {
          *var_len = 0;
          return( NULL );
        }
        newlen = parse_miboid(buf,newname);

        /* its good, so copy onto name/length */
        memcpy( (char *)name,(char *) newname, (int)newlen * sizeof (oid));
        *length = newlen;

        /* set up return pointer for setable stuff */
        *write_method = setPassPersist;

        if (newlen == 0 || fgets(buf,STRMAX,file) == NULL
            || fgets(buf2,STRMAX,file) == NULL) {
          *var_len = 0;
          close_persist_pipe(i);
          return(NULL);
        }

        /* buf contains the return type, and buf2 contains the data */
        if (!strncasecmp(buf,"string",6)) {
          buf2[strlen(buf2)-1] = 0;  /* zap the linefeed */
          *var_len = strlen(buf2);
          vp->type = ASN_OCTET_STR;
          return((unsigned char *) buf2);
        } else if (!strncasecmp(buf,"integer",7)) {
          *var_len = sizeof(long_ret);
          long_ret = atoi(buf2);
          vp->type = ASN_INTEGER;
          return((unsigned char *) &long_ret);
        } else if (!strncasecmp(buf,"counter",7)) {
          *var_len = sizeof(long_ret);
          long_ret = atoi(buf2);
          vp->type = ASN_COUNTER;
          return((unsigned char *) &long_ret);
        } else if (!strncasecmp(buf,"gauge",5)) {
          *var_len = sizeof(long_ret);
          long_ret = atoi(buf2);
          vp->type = ASN_GAUGE;
          return((unsigned char *) &long_ret);
        } else if (!strncasecmp(buf,"objectid",8)) {
          newlen = parse_miboid(buf2,objid);
          *var_len = newlen*sizeof(oid);
          vp->type = ASN_OBJECT_ID;
          return((unsigned char *) objid);
        } else if (!strncasecmp(buf,"timetick",8)) {
          *var_len = sizeof(long_ret);
          long_ret = atoi(buf2);
          vp->type = ASN_TIMETICKS;
          return((unsigned char *) &long_ret);
        } else if (!strncasecmp(buf,"ipaddress",9)) {
          newlen = parse_miboid(buf2,objid);
          if (newlen != 4) {
            fprintf(stderr,"invalid ipaddress returned:  %s\n",buf2);
            *var_len = 0;
            return(NULL);
          }
          long_ret = (objid[0] << (8*3)) + (objid[1] << (8*2)) +
            (objid[2] << 8) + objid[3];
          *var_len = sizeof(long_ret);
          vp->type = ASN_IPADDRESS;
          return((unsigned char *) &long_ret);
        }
      }
      *var_len = 0;
      return(NULL);
    }
  }
  if (var_len)
    *var_len = 0;
  *write_method = NULL;
  return(NULL);
}

int
setPassPersist(action, var_val, var_val_type, var_val_len, statP, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      name_len;
{
  int i, j, rtest, tmplen=1000, last;
  struct extensible *persistpassthru;

  static char buf[300], buf2[300];
  static long tmp;
  static unsigned long utmp;
  static int itmp;
  static oid objid[30];

  /* Make sure that our basic pipe structure is malloced */
  init_persist_pipes();

  for(i=1; i<= numpersistpassthrus; i++) {
    persistpassthru = get_exten_instance(persistpassthrus,i);
    last = persistpassthru->miblen;
    if (persistpassthru->miblen > name_len)
      last = name_len;
    for(j=0,rtest=0; j < last && !rtest; j++) {
      if (name[j] != persistpassthru->miboid[j]) {
        if (name[j] < persistpassthru->miboid[j])
          rtest = -1;
        else
          rtest = 1;
      }
    }
    if (rtest <= 0) {
      if (action != COMMIT)
        return SNMP_ERR_NOERROR;
      /* setup args */
      if (persistpassthru->miblen >= name_len || rtest < 0)
        sprint_mib_oid(buf, persistpassthru->miboid, persistpassthru->miblen);
      else
        sprint_mib_oid(buf, name, name_len);
      sprintf(persistpassthru->command,"set\n%s\n ",buf);
      switch(var_val_type) {
        case ASN_INTEGER:
        case ASN_COUNTER:
        case ASN_GAUGE:
        case ASN_TIMETICKS:
          asn_parse_int(var_val,&tmplen,&var_val_type, &tmp,
                        sizeof(tmp));
          switch (var_val_type) {
            case ASN_INTEGER:
              sprintf(buf,"integer %d",(int) tmp);
              break;
            case ASN_COUNTER:
              sprintf(buf,"counter %d",(int) tmp);
              break;
            case ASN_GAUGE:
              sprintf(buf,"gauge %d",(int) tmp);
              break;
            case ASN_TIMETICKS:
              sprintf(buf,"timeticks %d",(int) tmp);
              break;
          }
          break;
        case ASN_IPADDRESS:
          asn_parse_unsigned_int(var_val,&tmplen,&var_val_type, &utmp,
                                 sizeof(utmp));
          sprintf(buf,"ipaddress %d.%d.%d.%d",
                  (int) ((utmp & 0xff000000) >> (8*3)),
                  (int) ((utmp & 0xff0000) >> (8*2)),
                  (int) ((utmp & 0xff00) >> (8)),
                  (int) ((utmp & 0xff)));
          break;
        case ASN_OCTET_STR:
          itmp = sizeof(buf);
          memset(buf2,(0),itmp);
          asn_parse_string(var_val,&tmplen,&var_val_type,buf2,&itmp);
          sprintf(buf,"string %s",buf2);
          break;
        case ASN_OBJECT_ID:
          itmp = sizeof(objid);
          asn_parse_objid(var_val,&tmplen,&var_val_type,objid,&itmp);
          sprint_mib_oid(buf2, objid, itmp);
          sprintf(buf,"objectid \"%s\"",buf2);
          break;
      }
      strcat(persistpassthru->command,buf);
      strcat(persistpassthru->command,"\n");

      if( ! open_persist_pipe( i, persistpassthru->name ) ) {
        return SNMP_ERR_NOTWRITABLE;
      }

      DEBUGP("persistpass-writing:  %s\n",persistpassthru->command);
      if( ! write_persist_pipe( i, persistpassthru->command ) ) {
        close_persist_pipe(i);
        return SNMP_ERR_NOTWRITABLE;
      }

      if (fgets(buf,STRMAX,persist_pipes[i].fIn) == NULL) {
        close_persist_pipe(i);
        return SNMP_ERR_NOTWRITABLE;
      }

      if (!strncasecmp(buf,"not-writable",11)) {
        return SNMP_ERR_NOTWRITABLE;
      } else if (!strncasecmp(buf,"wrong-type",9)) {
        return SNMP_ERR_WRONGTYPE;
      }
      return SNMP_ERR_NOERROR;
    }
  }
  if (snmp_get_do_debugging()) {
    sprint_mib_oid(buf2,name,name_len);
    DEBUGP("persistpass-notfound:  %s\n",buf2);
  }
  return SNMP_ERR_NOSUCHNAME;
}

int pass_persist_compare(a, b)
  void *a, *b;
{
  struct extensible **ap, **bp;
  ap = (struct extensible **) a;
  bp = (struct extensible **) b;
  return compare((*ap)->miboid,(*ap)->miblen,(*bp)->miboid,(*bp)->miblen);
}

/*
 * Initialize our persistant pipes
 *   - Returns 1 on success, 0 on failure.
 *   - Initializes all FILE pointers to NULL to indicate "closed"
 */
static int init_persist_pipes __P((void))
{
  int i;

  /* if we are already taken care of, just return */
  if ( persist_pipes ) {
    return persist_pipes ? 1 : 0;
  }

  /* Otherwise malloc and initialize */
  persist_pipes = (struct persist_pipe_type *)
                  malloc( sizeof(struct persist_pipe_type) *
                          (numpersistpassthrus+1) );
  if( persist_pipes ) {
    for( i = 0; i <= numpersistpassthrus; i++ ) {
      persist_pipes[i].fIn = persist_pipes[i].fOut = (FILE *) 0;
      persist_pipes[i].fdIn = persist_pipes[i].fdOut = -1;
      persist_pipes[i].pid = -1;
    }
  }
  return persist_pipes ? 1 : 0;
}

/*
 * Destruct our persistant pipes
 *
 */
static void destruct_persist_pipes __P((void))
{
  int i;

  /* Return if there are no pipes */
  if ( ! persist_pipes ) {
    return;
  }

  for( i = 0; i <= numpersistpassthrus; i++ ) {
    close_persist_pipe(i);
  }

  free( persist_pipes );
  persist_pipes = (struct persist_pipe_type *) 0;
}

/* returns 0 on failure, 1 on success */
static int open_persist_pipe(index, command)
  int index;
  char *command;
{
  static int recurse = 0;  /* used to allow one level of recursion */

  DEBUGP("open_persist_pipe(%d,'%s')\n",index, command);
  /* Open if it's not already open */
  if( persist_pipes[index].pid == -1 ) {
    int fdIn, fdOut, pid;
    get_exec_pipes( command, &fdIn, &fdOut, &pid );

    /* Did we fail? */
    if( pid == -1 ) {
      DEBUGP("open_persist_pipe: pid == -1\n");
      recurse = 0;
      return 0;
    }

    /* If not, fill out our structure */
    persist_pipes[index].pid = pid;
    persist_pipes[index].fdIn = fdIn;
    persist_pipes[index].fdOut = fdOut;
    persist_pipes[index].fIn = fdopen(fdIn,"r");
    persist_pipes[index].fOut = fdopen(fdOut,"w");

    /* Setup our -non-buffered-io- */
    setbuf( persist_pipes[index].fOut, (char *)0 );
  }

  /* Send test packet always so we can self-catch */
  {
    char buf[STRMAX];
    /* Should catch SIGPIPE around this call! */	/* XXX */
    if( ! write_persist_pipe( index, "PING\n" ) ) {
      DEBUGP("open_persist_pipe: Error writing PING\n");
      close_persist_pipe(index);

      /* Recurse one time if we get a SIGPIPE */
      if( ! recurse ) {
        recurse = 1;
        return open_persist_pipe(index,command);
      }
      recurse = 0;
      return 0;
    }
    if (fgets(buf,STRMAX-1,persist_pipes[index].fIn) == NULL) {
      DEBUGP("open_persist_pipe: Error reading for PONG\n");
      close_persist_pipe(index);
      recurse = 0;
      return 0;
    }
    if ( strncmp( buf, "PONG", 4 ) ) {
      DEBUGP("open_persist_pipe: PONG not received!\n");
      close_persist_pipe(index);
      recurse = 0;
      return 0;
    }
  }

  recurse = 0;
  return 1;
}

/* Generic handler */
void sigpipe_handler (sig, sip, uap )
  int sig;
  siginfo_t *sip;
  void *uap;
{
  return;
}

static int write_persist_pipe( index, data )
  int index;
  char *data;
{
  struct sigaction sa, osa;
  int wret = 0, werrno = 0;

  /* Don't write to a non-existant process */
  if( persist_pipes[index].pid == -1 ) {
    return 0;
  }

  /* Setup our signal action to catch SIGPIPEs */
  sa.sa_handler = NULL;
  sa.sa_sigaction = &sigpipe_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  if( sigaction( SIGPIPE, &sa, &osa ) ) {
    DEBUGP("write_persist_pipe: sigaction failed: %d", errno);
  }

  /* Do the write */
  wret = write( persist_pipes[index].fdOut, data, strlen(data) );
  werrno = errno;

  /* Reset the signal handler */
  sigaction( SIGPIPE, &osa, (struct sigaction *) 0 );

  if( wret < 0 ) {
    if( werrno != EINTR ) {
      DEBUGP("write_persist_pipe: write returned unknown error %d", errno);
    }
    close_persist_pipe(index);
    return 0;
  }

  return 1;
}

static int close_persist_pipe(index)
  int index;
{

  /* Check and nix every item */
  if( persist_pipes[index].fOut ) {
    fclose( persist_pipes[index].fOut );
    persist_pipes[index].fOut = (FILE *) 0;
  }
  if( persist_pipes[index].fdOut != -1 ) {
    close( persist_pipes[index].fdOut );
    persist_pipes[index].fdOut = -1;
  }
  if( persist_pipes[index].fIn ) {
    fclose( persist_pipes[index].fIn );
    persist_pipes[index].fIn = (FILE *) 0;
  }
  if( persist_pipes[index].fdIn != -1 ) {
    close( persist_pipes[index].fdIn );
    persist_pipes[index].fdIn = -1;
  }
  if( persist_pipes[index].pid != -1 ) {
    waitpid(persist_pipes[index].pid,0,0);
    persist_pipes[index].pid = -1;
  }

}



