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
#if HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif

#include "mibincl.h"
#include "struct.h"
#include "pass.h"
#include "extensible.h"
#include "util_funcs.h"
#include "read_config.h"
#include "../../../snmplib/system.h"

struct extensible *passthrus=NULL;
int numpassthrus=0;

/* the relocatable extensible commands variables */
struct variable2 extensible_passthru_variables[] = {
  /* bogus entry.  Only some of it is actually used. */
  {MIBINDEX, ASN_INTEGER, RWRITE, var_extensible_pass, 0, {MIBINDEX}},
};

void pass_parse_config(word,cptr)
  char *word;
  char *cptr;
{
  struct extensible **ppass = &passthrus, **etmp, *ptmp;
  char *tcptr;
  int i;
  
  if (*cptr == '.') cptr++;
  if (!isdigit(*cptr)) {
    config_perror("second token is not a OID");
    return;
  }
  numpassthrus++;
  
  while(*ppass != NULL)
    ppass = &((*ppass)->next);
  (*ppass) = (struct extensible *) malloc(sizeof(struct extensible));
  (*ppass)->type = PASSTHRU;

  (*ppass)->miblen = parse_miboid(cptr,(*ppass)->miboid);
  while (isdigit(*cptr) || *cptr == '.') cptr++;
  /* name */
  cptr = skip_white(cptr);
  if (cptr == NULL) {
    config_perror("No command specified on pass line");
    (*ppass)->command[0] = 0;
  } else {
    for(tcptr=cptr; *tcptr != 0 && *tcptr != '#' && *tcptr != ';';
        tcptr++);
    strncpy((*ppass)->command,cptr,tcptr-cptr);
    (*ppass)->command[tcptr-cptr] = 0;
  }
  strcpy((*ppass)->name, (*ppass)->command);
  (*ppass)->next = NULL;

  register_mib("pass", (struct variable *) extensible_passthru_variables,
               sizeof(struct variable2),
               1, (*ppass)->miboid, (*ppass)->miblen);

  /* argggg -- pasthrus must be sorted */
  if (numpassthrus > 0) {
    etmp = (struct extensible **)
      malloc(((sizeof(struct extensible *)) * numpassthrus));
    for(i=0,ptmp = (struct extensible *) passthrus;
        i < numpassthrus && ptmp != 0;
        i++, ptmp = ptmp->next)
      etmp[i] = ptmp;
    qsort(etmp, numpassthrus, sizeof(struct extensible *),
#ifdef __STDC__
         (int (*)(const void *, const void *)) pass_compare
#else
	  pass_compare
#endif
          
      );
    passthrus = (struct extensible *) etmp[0];
    ptmp = (struct extensible *) etmp[0];
    
    for(i=0; i < numpassthrus-1; i++) {
      ptmp->next = etmp[i+1];
      ptmp = ptmp->next;
    }
    ptmp->next = NULL;
    free(etmp);
  }
}

void pass_free_config __P((void)) {
  struct extensible *etmp, *etmp2;
  
  for (etmp = passthrus; etmp != NULL;) {
    etmp2 = etmp;
    etmp = etmp->next;
    unregister_mib(etmp2->miboid, etmp2->miblen);
    free(etmp2);
  }
  passthrus = NULL;
  numpassthrus = 0;
}



  


unsigned char *var_extensible_pass(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
/* IN - pointer to variable entry that points here */
    register oid	*name;
/* IN/OUT - input name requested, output name found */
    register int	*length;
/* IN/OUT - length of input and output oid's */
    int			exact;
/* IN - TRUE if an exact match was requested. */
    int			*var_len;
/* OUT - length of variable or 0 if function returned. */
    int			(**write_method) __P((int, u_char *, u_char, int, u_char *,oid *, int));
/* OUT - pointer to function to set variable, otherwise 0 */
{

  oid newname[30];
  int i, j, rtest=0, fd, newlen, last;
  static long long_ret;
  static char buf[300], buf2[300];
  static oid  objid[30];
  struct extensible *passthru;
  FILE *file;

  long_ret = *length;
  for(i=1; i<= numpassthrus; i++) {
    passthru = get_exten_instance(passthrus,i);
    last = passthru->miblen;
    if (passthru->miblen > *length)
      last = *length;
    for(j=0,rtest=0; j < last && !rtest; j++) {
      if (name[j] != passthru->miboid[j]) {
        if (name[j] < passthru->miboid[j])
          rtest = -1;
        else
          rtest = 1;
      }
    }
    if ((exact && rtest == 0) || (!exact && rtest <= 0)) {
      /* setup args */
      if (passthru->miblen >= *length || rtest < 0)
        sprint_mib_oid(buf, passthru->miboid, passthru->miblen);
      else 
        sprint_mib_oid(buf, name, *length);
      if (exact)
        sprintf(passthru->command,"%s -g %s",passthru->name,buf);
      else
        sprintf(passthru->command,"%s -n %s",passthru->name,buf);
      DEBUGP("pass-running:  %s\n",passthru->command);
      /* valid call.  Exec and get output */
      if ((fd = get_exec_output(passthru))) {
        file = fdopen(fd,"r");
        if (fgets(buf,STRMAX,file) == NULL) {
          *var_len = 0;
          fclose(file);
          close(fd);
          wait_on_exec(passthru);
          return(NULL);
        }
        newlen = parse_miboid(buf,newname);

        /* its good, so copy onto name/length */
        memcpy( (char *)name,(char *) newname, (int)newlen * sizeof (oid));
        *length = newlen;

        /* set up return pointer for setable stuff */
        *write_method = setPass;

        if (newlen == 0 || fgets(buf,STRMAX,file) == NULL
            || fgets(buf2,STRMAX,file) == NULL) {
          *var_len = 0;
          fclose(file);
          close(fd);
          wait_on_exec(passthru);
          return(NULL);
        }
        fclose(file);
        close(fd);
        wait_on_exec(passthru);
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
setPass(action, var_val, var_val_type, var_val_len, statP, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      name_len;
{
  int i, j, rtest, tmplen=1000, last;
  struct extensible *passthru;

  static char buf[300], buf2[300];
  static long tmp;
  static unsigned long utmp;
  static int itmp;
  static oid objid[30];
  
  for(i=1; i<= numpassthrus; i++) {
    passthru = get_exten_instance(passthrus,i);
    last = passthru->miblen;
    if (passthru->miblen > name_len)
      last = name_len;
    for(j=0,rtest=0; j < last && !rtest; j++) {
      if (name[j] != passthru->miboid[j]) {
        if (name[j] < passthru->miboid[j])
          rtest = -1;
        else
          rtest = 1;
      }
    }
    if (rtest <= 0) {
      if (action != COMMIT)
        return SNMP_ERR_NOERROR;
      /* setup args */
      if (passthru->miblen >= name_len || rtest < 0)
        sprint_mib_oid(buf, passthru->miboid, passthru->miblen);
      else 
        sprint_mib_oid(buf, name, name_len);
      sprintf(passthru->command,"%s -s %s ",passthru->name,buf);
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
      strcat(passthru->command,buf);
      DEBUGP("pass-running:  %s\n",passthru->command);
      exec_command(passthru);
      if (!strncasecmp(passthru->output,"not-writable",11)) {
        return SNMP_ERR_NOTWRITABLE;
      } else if (!strncasecmp(passthru->output,"wrong-type",9)) {
        return SNMP_ERR_WRONGTYPE;
      } 
      return SNMP_ERR_NOERROR;
    }
  }
  if (snmp_get_do_debugging()) {
    sprint_mib_oid(buf2,name,name_len);
    DEBUGP("pass-notfound:  %s\n",buf2);
  }
  return SNMP_ERR_NOSUCHNAME;
}

int pass_compare(a, b)
  void *a, *b;
{
  struct extensible **ap, **bp;
  ap = (struct extensible **) a;
  bp = (struct extensible **) b;
  return compare((*ap)->miboid,(*ap)->miblen,(*bp)->miboid,(*bp)->miblen);
}
