#include <config.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <stdio.h>
#if HAVE_STRINGS_H
#include <strings.h>
#else
#if STDC_HEADERS
#include <string.h>
#endif
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include "mibincl.h"
#include "mibdefs.h"
#include "extproto.h"

#ifdef USEPASSMIB

struct extensible *passthrus=NULL;
int numpassthrus=0;

int setPass __P((int, u_char *, u_char, int, u_char *,oid *, int));

/* the relocatable extensible commands variables */
struct variable2 extensible_passthru_variables[] = {
  /* bogus entry.  Only some of it is actually used. */
  {MIBINDEX, INTEGER, RWRITE, var_extensible_pass, 0, {MIBINDEX}},
};

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
      DEBUGP1("pass-running:  %s\n",passthru->command);
      /* valid call.  Exec and get output */
      if ((fd = get_exec_output(passthru))) {
        file = fdopen(fd,"r");
        if (fgets(buf,STRMAX,file) == NULL) {
          *var_len = 0;
          fclose(file);
          close(fd);
          return(NULL);
        }
        newlen = parse_miboid(buf,newname);

        /* its good, so copy onto name/length */
        bcopy((char *) newname, (char *)name, (int)newlen * sizeof (oid));
        *length = newlen;

        /* set up return pointer for setable stuff */
        *write_method = setPass;

        if (newlen == 0 || fgets(buf,STRMAX,file) == NULL
            || fgets(buf2,STRMAX,file) == NULL) {
          *var_len = 0;
          fclose(file);
          close(fd);
          return(NULL);
        }
        fclose(file);
        close(fd);
        /* buf contains the return type, and buf2 contains the data */
        if (!strncasecmp(buf,"string",6)) {
          buf2[strlen(buf2)-1] = 0;  /* zap the linefeed */
          *var_len = strlen(buf2);
          vp->type = STRING;
          return((unsigned char *) buf2);
        } else if (!strncasecmp(buf,"integer",7)) {
          *var_len = sizeof(long_ret);
          long_ret = atoi(buf2);
          vp->type = INTEGER;
          return((unsigned char *) &long_ret);
        } else if (!strncasecmp(buf,"counter",7)) {
          *var_len = sizeof(long_ret);
          long_ret = atoi(buf2);
          vp->type = COUNTER;
          return((unsigned char *) &long_ret);
        } else if (!strncasecmp(buf,"gauge",5)) {
          *var_len = sizeof(long_ret);
          long_ret = atoi(buf2);
          vp->type = GAUGE;
          return((unsigned char *) &long_ret);
        } else if (!strncasecmp(buf,"objectid",8)) {
          newlen = parse_miboid(buf2,objid);
          *var_len = newlen*sizeof(oid);
          vp->type = OBJID;
          return((unsigned char *) objid);
        } else if (!strncasecmp(buf,"timetick",8)) {
          *var_len = sizeof(long_ret);
          long_ret = atoi(buf2);
          vp->type = TIMETICKS;
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
          vp->type = IPADDRESS;
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
        case INTEGER:
        case COUNTER:
        case GAUGE:
        case TIMETICKS:
          asn_parse_int(var_val,&tmplen,&var_val_type, &tmp,
                        sizeof(tmp));
          switch (var_val_type) {
            case INTEGER:
              sprintf(buf,"integer %d",(int) tmp);
              break;
            case COUNTER:
              sprintf(buf,"counter %d",(int) tmp);
              break;
            case GAUGE:
              sprintf(buf,"gauge %d",(int) tmp);
              break;
            case TIMETICKS:
              sprintf(buf,"timeticks %d",(int) tmp);
              break;
          }
          break;
        case IPADDRESS:
          asn_parse_unsigned_int(var_val,&tmplen,&var_val_type, &utmp,
                                 sizeof(utmp));
          sprintf(buf,"ipaddress %d.%d.%d.%d",
                  (int) ((utmp & 0xff000000) >> (8*3)),
                  (int) ((utmp & 0xff0000) >> (8*2)),
                  (int) ((utmp & 0xff00) >> (8)),
                  (int) ((utmp & 0xff)));
          break;
        case STRING:
          itmp = sizeof(buf);
          bzero(buf2,itmp);
          asn_parse_string(var_val,&tmplen,&var_val_type,buf2,&itmp);
          sprintf(buf,"string %s",buf2);
          break;
        case OBJID:
          itmp = sizeof(objid);
          asn_parse_objid(var_val,&tmplen,&var_val_type,objid,&itmp);
          sprint_mib_oid(buf2, objid, itmp);
          sprintf(buf,"objectid \"%s\"",buf2);
          break;
      }
      strcat(passthru->command,buf);
      DEBUGP1("pass-running:  %s\n",passthru->command);
      exec_command(passthru);
      if (!strncasecmp(passthru->output,"not-writable",11)) {
        return SNMP_ERR_NOTWRITABLE;
      } else if (!strncasecmp(passthru->output,"wrong-type",9)) {
        return SNMP_ERR_WRONGTYPE;
      } 
      return SNMP_ERR_NOERROR;
    }
  }
#ifdef DODEBUG
  sprint_mib_oid(buf2,name,name_len);
  DEBUGP1("pass-notfound:  %s\n",buf2);
#endif
  return SNMP_ERR_NOSUCHNAME;
}
  
#endif  /* USEPASSMIB */
