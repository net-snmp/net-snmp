/* snmpEngine.c: implement's the SNMP-FRAMEWORK-MIB. */

#include <config.h>

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

#include "mibincl.h"
#include "snmpv3.h"
#include "util_funcs.h"
#include "../mibII/sysORTable.h"
#include "snmpEngine.h"

void init_snmpEngine __P((void)) {
/* place any initialization routines needed here */
#ifdef USING_MIBII_SYSORTABLE_MODULE
  static oid reg[] = {1,3,6,1,6,3,10,3,1,1};
  register_sysORTable(reg,10,"The SNMP Management Architecture MIB.");
#endif
}

extern struct timeval starttime;

/* shhhhhhhhh! */
int write_engineBoots(int, u_char *,u_char, int, u_char *,oid*, int);
int write_engineTime(int, u_char *,u_char, int, u_char *,oid*, int);

unsigned char *
var_snmpEngine(vp, name, length, exact, var_len, write_method)
    struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, unsigned char *,unsigned char, int, unsigned char *,oid*, int));
{

  /* variables we may use later */
  static long long_ret;
  static unsigned char engineID[SNMP_MAXBUF];

  *write_method = 0;           /* assume it isnt writable for the time being */
  *var_len = sizeof(long_ret); /* assume an integer and change later if not */

  if (header_generic(vp,name,length,exact,var_len,write_method))
      return 0;

  /* this is where we do the value assignments for the mib results. */
  switch(vp->magic) {

    case SNMPENGINEID:
      *var_len = snmpv3_get_engineID(engineID, SNMP_MAXBUF);
      /* XXX  Set ERROR_MSG() upon error? */
      return (unsigned char *) engineID;

    case SNMPENGINEBOOTS:
      *write_method = write_engineBoots;
      long_ret = snmpv3_local_snmpEngineBoots();
      return (unsigned char *) &long_ret;

    case SNMPENGINETIME:
      *write_method = write_engineTime;
      long_ret = snmpv3_local_snmpEngineTime();
      return (unsigned char *) &long_ret;

    case SNMPENGINEMAXMESSAGESIZE:
      long_ret = 1500;
      return (unsigned char *) &long_ret;

    default:
      ERROR_MSG("");
  }
  return 0;
}

/* write_engineBoots():

   XXX: This is technically not writable, but we allow it so we can run
   some time synchronization tests.
*/
int
write_engineBoots(action, var_val, var_val_type, var_val_len, statP, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      name_len;
{
  /* variables we may use later */
  static long long_ret;
  int size, bigsize=SNMP_MAXBUF_MEDIUM;
  char buf[SNMP_MAXBUF_MEDIUM];
  u_char engineIDBuf[SNMP_MAXBUF_MEDIUM];
  int engineIDBufLen = 0;
  u_int boots_uint = 0;
  u_int time_uint = 0;

  if (var_val_type != ASN_INTEGER){
      DEBUGP("write to engineBoots not ASN_INTEGER\n");
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > sizeof(long_ret)){
      DEBUGP("write to engineBoots: bad length\n");
      return SNMP_ERR_WRONGLENGTH;
  }
  size = sizeof(long_ret);
  asn_parse_int(var_val, &bigsize, &var_val_type, &long_ret, size);
  if (action == COMMIT) {
    engineIDBufLen = snmpv3_get_engineID(engineIDBuf, SNMP_MAXBUF_MEDIUM);
    /* set our local engineTime in the LCD timing cache */
    snmpv3_set_engineBootsAndTime(long_ret, snmpv3_local_snmpEngineTime());
    set_enginetime(engineIDBuf, engineIDBufLen, 
                   snmpv3_local_snmpEngineBoots(), 
                   snmpv3_local_snmpEngineTime(),
                   TRUE);
  }
  return SNMP_ERR_NOERROR;
}

/* write_engineTime():

   XXX: This is technically not writable, but we allow it so we can run
   some time synchronization tests.
*/
int
write_engineTime(action, var_val, var_val_type, var_val_len, statP, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      name_len;
{
  /* variables we may use later */
  static long long_ret;
  int size, bigsize=SNMP_MAXBUF_MEDIUM;
  char buf[SNMP_MAXBUF_MEDIUM];
  u_char engineIDBuf[SNMP_MAXBUF_MEDIUM];
  int engineIDBufLen = 0;
  u_int boots_uint = 0;
  u_int time_uint = 0;

  if (var_val_type != ASN_INTEGER){
      DEBUGP("write to engineTime not ASN_INTEGER\n");
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > sizeof(long_ret)){
      DEBUGP("write to engineTime: bad length\n");
      return SNMP_ERR_WRONGLENGTH;
  }
  size = sizeof(long_ret);
  asn_parse_int(var_val, &bigsize, &var_val_type, &long_ret, size);
  if (action == COMMIT) {
    engineIDBufLen = snmpv3_get_engineID(engineIDBuf, SNMP_MAXBUF_MEDIUM);
    /* set our local engineTime in the LCD timing cache */
    snmpv3_set_engineBootsAndTime(snmpv3_local_snmpEngineBoots(), long_ret);
    set_enginetime(engineIDBuf, engineIDBufLen, 
                   snmpv3_local_snmpEngineBoots(), 
                   snmpv3_local_snmpEngineTime(),
                   TRUE);
  }
  return SNMP_ERR_NOERROR;
}
