/* ucdDemoPublic.c */

#include <config.h>

#include "mibincl.h"
#include "snmpv3.h"
#include "snmpusm.h"
#include "ucdDemoPublic.h"

#define MYMAX 1024
#define MAXUSERS 10

int num=0;
static char demoUsers[MAXUSERS][MYMAX];
static char demopass[MYMAX];

void ucdDemo_parse_user(char *word, char *line) {
  if (num == MAXUSERS)
    return;

  if (strlen(line) > MYMAX)
    return;
  
  strcpy(demoUsers[num++], line);
}


void ucdDemo_parse_userpass(char *word, char *line) {
  if (strlen(line) > MYMAX)
    return;
  
  strcpy(demopass, line);
}


void init_ucdDemoPublic(void) {
  snmpd_register_config_handler("demoUser",
                                ucdDemo_parse_user, NULL);
  snmpd_register_config_handler("demoPass",
                                ucdDemo_parse_userpass, NULL);
}

unsigned char publicString[MYMAX];

unsigned char *
var_ucdDemoPublic(vp, name, length, exact, var_len, write_method)
    struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) (int, unsigned char *,unsigned char, int, unsigned char *,oid*, int);
{

  static long long_ret;
  static char string[MYMAX], *cp;
  int i;
  
  *write_method = 0;           /* assume it isnt writable for the time being */
  *var_len = sizeof(long_ret); /* assume an integer and change later if not */

  if (header_generic(vp,name,length,exact,var_len,write_method))
      return 0;

  /* this is where we do the value assignments for the mib results. */
  switch(vp->magic) {

    case UCDDEMORESETKEYS:
      *write_method = write_ucdDemoResetKeys;
      long_ret = 0;
      return (unsigned char *) &long_ret;

    case UCDDEMOPUBLICSTRING:
      *write_method = write_ucdDemoPublicString;
      *var_len = strlen(publicString);
      return (unsigned char *) publicString;

    case UCDDEMOUSERLIST:
      cp = string;
      for(i=0; i < num; i++) {
        sprintf(cp, " %s", demoUsers[i]);
        cp = cp + strlen(cp);
      }
      *var_len = strlen(string);
      return (unsigned char *) string;
      
    case UCDDEMOPASSPHRASE:
      *var_len = strlen(demopass);
      return (unsigned char *) demopass;
      
    default:
      ERROR_MSG("");
  }
  return 0;
}

int
write_ucdDemoResetKeys(action, var_val, var_val_type, var_val_len, statP, name, name_len)
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
  static unsigned char string[1500];
  static oid objid[30];
  static struct counter64 c64;
  int size, bigsize=1000;
  unsigned char *engineID;
  int engineIDLen;
  int i;
  struct usmUser *user;

  if (var_val_type != ASN_INTEGER) {
      DEBUGP("write to ucdDemoResetKeys not ASN_INTEGER\n");
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > sizeof(long_ret)) {
      DEBUGP("write to ucdDemoResetKeys: bad length\n");
      return SNMP_ERR_WRONGLENGTH;
  }
  if (action == COMMIT) {
      size = sizeof(long_ret);
      asn_parse_int(var_val, &bigsize, &var_val_type, &long_ret, size);
      if (long_ret == 1) {
        engineID = snmpv3_generate_engineID(&engineIDLen);
        for(i=0; i < num; i++) {
          user = usm_get_user(engineID, engineIDLen, demoUsers[i]);
          if (user) {
            usm_set_user_password(user, "userSetAuthPass", demopass);
            usm_set_user_password(user, "userSetPrivPass", demopass);
          }
        }
        /* reset the keys */
      }
  }
  return SNMP_ERR_NOERROR;
}

int
write_ucdDemoPublicString(action, var_val, var_val_type, var_val_len, statP, name, name_len)
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
  static unsigned char string[1500];
  static oid objid[30];
  static struct counter64 c64;
  int size, bigsize=1000;

  if (var_val_type != ASN_OCTET_STR) {
      DEBUGP("write to ucdDemoPublicString not ASN_OCTET_STR\n");
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > sizeof(string)) {
      DEBUGP("write to ucdDemoPublicString: bad length\n");
      return SNMP_ERR_WRONGLENGTH;
  }
  if (action == COMMIT) {
      size = sizeof(string);
      asn_parse_string(var_val, &bigsize, &var_val_type, string, &size);
      string[size] = 0;
      if (size > MYMAX)
        return SNMP_ERR_TOOBIG;
      strcpy(publicString, string);
  }
  return SNMP_ERR_NOERROR;
}

