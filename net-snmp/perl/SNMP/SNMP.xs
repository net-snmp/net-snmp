/*
     SNMP.xs -- Perl 5 interface to the UCD SNMP toolkit

     written by G. S. Marzot (gmarzot@nortelnetworks.com)

     Copyright (c) 1995-1999 G. S. Marzot. All rights reserved.
     This program is free software; you can redistribute it and/or
     modify it under the same terms as Perl itself.
*/
#define WIN32SCK_IS_STDSCK
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <sys/types.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <ctype.h>
#ifdef I_SYS_TIME
#include <sys/time.h>
#endif
#include <netdb.h>
#include <stdlib.h>

#ifndef __P
#define __P(x) x
#endif

#ifndef na
#define na PL_na
#endif

#ifndef sv_undef
#define sv_undef PL_sv_undef
#endif

#ifndef stack_base
#define stack_base PL_stack_base
#endif

#ifndef G_VOID
#define G_VOID G_DISCARD
#endif

#ifdef WIN32
#define SOCK_STARTUP winsock_startup()
#define SOCK_CLEANUP winsock_cleanup()
#define DLL_IMPORT   __declspec( dllimport )
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#else
#define SOCK_STARTUP
#define SOCK_CLEANUP
#define DLL_IMPORT
#endif

extern int Suffix;
DLL_IMPORT extern struct tree *Mib;
#include "ucd-snmp/ucd-snmp-config.h"
#include "ucd-snmp/asn1.h"
#include "ucd-snmp/snmp_api.h"
#include "ucd-snmp/snmp_client.h"
#include "ucd-snmp/snmp_impl.h"
#include "ucd-snmp/snmp.h"
#undef CMU_COMPATIBLE
#include "ucd-snmp/parse.h"
#include "ucd-snmp/mib.h"
#include "ucd-snmp/scapi.h"
#include "ucd-snmp/keytools.h"
#include "ucd-snmp/snmpv3.h"
#include "ucd-snmp/transform_oids.h"
#include "ucd-snmp/default_store.h"


#include "perlsnmp.h"

#define SUCCESS 1
#define FAILURE 0

#define ZERO_BUT_TRUE "0 but true"

#define VARBIND_TAG_F 0
#define VARBIND_IID_F 1
#define VARBIND_VAL_F 2
#define VARBIND_TYPE_F 3

#define TYPE_UNKNOWN 0
#define MAX_TYPE_NAME_LEN 16
#define STR_BUF_SIZE 1024
#define ENG_ID_BUF_SIZE 32

#define SYS_UPTIME_OID_LEN 9
#define SNMP_TRAP_OID_LEN 11
#define NO_RETRY_NOSUCH 0
static oid sysUpTime[SYS_UPTIME_OID_LEN] = {1, 3, 6, 1, 2, 1, 1, 3, 0};
static oid snmpTrapOID[SNMP_TRAP_OID_LEN] = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};

/* these should be part of transform_oids.h ? */
#define USM_AUTH_PROTO_MD5_LEN 10
#define USM_AUTH_PROTO_SHA_LEN 10
#define USM_PRIV_PROTO_DES_LEN 10

/* why does ucd-snmp redefine sockaddr_in ??? */
#define SIN_ADDR(snmp_addr) (((struct sockaddr_in *) &(snmp_addr))->sin_addr)

typedef struct snmp_session SnmpSession;
typedef struct tree SnmpMibNode;
typedef struct snmp_xs_cb_data {
    SV* perl_cb;
    SV* sess_ref;
} snmp_xs_cb_data;

static void __recalc_timeout _((struct timeval*,struct timeval*,
                                struct timeval*,struct timeval*, int* ));
static in_addr_t __parse_address _((char*));
static int __is_numeric_oid _((char*));
static int __is_leaf _((struct tree*));
static int __translate_appl_type _((char*));
static int __translate_asn_type _((int));
static int __sprint_value _((char *, struct variable_list*, struct tree *,
                             int, int));
static int __sprint_num_objid _((char *, oid *, int));
static int __scan_num_objid _((char *, oid *, int *));
static int __get_type_str _((int, char *));
static int __get_label_iid _((char *, char **, char **, int));
static int __oid_cmp _((oid *, int, oid *, int));
static int __tp_sprint_num_objid _((char*,SnmpMibNode *));
static SnmpMibNode * __get_next_mib_node _((SnmpMibNode *));
static struct tree * __oid2tp _((oid*, int, struct tree *, int*));
static struct tree * __tag2oid _((char *, char *, oid  *, int  *, int *));
static int __concat_oid_str _((oid *, int *, char *));
static int __add_var_val_str _((struct snmp_pdu *, oid *, int, char *,
                                 int, int));
static int __send_sync_pdu _((struct snmp_session *, struct snmp_pdu *,
                              struct snmp_pdu **, int , SV *, SV *, SV *));
static int __snmp_xs_cb __P((int, struct snmp_session *, int,
                             struct snmp_pdu *, void *));
static int __push_cb_args _((SV ** svp, SV * esv));
static int __call_callback _((SV * sv, int flags));
static char* __av_elem_pv _((AV * av, I32 key, char *dflt));

#define NON_LEAF_NAME 0x04
#define USE_LONG_NAMES 0x02
#define FAIL_ON_NULL_IID 0x01
#define NO_FLAGS 0x00

static void
__recalc_timeout (tvp, ctvp, ltvp, itvp, block)
struct timeval* tvp;
struct timeval* ctvp;
struct timeval* ltvp;
struct timeval* itvp;
int *block;
{
   struct timeval now;

   if (!timerisset(itvp)) return;  /* interval zero means loop forever */
   *block = 0;
   gettimeofday(&now,(struct timezone *)0);

   if (ctvp->tv_sec < 0) { /* first time or callback just fired */
      timersub(&now,ltvp,ctvp);
      timersub(ctvp,itvp,ctvp);
      timersub(itvp,ctvp,ctvp);
      timeradd(ltvp,itvp,ltvp);
   } else {
      timersub(&now,ltvp,ctvp);
      timersub(itvp,ctvp,ctvp);
   }

   /* flag is set for callback but still hasnt fired so set to something
    * small and we will service packets first if there are any ready
    * (also guard against negative timeout - should never happen?)
    */
   if (!timerisset(ctvp) || ctvp->tv_sec < 0 || ctvp->tv_usec < 0) {
      ctvp->tv_sec = 0;
      ctvp->tv_usec = 10;
   }

   /* if snmp timeout > callback timeout or no more requests to process */
   if (timercmp(tvp, ctvp, >) || !timerisset(tvp)) {
      *tvp = *ctvp; /* use the smaller non-zero timeout */
      timerclear(ctvp); /* used as a flag to let callback fire on timeout */
   }
}

static in_addr_t
__parse_address(address)
char *address;
{
    in_addr_t addr;
    struct sockaddr_in saddr;
    struct hostent *hp;

    if ((addr = inet_addr(address)) != -1)
	return addr;
    hp = gethostbyname(address);
    if (hp == NULL){
        return (-1); /* error value */
    } else {
	memcpy(&saddr.sin_addr, hp->h_addr, hp->h_length);
	return saddr.sin_addr.s_addr;
    }

}

static int
__is_numeric_oid (oidstr)
char* oidstr;
{
  if (!oidstr) return 0;
  for (; *oidstr; oidstr++) {
     if (isalpha(*oidstr)) return 0;
  }
  return(1);
}

static int
__is_leaf (tp)
struct tree* tp;
{
   char buf[MAX_TYPE_NAME_LEN];
   return (tp && __get_type_str(tp->type,buf));
}

static SnmpMibNode*
__get_next_mib_node (tp)
SnmpMibNode* tp;
{
   /* printf("tp = %lX, parent = %lX, peer = %lX, child = %lX\n",
              tp, tp->parent, tp->next_peer, tp->child_list); */
   if (tp->child_list) return(tp->child_list);
   if (tp->next_peer) return(tp->next_peer);
   if (!tp->parent) return(NULL);
   for (tp = tp->parent; !tp->next_peer; tp = tp->parent) {
      if (!tp->parent) return(NULL);
   }
   return(tp->next_peer);
}

static int
__translate_appl_type(typestr)
char* typestr;
{
	if (typestr == NULL || *typestr == '\0') return TYPE_UNKNOWN;

	if (!strncasecmp(typestr,"INTEGER",3))
            return(TYPE_INTEGER);
	if (!strcasecmp(typestr,"COUNTER")) /* check all in case counter64 */
            return(TYPE_COUNTER);
	if (!strncasecmp(typestr,"GAUGE",3))
            return(TYPE_GAUGE);
	if (!strncasecmp(typestr,"IPADDR",3))
            return(TYPE_IPADDR);
	if (!strncasecmp(typestr,"OCTETSTR",3))
            return(TYPE_OCTETSTR);
	if (!strncasecmp(typestr,"TICKS",3))
            return(TYPE_TIMETICKS);
	if (!strncasecmp(typestr,"OPAQUE",3))
            return(TYPE_OPAQUE);
	if (!strncasecmp(typestr,"OBJECTID",3))
            return(TYPE_OBJID);
	if (!strncasecmp(typestr,"NETADDR",3))
	    return(TYPE_NETADDR);
	if (!strncasecmp(typestr,"COUNTER64",3))
	    return(TYPE_COUNTER64);
	if (!strncasecmp(typestr,"NULL",3))
	    return(TYPE_NULL);
	if (!strncasecmp(typestr,"ENDOFMIBVIEW",3))
	    return(SNMP_ENDOFMIBVIEW);
	if (!strncasecmp(typestr,"NOSUCHOBJECT",7))
	    return(SNMP_NOSUCHOBJECT);
	if (!strncasecmp(typestr,"NOSUCHINSTANCE",7))
	    return(SNMP_NOSUCHINSTANCE);
	if (!strncasecmp(typestr,"UINTEGER",3))
	    return(TYPE_UINTEGER); /* historic - should not show up */
                                   /* but it does?                  */
        return(TYPE_UNKNOWN);
}

static int
__translate_asn_type(type)
int type;
{
   switch (type) {
        case ASN_INTEGER:
            return(TYPE_INTEGER);
	    break;
	case ASN_OCTET_STR:
            return(TYPE_OCTETSTR);
	    break;
	case ASN_OPAQUE:
            return(TYPE_OPAQUE);
	    break;
	case ASN_OBJECT_ID:
            return(TYPE_OBJID);
	    break;
	case ASN_TIMETICKS:
            return(TYPE_TIMETICKS);
	    break;
	case ASN_GAUGE:
            return(TYPE_GAUGE);
	    break;
	case ASN_COUNTER:
            return(TYPE_COUNTER);
	    break;
	case ASN_IPADDRESS:
            return(TYPE_IPADDR);
	    break;
	case ASN_NULL:
            return(TYPE_NULL);
	    break;
	/* no translation for these exception type values */
	case SNMP_ENDOFMIBVIEW:
	case SNMP_NOSUCHOBJECT:
	case SNMP_NOSUCHINSTANCE:
	    return(type);
	    break;
	case ASN_UINTEGER:
            return(TYPE_UINTEGER);
	    break;
	default:
            warn("translate_asn_type: unhandled asn type (%d)\n",type);
            return(TYPE_OTHER);
            break;
        }
}

#define USE_BASIC 0
#define USE_ENUMS 1
#define USE_SPRINT_VALUE 2
static int
__sprint_value (buf, var, tp, type, flag)
char * buf;
struct variable_list * var;
struct tree * tp;
int type;
int flag;
{
   int len = 0;
   u_char* ip;
   struct enum_list *ep;


   buf[0] = '\0';
   if (flag == USE_SPRINT_VALUE) {
	sprint_value(buf, var->name, var->name_length, var);
	len = strlen(buf);
   } else {
     switch (var->type) {
        case ASN_INTEGER:
           if (flag == USE_ENUMS) {
              for(ep = tp->enums; ep; ep = ep->next) {
                 if (ep->value == *var->val.integer) {
                    strcpy(buf, ep->label);
                    len = strlen(buf);
                    break;
                 }
              }
           }
           if (!len) {
              sprintf(buf,"%ld", *var->val.integer);
              len = strlen(buf);
           }
           break;

        case ASN_GAUGE:
        case ASN_COUNTER:
        case ASN_TIMETICKS:
        case ASN_UINTEGER:
           sprintf(buf,"%lu", (unsigned long) *var->val.integer);
           len = strlen(buf);
           break;

        case ASN_OCTET_STR:
        case ASN_OPAQUE:
           bcopy((char*)var->val.string, buf, var->val_len);
           len = var->val_len;
           break;

        case ASN_IPADDRESS:
          ip = (u_char*)var->val.string;
          sprintf(buf, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
          len = strlen(buf);
          break;

        case ASN_NULL:
           break;

        case ASN_OBJECT_ID:
          __sprint_num_objid(buf, (oid *)(var->val.objid),
                             var->val_len/sizeof(oid));
          len = strlen(buf);
          break;

	case SNMP_ENDOFMIBVIEW:
          sprintf(buf,"%s", "ENDOFMIBVIEW");
	  break;
	case SNMP_NOSUCHOBJECT:
	  sprintf(buf,"%s", "NOSUCHOBJECT");
	  break;
	case SNMP_NOSUCHINSTANCE:
	  sprintf(buf,"%s", "NOSUCHINSTANCE");
	  break;

        case ASN_COUNTER64:
          printI64(buf,(struct counter64 *)var->val.counter64);
          len = strlen(buf);
          break;

        case ASN_BIT_STR:
        case ASN_NSAP:
        default:
           warn("sprint_value: asn type not handled %d\n",var->type);
     }
   }
   return(len);
}

static int
__sprint_num_objid (buf, objid, len)
char *buf;
oid *objid;
int len;
{
   int i;
   buf[0] = '\0';
   for (i=0; i < len; i++) {
	sprintf(buf,".%lu",*objid++);
	buf += strlen(buf);
   }
   return SUCCESS;
}

static int
__tp_sprint_num_objid (buf, tp)
char *buf;
SnmpMibNode *tp;
{
   oid newname[MAX_OID_LEN], *op;
   int newname_len = 0;
   /* code taken from get_node in snmp_client.c */
   for (op = newname + MAX_OID_LEN - 1; op >= newname; op--) {
      *op = tp->subid;
      tp = tp->parent;
      if (tp == NULL) break;
   }
   return __sprint_num_objid(buf, op, newname + MAX_OID_LEN - op);
}

static int
__scan_num_objid (buf, objid, len)
char *buf;
oid *objid;
int *len;
{
   char *cp;
   *len = 0;
   if (*buf == '.') buf++;
   cp = buf;
   while (*buf) {
      if (*buf++ == '.') {
         sscanf(cp, "%lu", objid++);
         /* *objid++ = atoi(cp); */
         (*len)++;
         cp = buf;
      } else {
         if (isalpha(*buf)) {
	    return FAILURE;
         }
      }
   }
   sscanf(cp, "%lu", objid++);
   /* *objid++ = atoi(cp); */
   (*len)++;
   return SUCCESS;
}

static int
__get_type_str (type, str)
int type;
char * str;
{
   switch (type) {
	case TYPE_OBJID:
       		strcpy(str, "OBJECTID");
	        break;
	case TYPE_OCTETSTR:
       		strcpy(str, "OCTETSTR");
	        break;
	case TYPE_INTEGER:
       		strcpy(str, "INTEGER");
	        break;
	case TYPE_NETADDR:
       		strcpy(str, "NETADDR");
	        break;
	case TYPE_IPADDR:
       		strcpy(str, "IPADDR");
	        break;
	case TYPE_COUNTER:
       		strcpy(str, "COUNTER");
	        break;
	case TYPE_GAUGE:
       		strcpy(str, "GAUGE");
	        break;
	case TYPE_TIMETICKS:
       		strcpy(str, "TICKS");
	        break;
	case TYPE_OPAQUE:
       		strcpy(str, "OPAQUE");
	        break;
	case TYPE_COUNTER64:
       		strcpy(str, "COUNTER64");
	        break;
	case TYPE_NULL:
                strcpy(str, "NULL");
                break;
	case SNMP_ENDOFMIBVIEW:
                strcpy(str, "ENDOFMIBVIEW");
                break;
	case SNMP_NOSUCHOBJECT:
                strcpy(str, "NOSUCHOBJECT");
                break;
	case SNMP_NOSUCHINSTANCE:
                strcpy(str, "NOSUCHINSTANCE");
                break;
	case TYPE_UINTEGER:
                strcpy(str, "UINTEGER"); /* historic - should not show up */
                                          /* but it does?                  */
                break;
	case TYPE_OTHER: /* not sure if this is a valid leaf type?? */
	case TYPE_BITSTRING:
	case TYPE_NSAPADDRESS:
        default: /* unsupported types for now */
           strcpy(str, "");
           return(FAILURE);
   }
   return SUCCESS;
}

/* does a destructive disection of <label1>...<labeln>.<iid> returning
   <labeln> and <iid> in seperate strings (note: will destructively
   alter input string, 'name') */
static int
__get_label_iid (name, last_label, iid, flag)
char * name;
char ** last_label;
char ** iid;
int flag;
{
   char *lcp;
   char *icp;
   int len = strlen(name);
   int found_label = 0;

   *last_label = *iid = NULL;

   if (len == 0) return(FAILURE);

   lcp = icp = &(name[len]);

   while (lcp > name) {
      if (*lcp == '.') {
	if (found_label) {
	   lcp++;
           break;
        } else {
           icp = lcp;
        }
      }
      if (!found_label && isalpha(*lcp)) found_label = 1;
      lcp--;
   }

   if (!found_label || (!isdigit(*(icp+1)) && (flag & FAIL_ON_NULL_IID)))
      return(FAILURE);

   if (flag & NON_LEAF_NAME) { /* dont know where to start instance id */
     /* put the whole thing in label */
     icp = &(name[len]);
     flag |= USE_LONG_NAMES;
     /* special hack in case no mib loaded - object identifiers will
      * start with .iso.<num>.<num>...., in which case it is preferable
      * to make the label entirely numeric (i.e., convert "iso" => "1")
      */
      if (*lcp == '.' && lcp == name) {
         if (!strncmp(".ccitt.",lcp,7)) {
            name += 2;
            *name = '.';
            *(name+1) = '0';
         } else if (!strncmp(".iso.",lcp,5)) {
            name += 2;
            *name = '.';
            *(name+1) = '1';
         } else if (!strncmp(".joint-iso-ccitt.",lcp,17)) {
            name += 2;
            *name = '.';
            *(name+1) = '2';
         }
      }
   } else if (*icp) {
      *(icp++) = '\0';
   }
   *last_label = (flag & USE_LONG_NAMES ? name : lcp);

   *iid = icp;

   return(SUCCESS);
}


static int
__oid_cmp(oida_arr, oida_arr_len, oidb_arr, oidb_arr_len)
oid *oida_arr;
int oida_arr_len;
oid *oidb_arr;
int oidb_arr_len;
{
   for (;oida_arr_len && oidb_arr_len;
	oida_arr++, oida_arr_len--, oidb_arr++, oidb_arr_len--) {
	if (*oida_arr == *oidb_arr) continue;
	return(*oida_arr > *oidb_arr ? 1 : -1);
   }
   if (oida_arr_len == oidb_arr_len) return(0);
   return(oida_arr_len > oidb_arr_len ? 1 : -1);
}

static struct tree *
__tag2oid(tag, iid, oid_arr, oid_arr_len, type)
char * tag;
char * iid;
oid  * oid_arr;
int  * oid_arr_len;
int  * type;
{
   struct tree *tp = NULL;
   struct tree *rtp = NULL;
   oid newname[MAX_OID_LEN], *op;
   int newname_len = 0;

   if (type) *type = TYPE_UNKNOWN;
   if (oid_arr_len) *oid_arr_len = 0;
   if (!tag) goto done;

   if (strchr(tag,'.')) { /* if multi part tag  */
      if (!__scan_num_objid(tag, newname, &newname_len)) { /* numeric tag */
         newname_len = MAX_OID_LEN;
         read_objid(tag, newname, &newname_len); /* long name */
      }
      if (newname_len) rtp = tp = get_tree(newname, newname_len, Mib);
      if (type) *type = (tp ? tp->type : TYPE_UNKNOWN);
      if ((oid_arr == NULL) || (oid_arr_len == NULL)) return rtp;
      bcopy((char*)newname,oid_arr,newname_len*sizeof(oid));
      *oid_arr_len = newname_len;
   } else { /* else it is a leaf */
      rtp = tp = find_node(tag, Mib);
      if (tp) {
         if (type) *type = tp->type;
         if ((oid_arr == NULL) || (oid_arr_len == NULL)) return rtp;
         /* code taken from get_node in snmp_client.c */
         for(op = newname + MAX_OID_LEN - 1; op >= newname; op--){
           *op = tp->subid;
	   tp = tp->parent;
	   if (tp == NULL)
	      break;
         }
         *oid_arr_len = newname + MAX_OID_LEN - op;
         bcopy(op, oid_arr, *oid_arr_len * sizeof(oid));
      } else {
         return(rtp);   /* HACK: otherwise, concat_oid_str confuses things */
      }
   }
 done:
   if (iid && *iid) __concat_oid_str(oid_arr, oid_arr_len, iid);
   return(rtp);
}
/* searches down the mib tree for the given oid
   returns the last found tp and its index in lastind
 */
static struct tree *
__oid2tp (oidp, len, subtree, lastind)
oid* oidp;
int len;
struct tree * subtree;
int* lastind;
{
    struct tree    *return_tree = NULL;


    for (; subtree; subtree = subtree->next_peer) {
	if (*oidp == subtree->subid){
	    goto found;
	}
    }
    *lastind=0;
    return NULL;

found:
    if (len > 1){
       return_tree =
          __oid2tp(oidp + 1, len - 1, subtree->child_list, lastind);
       *lastind++;
    } else {
       *lastind=1;
    }
    if (return_tree)
	return return_tree;
    else
	return subtree;
}

/* function: __concat_oid_str
 *
 * This function converts a dotted-decimal string, soid_str, to an array
 * of oid types and concatenates them on doid_arr begining at the index
 * specified by doid_arr_len.
 *
 * returns : SUCCESS, FAILURE
 */
static int
__concat_oid_str(doid_arr, doid_arr_len, soid_str)
oid *doid_arr;
int *doid_arr_len;
char * soid_str;
{
   char soid_buf[STR_BUF_SIZE];
   char *cp;

   if (!soid_str || !*soid_str) return SUCCESS;/* successfully added nothing */
   if (*soid_str == '.') soid_str++;
   strcpy(soid_buf, soid_str);
   cp = strtok(soid_buf,".");
   while (cp) {
     sscanf(cp, "%lu", &(doid_arr[(*doid_arr_len)++]));
     /* doid_arr[(*doid_arr_len)++] =  atoi(cp); */
     cp = strtok(NULL,".");
   }
   return(SUCCESS);
}

/*
 * add a varbind to PDU
 */
static int
__add_var_val_str(pdu, name, name_length, val, len, type)
    struct snmp_pdu *pdu;
    oid *name;
    int name_length;
    char * val;
    int len;
    int type;
{
    struct variable_list *vars;
    oid oidbuf[MAX_OID_LEN];
    int ret = SUCCESS;
    struct tree *tp;

    if (pdu->variables == NULL){
	pdu->variables = vars =
           (struct variable_list *)malloc(sizeof(struct variable_list));
    } else {
	for(vars = pdu->variables;
            vars->next_variable;
            vars = vars->next_variable)
	    /*EXIT*/;
	vars->next_variable =
           (struct variable_list *)malloc(sizeof(struct variable_list));
	vars = vars->next_variable;
    }

    vars->next_variable = NULL;
    vars->name = (oid *)malloc(name_length * sizeof(oid));
    bcopy((char *)name, (char *)vars->name, name_length * sizeof(oid));
    vars->name_length = name_length;
    switch (type) {
      case TYPE_INTEGER:
        vars->type = ASN_INTEGER;
        vars->val.integer = (long *)malloc(sizeof(long));
        *(vars->val.integer) = strtol(val,NULL,0);
        vars->val_len = sizeof(long);
        break;

      case TYPE_GAUGE:
        vars->type = ASN_GAUGE;
        goto UINT;
      case TYPE_COUNTER:
        vars->type = ASN_COUNTER;
        goto UINT;
      case TYPE_TIMETICKS:
        vars->type = ASN_TIMETICKS;
        goto UINT;
      case TYPE_UINTEGER:
        vars->type = ASN_UINTEGER;
UINT:
        vars->val.integer = (long *)malloc(sizeof(long));
        sscanf(val,"%lu",vars->val.integer);
        vars->val_len = sizeof(long);
        break;

      case TYPE_OCTETSTR:
	vars->type = ASN_OCTET_STR;
	goto OCT;
      case TYPE_OPAQUE:
        vars->type = ASN_OCTET_STR;
OCT:
        vars->val.string = (u_char *)malloc(len);
        vars->val_len = len;
        bcopy(val,(char *)vars->val.string, vars->val_len);
        break;

      case TYPE_IPADDR:
        vars->type = ASN_IPADDRESS;
        vars->val.integer = (long *)malloc(sizeof(long));
        *(vars->val.integer) = inet_addr(val);
        vars->val_len = sizeof(long);
        break;

      case TYPE_OBJID:
        vars->type = ASN_OBJECT_ID;
	vars->val_len = MAX_OID_LEN;
        /* if (read_objid(val, oidbuf, &(vars->val_len))) { */
	tp = __tag2oid(val,NULL,oidbuf,&(vars->val_len),NULL);
        if (vars->val_len) {
        	vars->val_len *= sizeof(oid);
		vars->val.objid = (oid *)malloc(vars->val_len);
		bcopy((char *)oidbuf, (char *)vars->val.objid,vars->val_len);
        } else {
            vars->val.objid = NULL;
	    ret = FAILURE;
        }
        break;

      default:
        vars->type = ASN_NULL;
	vars->val_len = 0;
	vars->val.string = NULL;
	ret = FAILURE;
    }

     return ret;
}

/* takes ss and pdu as input and updates the 'response' argument */
/* the input 'pdu' argument will be freed */
static int
__send_sync_pdu(ss, pdu, response, retry_nosuch,
	        err_str_sv, err_num_sv, err_ind_sv)
struct snmp_session *ss;
struct snmp_pdu *pdu;
struct snmp_pdu **response;
int retry_nosuch;
SV * err_str_sv;
SV * err_num_sv;
SV * err_ind_sv;
{
   int status;
   long command = pdu->command;
   *response = NULL;
retry:

   status = snmp_synch_response(ss, pdu, response);

   if ((*response == NULL) && (status == STAT_SUCCESS)) status = STAT_ERROR;

   switch (status) {
      case STAT_SUCCESS:
	 switch ((*response)->errstat) {
	    case SNMP_ERR_NOERROR:
	       break;

            case SNMP_ERR_NOSUCHNAME:
               if (retry_nosuch && (pdu = snmp_fix_pdu(*response, command))) {
                  if (*response) snmp_free_pdu(*response);
                  goto retry;
               }

            /* Pv1, SNMPsec, Pv2p, v2c, v2u, v2*, and SNMPv3 PDUs */
            case SNMP_ERR_TOOBIG:
            case SNMP_ERR_BADVALUE:
            case SNMP_ERR_READONLY:
            case SNMP_ERR_GENERR:
            /* in SNMPv2p, SNMPv2c, SNMPv2u, SNMPv2*, and SNMPv3 PDUs */
            case SNMP_ERR_NOACCESS:
            case SNMP_ERR_WRONGTYPE:
            case SNMP_ERR_WRONGLENGTH:
            case SNMP_ERR_WRONGENCODING:
            case SNMP_ERR_WRONGVALUE:
            case SNMP_ERR_NOCREATION:
            case SNMP_ERR_INCONSISTENTVALUE:
            case SNMP_ERR_RESOURCEUNAVAILABLE:
            case SNMP_ERR_COMMITFAILED:
            case SNMP_ERR_UNDOFAILED:
            case SNMP_ERR_AUTHORIZATIONERROR:
            case SNMP_ERR_NOTWRITABLE:
            /* in SNMPv2c, SNMPv2u, SNMPv2*, and SNMPv3 PDUs */
            case SNMP_ERR_INCONSISTENTNAME:
            default:
               sv_catpv(err_str_sv,
                        (char*)snmp_errstring((*response)->errstat));
               sv_setiv(err_num_sv, (*response)->errstat);
	       sv_setiv(err_ind_sv, (*response)->errindex);
               status = (*response)->errstat;
               break;
	 }
         break;

      case STAT_TIMEOUT:
      case STAT_ERROR:
          sv_catpv(err_str_sv, (char*)snmp_api_errstring(ss->s_snmp_errno));
          sv_setiv(err_num_sv, ss->s_snmp_errno);
         break;

      default:
         sv_catpv(err_str_sv, "send_sync_pdu: unknown status");
         sv_setiv(err_num_sv, ss->s_snmp_errno);
         break;
   }

   return(status);
}

static int
__snmp_xs_cb (op, ss, reqid, pdu, cb_data)
int op;
struct snmp_session *ss;
int reqid;
struct snmp_pdu *pdu;
void *cb_data;
{
  SV *varlist_ref;
  AV *varlist;
  SV *varbind_ref;
  AV *varbind;
  struct variable_list *vars;
  struct tree *tp;
  int len;
  oid *oid_arr;
  int oid_arr_len = MAX_OID_LEN;
  SV *tmp_sv;
  int type;
  char tmp_type_str[MAX_TYPE_NAME_LEN];
  int status;
  char str_buf[STR_BUF_SIZE];
  char *label;
  char *iid;
  char *cp;
  int getlabel_flag = NO_FLAGS;
  int sprintval_flag = USE_BASIC;

  SV* cb = ((struct snmp_xs_cb_data*)cb_data)->perl_cb;
  SV* sess_ref = ((struct snmp_xs_cb_data*)cb_data)->sess_ref;
  SV **err_str_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorStr", 8, 1);
  SV **err_num_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorNum", 8, 1);
  SV **err_ind_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorInd", 8, 1);

  dSP;
  ENTER;
  SAVETMPS;

  free(cb_data);

  sv_catpv(*err_str_svp, (char*)snmp_errstring(pdu->errstat));
  sv_setiv(*err_num_svp, pdu->errstat);
  sv_setiv(*err_ind_svp, pdu->errindex);

  switch (op) {
  case RECEIVED_MESSAGE:
    switch (pdu->command) {
    case SNMP_MSG_RESPONSE:
      {
      varlist = newAV();
      varlist_ref = newRV_noinc((SV*)varlist);
      sv_bless(varlist_ref, gv_stashpv("SNMP::VarList",0));
      for(vars = (pdu?pdu->variables:NULL); vars; vars = vars->next_variable) {
         varbind = newAV();
         varbind_ref = newRV_noinc((SV*)varbind);
         sv_bless(varbind_ref, gv_stashpv("SNMP::Varbind",0));
         av_push(varlist, varbind_ref);
         *str_buf = '.';
         tp = get_symbol(vars->name,vars->name_length,
                         get_tree_head(),str_buf+1);
         if (__is_leaf(tp)) {
            type = tp->type;
         } else {
            getlabel_flag |= NON_LEAF_NAME;
            type = __translate_asn_type(vars->type);
         }
         __get_label_iid(str_buf,&label,&iid,getlabel_flag);
         av_store(varbind, VARBIND_TAG_F,
                  newSVpv(label, strlen(label)));
         av_store(varbind, VARBIND_IID_F,
                  newSVpv(iid, strlen(iid)));
         __get_type_str(type, tmp_type_str);
         tmp_sv = newSVpv(tmp_type_str, strlen(tmp_type_str));
         av_store(varbind, VARBIND_TYPE_F, tmp_sv);
         len = __sprint_value(str_buf, vars, tp, type, sprintval_flag);
         tmp_sv = newSVpv((char*)str_buf, len);
         av_store(varbind, VARBIND_VAL_F, tmp_sv);
      } /* for */
      } /* case SNMP_MSG_RESPONSE */
      break;
    default:;
    } /* switch pdu->command */
    break;

  case TIMED_OUT:
    varlist_ref = &sv_undef;
    break;
  default:;
  } /* switch op */
  sv_2mortal(cb);
  __push_cb_args(&cb,
                 (SvTRUE(varlist_ref) ? sv_2mortal(varlist_ref):varlist_ref));
  __call_callback(cb, G_DISCARD);

  FREETMPS;
  LEAVE;
  sv_2mortal(sess_ref);
  return 1;
}

static int
__push_cb_args(svp,esv)
SV **svp;
SV *esv;
{
   SV *sv = *svp;
   dSP;
   if (SvTYPE(SvRV(sv)) != SVt_PVCV) sv = SvRV(sv);

   PUSHMARK(sp);
   if (SvTYPE(sv) == SVt_PVAV) {
      AV *av = (AV *) sv;
      int n = av_len(av) + 1;
      SV **x = av_fetch(av, 0, 0);
      if (x) {
         int i = 1;
         sv = *x;

         for (i = 1; i < n; i++) {
            x = av_fetch(av, i, 0);
            if (x) {
               SV *arg = *x;
               XPUSHs(sv_mortalcopy(arg));
            } else {
               XPUSHs(&sv_undef);
            }
         }
      } else {
         sv = &sv_undef;
      }
   }
   if (esv) XPUSHs(sv_mortalcopy(esv));
   *svp = sv;
   PUTBACK;
   return SUCCESS;
}

static int
__call_callback(sv, flags)
SV *sv;
int flags;
{
 dSP;
 I32 myframe = TOPMARK;
 I32 count;
 ENTER;
 if (SvTYPE(sv) == SVt_PVCV)
  {
   count = perl_call_sv(sv, flags);
  }
 else if (SvROK(sv) && SvTYPE(SvRV(sv)) == SVt_PVCV)
  {
   count = perl_call_sv(SvRV(sv), flags);
  }
 else
  {

   SV **top = stack_base + myframe + 1;
   SV *obj = *top;
   if (SvPOK(sv) && SvROK(obj) && SvOBJECT(SvRV(obj)))
    {
     count = perl_call_method(SvPV(sv, na), flags);
    }
   else if (SvPOK(obj) && SvROK(sv) && SvOBJECT(SvRV(sv)))
    {
     /* We have obj method ...
        Used to be used instead of LangMethodCall()
      */
     *top = sv;
     count = perl_call_method(SvPV(obj, na), flags);
    }
   else
    {
     count = perl_call_sv(sv, flags);
    }
 }
 LEAVE;
 return count;
}

static char *
__av_elem_pv(AV *av, I32 key, char *dflt)
{
   SV **elem = av_fetch(av, key, 0);

   return (elem && SvOK(*elem)) ? SvPV(*elem, na) : dflt;
}

static int
not_here(s)
char *s;
{
    croak("%s not implemented on this architecture", s);
    return -1;
}

static double
constant(name, arg)
char *name;
int arg;
{
    errno = 0;
    switch (*name) {
    case 'R':
	if (strEQ(name, "RECEIVED_MESSAGE"))
#ifdef RECEIVED_MESSAGE
	    return RECEIVED_MESSAGE;
#else
	    goto not_there;
#endif
	break;
    case 'S':
	if (strEQ(name, "SNMPERR_BAD_ADDRESS"))
#ifdef SNMPERR_BAD_ADDRESS
	    return SNMPERR_BAD_ADDRESS;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMPERR_BAD_LOCPORT"))
#ifdef SNMPERR_BAD_LOCPORT
	    return SNMPERR_BAD_LOCPORT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMPERR_BAD_SESSION"))
#ifdef SNMPERR_BAD_SESSION
	    return SNMPERR_BAD_SESSION;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMPERR_GENERR"))
#ifdef SNMPERR_GENERR
	    return SNMPERR_GENERR;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMPERR_TOO_LONG"))
#ifdef SNMPERR_TOO_LONG
	    return SNMPERR_TOO_LONG;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMP_DEFAULT_ADDRESS"))
#ifdef SNMP_DEFAULT_ADDRESS
	    return SNMP_DEFAULT_ADDRESS;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMP_DEFAULT_COMMUNITY_LEN"))
#ifdef SNMP_DEFAULT_COMMUNITY_LEN
	    return SNMP_DEFAULT_COMMUNITY_LEN;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMP_DEFAULT_ENTERPRISE_LENGTH"))
#ifdef SNMP_DEFAULT_ENTERPRISE_LENGTH
	    return SNMP_DEFAULT_ENTERPRISE_LENGTH;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMP_DEFAULT_ERRINDEX"))
#ifdef SNMP_DEFAULT_ERRINDEX
	    return SNMP_DEFAULT_ERRINDEX;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMP_DEFAULT_ERRSTAT"))
#ifdef SNMP_DEFAULT_ERRSTAT
	    return SNMP_DEFAULT_ERRSTAT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMP_DEFAULT_PEERNAME"))
#ifdef SNMP_DEFAULT_PEERNAME
	    return 0;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMP_DEFAULT_REMPORT"))
#ifdef SNMP_DEFAULT_REMPORT
	    return SNMP_DEFAULT_REMPORT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMP_DEFAULT_REQID"))
#ifdef SNMP_DEFAULT_REQID
	    return SNMP_DEFAULT_REQID;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMP_DEFAULT_RETRIES"))
#ifdef SNMP_DEFAULT_RETRIES
	    return SNMP_DEFAULT_RETRIES;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMP_DEFAULT_TIME"))
#ifdef SNMP_DEFAULT_TIME
	    return SNMP_DEFAULT_TIME;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMP_DEFAULT_TIMEOUT"))
#ifdef SNMP_DEFAULT_TIMEOUT
	    return SNMP_DEFAULT_TIMEOUT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMP_DEFAULT_VERSION"))
#ifdef SNMP_DEFAULT_VERSION
	    return SNMP_DEFAULT_VERSION;
#else
	    goto not_there;
#endif
	break;
    case 'T':
	if (strEQ(name, "TIMED_OUT"))
#ifdef TIMED_OUT
	    return TIMED_OUT;
#else
	    goto not_there;
#endif
	break;
    default:
	break;
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}


MODULE = SNMP		PACKAGE = SNMP		PREFIX = snmp

BOOT:
# first blank line terminates bootstrap code
SOCK_STARTUP;
Mib = 0;
snmp_set_do_debugging(0); /* overrides lib dflt - silence init_mib_internals */
snmp_set_quick_print(1);
init_snmpv3("snmpapp");
snmp_call_callbacks(0,0,NULL);
ds_set_boolean(DS_LIBRARY_ID, DS_LIB_DONT_BREAKDOWN_OIDS, 1);
#init_mib_internals();

double
constant(name,arg)
	char *		name
	int		arg

long
snmp_sys_uptime()
	CODE:
	RETVAL = get_uptime();
	OUTPUT:
	RETVAL

SnmpSession *
snmp_new_session(version, community, peer, port, retries, timeout)
        char *	version
        char *	community
        char *	peer
        int	port
        int	retries
        int	timeout
	CODE:
	{
	   SnmpSession session = {0};
	   SnmpSession *ss = NULL;
           int verbose = SvIV(perl_get_sv("SNMP::verbose", 0x01 | 0x04));

	   if (!strcmp(version, "1")) {
		session.version = SNMP_VERSION_1;
           } else if ((!strcmp(version, "2")) || (!strcmp(version, "2c"))) {
		session.version = SNMP_VERSION_2c;
           } else if (!strcmp(version, "3")) {
	        session.version = SNMP_VERSION_3;
	   } else {
		if (verbose)
                   warn("error:snmp_new_session:Unsupported SNMP version (%s)\n", version);
                goto end;
	   }

           session.community_len = strlen((char *)community);
           session.community = (u_char *)community;
	   session.peername = peer;
	   session.remote_port = port;
           session.retries = retries; /* 5 */
           session.timeout = timeout; /* 1000000L */
           session.authenticator = NULL;

           ss = snmp_open(&session);

           if (ss == NULL) {
	      if (verbose) warn("error:snmp_new_session: Couldn't open SNMP session");
           }
        end:
           RETVAL = ss;
	}
        OUTPUT:
        RETVAL

SnmpSession *
snmp_new_v3_session(version, peer, port, retries, timeout, sec_name, sec_level, sec_eng_id, context_eng_id, context, auth_proto, auth_pass, priv_proto, priv_pass, eng_boots, eng_time)
        int	version
        char *	peer
        int	port
        int	retries
        int	timeout
        char *  sec_name
        int     sec_level
        char *  sec_eng_id
        char *  context_eng_id
        char *  context
        char *  auth_proto
        char *  auth_pass
        char *  priv_proto
        char *  priv_pass
	int     eng_boots
	int     eng_time
	CODE:
	{
           u_char sec_eng_id_buf[ENG_ID_BUF_SIZE];
           u_char context_eng_id_buf[ENG_ID_BUF_SIZE];
	   SnmpSession session = {0};
	   SnmpSession *ss = NULL;
           int verbose = SvIV(perl_get_sv("SNMP::verbose", 0x01 | 0x04));

	   if (version == 3) {
		session.version = SNMP_VERSION_3;
           } else {
		if (verbose)
                   warn("error:snmp_new_v3_session:Unsupported SNMP version (%d)\n", version);
                goto end;
	   }

	   session.peername = strdup(peer);
	   session.remote_port = port;
           session.retries = retries; /* 5 */
           session.timeout = timeout; /* 1000000L */
           session.authenticator = NULL;
           session.contextNameLen = strlen(context);
           session.contextName = context;
           session.securityNameLen = strlen(sec_name);
           session.securityName = sec_name;
           session.securityLevel = sec_level;
           /* session.securityEngineID = sec_eng_id_buf;*/
           session.securityEngineID = malloc(ENG_ID_BUF_SIZE);
           session.securityEngineIDLen =
              hex_to_binary(sec_eng_id, session.securityEngineID);
           /* session.contextEngineID = context_eng_id_buf; */
	   session.contextEngineID = malloc(ENG_ID_BUF_SIZE);
           session.contextEngineIDLen =
              hex_to_binary(context_eng_id, session.contextEngineID);
           session.engineBoots = eng_boots;
           session.engineTime = eng_time;
           if (!strcmp(auth_proto, "MD5")) {
              session.securityAuthProto = usmHMACMD5AuthProtocol;
              session.securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN;
           } else if (!strcmp(auth_proto, "SHA")) {
              session.securityAuthProto = usmHMACSHA1AuthProtocol;
              session.securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
           } else {
              if (verbose)
                 warn("error:snmp_new_v3_session:Unsupported authentication protocol(%s)\n", auth_proto);
              goto end;
           }
           if (session.securityLevel >= SNMP_SEC_LEVEL_AUTHNOPRIV) {
              session.securityAuthKeyLen = USM_AUTH_KU_LEN;
              if (generate_Ku(session.securityAuthProto,
                              session.securityAuthProtoLen,
                              (u_char *)auth_pass, strlen(auth_pass),
                              session.securityAuthKey,
                              &session.securityAuthKeyLen) != SNMPERR_SUCCESS) {
                 if (verbose)
                    warn("error:snmp_new_v3_session:Error generating Ku from authentication password.\n");
                 goto end;
              }
           }
           if (!strcmp(priv_proto, "DES")) {
              session.securityPrivProto = usmDESPrivProtocol;
              session.securityPrivProtoLen = USM_PRIV_PROTO_DES_LEN;
           } else {
              if (verbose)
                 warn("error:snmp_new_v3_session:Unsupported privacy protocol(%s)\n", priv_proto);
              goto end;
           }
           if (session.securityLevel >= SNMP_SEC_LEVEL_AUTHPRIV) {
             session.securityPrivKeyLen = USM_PRIV_KU_LEN;
              if (generate_Ku(session.securityAuthProto,
                              session.securityAuthProtoLen,
                              (u_char *)priv_pass, strlen(priv_pass),
                              session.securityPrivKey,
                              &session.securityPrivKeyLen) != SNMPERR_SUCCESS) {
                 if (verbose)
                    warn("error:snmp_new_v3_session:Error generating Ku from privacy pass phrase.\n");
                 goto end;
               }
            }

           ss = snmp_open(&session);

           if (ss == NULL) {
	      if (verbose) warn("error:snmp_new_v3_session:Couldn't open SNMP session");
           }
        end:
           RETVAL = ss;
	   free (session.contextEngineID);
	}
        OUTPUT:
        RETVAL


SnmpSession *
snmp_update_session(sess_ref, version, community, peer, port, retries, timeout)
        SV *	sess_ref
        char *	version
        char *	community
        char *	peer
        int	port
        int	retries
        int	timeout
	CODE:
	{
           SV **sess_ptr_sv;
	   SnmpSession *ss;
           int verbose = SvIV(perl_get_sv("SNMP::verbose", 0x01 | 0x04));

           sess_ptr_sv = hv_fetch((HV*)SvRV(sess_ref), "SessPtr", 7, 1);
           ss = (SnmpSession *)SvIV((SV*)SvRV(*sess_ptr_sv));

           if (!ss) goto update_end;

           if (!strcmp(version, "1")) {
		ss->version = SNMP_VERSION_1;
           } else if (!strcmp(version, "2") || !strcmp(version, "2c")) {
		ss->version = SNMP_VERSION_2c;
	   } else if (!strcmp(version, "3")) {
	        ss->version = SNMP_VERSION_3;
	   } else {
		if (verbose)
                   warn("Unsupported SNMP version (%s)\n", version);
                goto update_end;
	   }
           /* WARNING LEAKAGE but I cant free lib memory under win32 */
           ss->community_len = strlen((char *)community);
           ss->community = (u_char *)strdup(community);
	   ss->peername = strdup(peer);
	   ss->remote_port = port;
           ss->retries = retries; /* 5 */
           ss->timeout = timeout; /* 1000000L */
           ss->authenticator = NULL;

    update_end:
	   RETVAL = ss;
        }
        OUTPUT:
           RETVAL

int
snmp_add_mib_dir(mib_dir,force=0)
	char *		mib_dir
	int		force
	CODE:
        {
	int result;
        int verbose = SvIV(perl_get_sv("SNMP::verbose", 0x01 | 0x04));

        if (mib_dir && *mib_dir) {
	   result = add_mibdir(mib_dir);
        }
        if (result) {
           if (verbose) warn("Added mib dir %s\n", mib_dir);
        } else {
           if (verbose) warn("Failed to add %s\n", mib_dir);
        }
        RETVAL = (I32)result;
        }
        OUTPUT:
        RETVAL

void
snmp_init_mib_internals()
	CODE:
        {
        int verbose = SvIV(perl_get_sv("SNMP::verbose", 0x01 | 0x04));

        /* should test better to see if it has been done already */
	if (Mib == NULL) {
           if (verbose) warn("initializing MIB internals (empty)\n");
           init_mib_internals();
        }
        }


int
snmp_read_mib(mib_file, force=0)
	char *		mib_file
	int		force
	CODE:
        {
        int verbose = SvIV(perl_get_sv("SNMP::verbose", 0x01 | 0x04));

        /* if (Mib && force) __free_tree(Mib); needs more work to cleanup */

        if ((mib_file == NULL) || (*mib_file == '\0')) {
           if (Mib == NULL) {
              if (verbose) warn("initializing MIB\n");
              init_mib();
              if (Mib) {
                 if (verbose) warn("done\n");
              } else {
                 if (verbose) warn("failed\n");
              }
	   }
        } else {
           if (verbose) warn("reading MIB: %s\n", mib_file);
           if (Mib == NULL) init_mib_internals();
           if (strcmp("ALL",mib_file))
              Mib = read_mib(mib_file);
           else
             Mib = read_all_mibs();
           if (Mib) {
              if (verbose) warn("done\n");
           } else {
              if (verbose) warn("failed\n");
           }
        }
        RETVAL = (I32)Mib;
        }
        OUTPUT:
        RETVAL


int
snmp_read_module(module)
	char *		module
	CODE:
        {
        int verbose = SvIV(perl_get_sv("SNMP::verbose", 0x01 | 0x04));
	if (Mib == NULL)     init_mib_internals();

        if (!strcmp(module,"ALL")) {
           Mib = read_all_mibs();
        } else {
	   Mib = read_module(module);
        }
        if (Mib) {
           if (verbose) warn("Read %s\n", module);
        } else {
           if (verbose) warn("Failed reading %s\n", module);
        }
        RETVAL = (I32)Mib;
        }
        OUTPUT:
        RETVAL


int
snmp_set(sess_ref, varlist_ref, perl_callback)
        SV *	sess_ref
        SV *	varlist_ref
        SV *	perl_callback
	PPCODE:
	{
           AV *varlist;
           SV **varbind_ref;
           SV **varbind_val_f;
           AV *varbind;
	   I32 varlist_len;
	   I32 varlist_ind;
	   I32 varbind_len;
           SnmpSession *ss;
           struct snmp_pdu *pdu, *response;
           struct variable_list *vars;
           struct variable_list *last_vars;
           struct tree *tp;
	   oid *oid_arr;
	   int oid_arr_len = MAX_OID_LEN;
           SV *tmp_sv;
           char *tag_pv;
           snmp_xs_cb_data *xs_cb_data;
           SV **sess_ptr_sv;
           SV **err_str_svp;
           SV **err_num_svp;
           SV **err_ind_svp;
           int status = 0;
           int type;
	   int res;
           int verbose = SvIV(perl_get_sv("SNMP::verbose", 0x01 | 0x04));
           int use_enums = SvIV(*hv_fetch((HV*)SvRV(sess_ref),"UseEnums",8,1));
           struct enum_list *ep;

           oid_arr = (oid*)malloc(sizeof(oid) * MAX_OID_LEN);

           if (oid_arr && SvROK(sess_ref) && SvROK(varlist_ref)) {

              sess_ptr_sv = hv_fetch((HV*)SvRV(sess_ref), "SessPtr", 7, 1);
	      ss = (SnmpSession *)SvIV((SV*)SvRV(*sess_ptr_sv));
              err_str_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorStr", 8, 1);
              err_num_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorNum", 8, 1);
              err_ind_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorInd", 8, 1);
              sv_setpv(*err_str_svp, "");
              sv_setiv(*err_num_svp, 0);
              sv_setiv(*err_ind_svp, 0);

              pdu = snmp_pdu_create(SNMP_MSG_SET);

              varlist = (AV*) SvRV(varlist_ref);
              varlist_len = av_len(varlist);
	      for(varlist_ind = 0; varlist_ind <= varlist_len; varlist_ind++) {
                 varbind_ref = av_fetch(varlist, varlist_ind, 0);
                 if (SvROK(*varbind_ref)) {
                    varbind = (AV*) SvRV(*varbind_ref);
                    tag_pv = __av_elem_pv(varbind, VARBIND_TAG_F,NULL);
                    tp=__tag2oid(tag_pv,
                                 __av_elem_pv(varbind, VARBIND_IID_F,NULL),
                                 oid_arr, &oid_arr_len, &type);

                    if (oid_arr_len==0) {
                       if (verbose)
                          warn("error: set: unknown object ID (%s)",
                                (tag_pv?tag_pv:"<null>"));
	               sv_catpv(*err_str_svp,
                               (char*)snmp_api_errstring(SNMPERR_UNKNOWN_OBJID));
                       sv_setiv(*err_num_svp, SNMPERR_UNKNOWN_OBJID);
                       XPUSHs(&sv_undef); /* unknown OID */
		       snmp_free_pdu(pdu);
		       goto done;
		    }


                    if (type == TYPE_UNKNOWN) {
                      type = __translate_appl_type(
                                __av_elem_pv(varbind, VARBIND_TYPE_F, NULL));
                      if (type == TYPE_UNKNOWN) {
                         if (verbose)
                            warn("error: set: no type found for object");
	                 sv_catpv(*err_str_svp,
                                  (char*)snmp_api_errstring(SNMPERR_VAR_TYPE));
                         sv_setiv(*err_num_svp, SNMPERR_VAR_TYPE);
                         XPUSHs(&sv_undef); /* unknown OID */
		         snmp_free_pdu(pdu);
		         goto done;
                      }
                    }

	            varbind_val_f = av_fetch(varbind, VARBIND_VAL_F, 0);

                    if (type==TYPE_INTEGER && use_enums && tp && tp->enums) {
                      for(ep = tp->enums; ep; ep = ep->next) {
                        if (varbind_val_f && SvOK(*varbind_val_f) &&
                            !strcmp(ep->label, SvPV(*varbind_val_f,na))) {
                          sv_setiv(*varbind_val_f, ep->value);
                          break;
                        }
                      }
                    }

                    res = __add_var_val_str(pdu, oid_arr, oid_arr_len,
				     (varbind_val_f && SvOK(*varbind_val_f) ?
				      SvPV(*varbind_val_f,na):NULL),
				      (varbind_val_f && SvOK(*varbind_val_f) ?
				       SvCUR(*varbind_val_f):0), type);

		    if (verbose && res == FAILURE)
		      warn("error: adding variable/value to PDU");
                 } /* if var_ref is ok */
              } /* for all the vars */

              if (SvTRUE(perl_callback)) {
                  xs_cb_data =
                      (snmp_xs_cb_data*)malloc(sizeof(snmp_xs_cb_data));
                 xs_cb_data->perl_cb = newSVsv(perl_callback);
                 xs_cb_data->sess_ref = newRV_inc(SvRV(sess_ref));

                 status = snmp_async_send(ss, pdu, __snmp_xs_cb,
                                          (void*)xs_cb_data);
                 if (status != 0) {
                    XPUSHs(sv_2mortal(newSViv(status))); /* push the reqid?? */
                 } else {
                    snmp_free_pdu(pdu);
                    sv_catpv(*err_str_svp,
                             (char*)snmp_api_errstring(ss->s_snmp_errno));
                    sv_setiv(*err_num_svp, ss->s_snmp_errno);
                    XPUSHs(&sv_undef);
                 }
		 goto done;
              }

	      status = __send_sync_pdu(ss, pdu, &response,
				       NO_RETRY_NOSUCH,
                                       *err_str_svp, *err_num_svp,
                                       *err_ind_svp);

              if (response) snmp_free_pdu(response);

              if (status) {
		 XPUSHs(&sv_undef);
	      } else {
                 XPUSHs(sv_2mortal(newSVpv(ZERO_BUT_TRUE,0)));
              }
           } else {
err:
              /* BUG!!! need to return an error value */
              XPUSHs(&sv_undef); /* no mem or bad args */
           }
done:
           Safefree(oid_arr);
        }


void
snmp_get(sess_ref, retry_nosuch, varlist_ref, perl_callback)
        SV *    sess_ref
        int     retry_nosuch
        SV *    varlist_ref
        SV *    perl_callback
        PPCODE:
        {
           AV *varlist;
           SV **varbind_ref;
           AV *varbind;
           I32 varlist_len;
           I32 varlist_ind;
           I32 varbind_len;
           struct snmp_session *ss;
           struct snmp_pdu *pdu, *response;
           struct variable_list *vars;
           struct variable_list *last_vars;
           struct tree *tp;
           int len;
           oid *oid_arr;
           int oid_arr_len = MAX_OID_LEN;
           SV *tmp_sv;
           char *tag_pv;
           int type;
           char tmp_type_str[MAX_TYPE_NAME_LEN];
           char str_buf[STR_BUF_SIZE];
           snmp_xs_cb_data *xs_cb_data;
           SV **sess_ptr_sv;
           SV **err_str_svp;
           SV **err_num_svp;
           SV **err_ind_svp;
           int status;
           int sprintval_flag = USE_BASIC;
           int verbose = SvIV(perl_get_sv("SNMP::verbose", 0x01 | 0x04));

           oid_arr = (oid*)malloc(sizeof(oid) * MAX_OID_LEN);

           if (oid_arr && SvROK(sess_ref) && SvROK(varlist_ref)) {

              sess_ptr_sv = hv_fetch((HV*)SvRV(sess_ref), "SessPtr", 7, 1);
              ss = (SnmpSession *)SvIV((SV*)SvRV(*sess_ptr_sv));
              err_str_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorStr", 8, 1);
              err_num_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorNum", 8, 1);
              err_ind_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorInd", 8, 1);
              sv_setpv(*err_str_svp, "");
              sv_setiv(*err_num_svp, 0);
              sv_setiv(*err_ind_svp, 0);
              if (SvIV(*hv_fetch((HV*)SvRV(sess_ref),"UseEnums", 8, 1)))
                 sprintval_flag = USE_ENUMS;
              if (SvIV(*hv_fetch((HV*)SvRV(sess_ref),"UseSprintValue", 14, 1)))
                 sprintval_flag = USE_SPRINT_VALUE;

              pdu = snmp_pdu_create(SNMP_MSG_GET);

              varlist = (AV*) SvRV(varlist_ref);
              varlist_len = av_len(varlist);
              for(varlist_ind = 0; varlist_ind <= varlist_len; varlist_ind++) {
                 varbind_ref = av_fetch(varlist, varlist_ind, 0);
                 if (SvROK(*varbind_ref)) {
                    varbind = (AV*) SvRV(*varbind_ref);
                    tag_pv = __av_elem_pv(varbind, VARBIND_TAG_F,NULL);
                    tp = __tag2oid(tag_pv,
                                   __av_elem_pv(varbind, VARBIND_IID_F,NULL),
                                   oid_arr, &oid_arr_len, NULL);

                    if (oid_arr_len) {
                       snmp_add_null_var(pdu, oid_arr, oid_arr_len);
                    } else {
                       if (verbose)
                          warn("error: get: unknown object ID (%s)",
                                (tag_pv?tag_pv:"<null>"));
	               sv_catpv(*err_str_svp,
                                (char*)snmp_api_errstring(SNMPERR_UNKNOWN_OBJID));
                       sv_setiv(*err_num_svp, SNMPERR_UNKNOWN_OBJID);
                       XPUSHs(&sv_undef); /* unknown OID */
		       snmp_free_pdu(pdu);
		       goto done;
                    }
                 } /* if var_ref is ok */
              } /* for all the vars */

              if (SvTRUE(perl_callback)) {
                  xs_cb_data =
                      (snmp_xs_cb_data*)malloc(sizeof(snmp_xs_cb_data));
                 xs_cb_data->perl_cb = newSVsv(perl_callback);
                 xs_cb_data->sess_ref = newSVsv(sess_ref);

                 status = snmp_async_send(ss, pdu, __snmp_xs_cb,
                                          (void*)xs_cb_data);
                 if (status != 0) {
                    XPUSHs(sv_2mortal(newSViv(status))); /* push the reqid?? */
                 } else {
                    snmp_free_pdu(pdu);
                    sv_catpv(*err_str_svp,
                             (char*)snmp_api_errstring(ss->s_snmp_errno));
                    sv_setiv(*err_num_svp, ss->s_snmp_errno);
                    XPUSHs(&sv_undef);
                 }
                 goto done;
              }

              status = __send_sync_pdu(ss, pdu, &response, retry_nosuch,
                                       *err_str_svp,*err_num_svp,*err_ind_svp);

              last_vars = (response ? response->variables : NULL);

              for(varlist_ind = 0; varlist_ind <= varlist_len; varlist_ind++) {
                 varbind_ref = av_fetch(varlist, varlist_ind, 0);
                 if (SvROK(*varbind_ref)) {
                    varbind = (AV*) SvRV(*varbind_ref);

                    tp=__tag2oid(__av_elem_pv(varbind, VARBIND_TAG_F,NULL),
                                 __av_elem_pv(varbind, VARBIND_IID_F,NULL),
                                 oid_arr, &oid_arr_len, &type);

                    for (vars = last_vars; vars; vars=vars->next_variable) {
	            if (__oid_cmp(oid_arr, oid_arr_len, vars->name,
                                     vars->name_length) == 0) {
                          if (type == TYPE_UNKNOWN)
                             type = __translate_asn_type(vars->type);
                          last_vars = vars->next_variable;
                          break;
                       }
                    }
                    if (vars) {
                       __get_type_str(type, tmp_type_str);
                       tmp_sv = newSVpv(tmp_type_str,strlen(tmp_type_str));
                       av_store(varbind, VARBIND_TYPE_F, tmp_sv);
                       len=__sprint_value(str_buf,vars,tp,type,sprintval_flag);
                       tmp_sv=newSVpv((char*)str_buf, len);
                       av_store(varbind, VARBIND_VAL_F, tmp_sv);
                       XPUSHs(sv_mortalcopy(tmp_sv));
                    } else {
                       av_store(varbind, VARBIND_VAL_F, &sv_undef);
                       av_store(varbind, VARBIND_TYPE_F, &sv_undef);
                       XPUSHs(&sv_undef);
                    }
                 }
              }
              if (response) snmp_free_pdu(response);
           } else {
              XPUSHs(&sv_undef); /* no mem or bad args */
           }
     done:
           Safefree(oid_arr);
        }

int
snmp_getnext(sess_ref, varlist_ref, perl_callback)
        SV *    sess_ref
        SV *    varlist_ref
        SV *    perl_callback
        PPCODE:
        {
           AV *varlist;
           SV **varbind_ref;
           AV *varbind;
           I32 varlist_len;
           I32 varlist_ind;
           I32 varbind_len;
           struct snmp_session *ss;
           struct snmp_pdu *pdu, *response;
           struct variable_list *vars;
           struct variable_list *last_vars;
           struct tree *tp;
           int len;
	   oid *oid_arr;
	   int oid_arr_len = MAX_OID_LEN;
           SV *tmp_sv;
           int type;
	   char tmp_type_str[MAX_TYPE_NAME_LEN];
           snmp_xs_cb_data *xs_cb_data;
           SV **sess_ptr_sv;
           SV **err_str_svp;
           SV **err_num_svp;
           SV **err_ind_svp;
           int status;
	   char str_buf[STR_BUF_SIZE];
           char *label;
           char *iid;
           char *cp;
           int getlabel_flag = NO_FLAGS;
           int sprintval_flag = USE_BASIC;
           int verbose = SvIV(perl_get_sv("SNMP::verbose", 0x01 | 0x04));

           oid_arr = (oid*)malloc(sizeof(oid) * MAX_OID_LEN);

           if (oid_arr && SvROK(sess_ref) && SvROK(varlist_ref)) {

              sess_ptr_sv = hv_fetch((HV*)SvRV(sess_ref), "SessPtr", 7, 1);
	      ss = (SnmpSession *)SvIV((SV*)SvRV(*sess_ptr_sv));
              err_str_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorStr", 8, 1);
              err_num_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorNum", 8, 1);
              err_ind_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorInd", 8, 1);
              sv_setpv(*err_str_svp, "");
              sv_setiv(*err_num_svp, 0);
              sv_setiv(*err_ind_svp, 0);
	      if (SvIV(*hv_fetch((HV*)SvRV(sess_ref),"UseLongNames", 12, 1)))
                 getlabel_flag |= USE_LONG_NAMES;
	      if (SvIV(*hv_fetch((HV*)SvRV(sess_ref),"UseEnums", 8, 1)))
                 sprintval_flag = USE_ENUMS;
	      if (SvIV(*hv_fetch((HV*)SvRV(sess_ref),"UseSprintValue", 14, 1)))
                 sprintval_flag = USE_SPRINT_VALUE;

              pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);

              varlist = (AV*) SvRV(varlist_ref);
              varlist_len = av_len(varlist);
	      for(varlist_ind = 0; varlist_ind <= varlist_len; varlist_ind++) {
                 varbind_ref = av_fetch(varlist, varlist_ind, 0);
                 if (SvROK(*varbind_ref)) {
                    varbind = (AV*) SvRV(*varbind_ref);

                    tp = __tag2oid(__av_elem_pv(varbind, VARBIND_TAG_F, ".0"),
                              __av_elem_pv(varbind, VARBIND_IID_F, NULL),
                              oid_arr, &oid_arr_len, NULL);

      		    if (oid_arr_len) {
  		       snmp_add_null_var(pdu, oid_arr, oid_arr_len);
		    } else {
                       if (verbose)
                          warn("error: set: unknown object ID");
	               sv_catpv(*err_str_svp,
                               (char*)snmp_api_errstring(SNMPERR_UNKNOWN_OBJID));
                       sv_setiv(*err_num_svp, SNMPERR_UNKNOWN_OBJID);
                       XPUSHs(&sv_undef); /* unknown OID */
		       snmp_free_pdu(pdu);
		       goto done;
		    }

                 } /* if var_ref is ok */
              } /* for all the vars */

              if (SvTRUE(perl_callback)) {
                  xs_cb_data =
                      (snmp_xs_cb_data*)malloc(sizeof(snmp_xs_cb_data));
                 xs_cb_data->perl_cb = newSVsv(perl_callback);
                 xs_cb_data->sess_ref = newSVsv(sess_ref);

                 status = snmp_async_send(ss, pdu, __snmp_xs_cb,
                                          (void*)xs_cb_data);
                 if (status != 0) {
                    XPUSHs(sv_2mortal(newSViv(status))); /* push the reqid?? */
                 } else {
                    snmp_free_pdu(pdu);
                    sv_catpv(*err_str_svp,
                             (char*)snmp_api_errstring(ss->s_snmp_errno));
                    sv_setiv(*err_num_svp, ss->s_snmp_errno);
                    XPUSHs(&sv_undef);
                 }
		 goto done;
              }

	      status = __send_sync_pdu(ss, pdu, &response,
				       NO_RETRY_NOSUCH,
                                       *err_str_svp, *err_num_svp,
				       *err_ind_svp);

              for(vars = (response?response->variables:NULL), varlist_ind = 0;
                  vars && (varlist_ind <= varlist_len);
                  vars = vars->next_variable, varlist_ind++) {
                 varbind_ref = av_fetch(varlist, varlist_ind, 0);
                 if (SvROK(*varbind_ref)) {
                    varbind = (AV*) SvRV(*varbind_ref);

                    *str_buf = '.';
                    tp = get_symbol(vars->name,vars->name_length,
                                    get_tree_head(),str_buf+1);
                    if (__is_leaf(tp)) {
                       type = tp->type;
                    } else {
                       getlabel_flag |= NON_LEAF_NAME;
                       type = __translate_asn_type(vars->type);
                    }
                    __get_label_iid(str_buf,&label,&iid,getlabel_flag);
                    av_store(varbind, VARBIND_TAG_F,
                             newSVpv(label, strlen(label)));
                    av_store(varbind, VARBIND_IID_F,
                             newSVpv(iid, strlen(iid)));
                    __get_type_str(type, tmp_type_str);
                    tmp_sv = newSVpv(tmp_type_str, strlen(tmp_type_str));
                    av_store(varbind, VARBIND_TYPE_F, tmp_sv);
                    len=__sprint_value(str_buf,vars,tp,type,sprintval_flag);
                    tmp_sv = newSVpv((char*)str_buf, len);
                    av_store(varbind, VARBIND_VAL_F, tmp_sv);
                    XPUSHs(sv_mortalcopy(tmp_sv));
                 } else {
err:
                    av_store(varbind, VARBIND_IID_F, &sv_undef);
                    av_store(varbind, VARBIND_VAL_F, &sv_undef);
                    av_store(varbind, VARBIND_TYPE_F, &sv_undef);
                    XPUSHs(&sv_undef);
                 }
              }

              if (response) snmp_free_pdu(response);

           } else {
              XPUSHs(&sv_undef); /* no mem or bad args */
	   }
done:
	Safefree(oid_arr);
	}

int
snmp_getbulk(sess_ref, nonrepeaters, maxrepetitions, varlist_ref, perl_callback)
        SV *	sess_ref
	int nonrepeaters
	int maxrepetitions
        SV *	varlist_ref
        SV *	perl_callback
	PPCODE:
	{
           AV *varlist;
           SV **varbind_ref;
           AV *varbind;
	   I32 varlist_len;
	   I32 varlist_ind;
	   I32 varbind_len;
           struct snmp_session *ss;
           struct snmp_pdu *pdu, *response;
           struct variable_list *vars;
           struct variable_list *last_vars;
           struct tree *tp;
           int len;
	   oid *oid_arr;
	   int oid_arr_len = MAX_OID_LEN;
           SV *tmp_sv;
           int type;
	   char tmp_type_str[MAX_TYPE_NAME_LEN];
           snmp_xs_cb_data *xs_cb_data;
           SV **sess_ptr_sv;
           SV **err_str_svp;
           SV **err_num_svp;
           SV **err_ind_svp;
           int status;
	   char str_buf[STR_BUF_SIZE];
           char *label;
           char *iid;
           char *cp;
           int getlabel_flag = NO_FLAGS;
           int sprintval_flag = USE_BASIC;
           int verbose = SvIV(perl_get_sv("SNMP::verbose", 0x01 | 0x04));
	   SV *rv;

           oid_arr = (oid*)malloc(sizeof(oid) * MAX_OID_LEN);

           if (oid_arr && SvROK(sess_ref) && SvROK(varlist_ref)) {

              sess_ptr_sv = hv_fetch((HV*)SvRV(sess_ref), "SessPtr", 7, 1);
	      ss = (SnmpSession *)SvIV((SV*)SvRV(*sess_ptr_sv));
              err_str_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorStr", 8, 1);
              err_num_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorNum", 8, 1);
              err_ind_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorInd", 8, 1);
              sv_setpv(*err_str_svp, "");
              sv_setiv(*err_num_svp, 0);
              sv_setiv(*err_ind_svp, 0);
	      if (SvIV(*hv_fetch((HV*)SvRV(sess_ref),"UseLongNames", 12, 1)))
                 getlabel_flag |= USE_LONG_NAMES;
	      if (SvIV(*hv_fetch((HV*)SvRV(sess_ref),"UseEnums", 8, 1)))
                 sprintval_flag = USE_ENUMS;
	      if (SvIV(*hv_fetch((HV*)SvRV(sess_ref),"UseSprintValue", 14, 1)))
                 sprintval_flag = USE_SPRINT_VALUE;

              pdu = snmp_pdu_create(SNMP_MSG_GETBULK);

	      pdu->errstat = nonrepeaters;
	      pdu->errindex = maxrepetitions;

              varlist = (AV*) SvRV(varlist_ref);
              varlist_len = av_len(varlist);
	      for(varlist_ind = 0; varlist_ind <= varlist_len; varlist_ind++) {
                 varbind_ref = av_fetch(varlist, varlist_ind, 0);
                 if (SvROK(*varbind_ref)) {
                    varbind = (AV*) SvRV(*varbind_ref);
                    __tag2oid(__av_elem_pv(varbind, VARBIND_TAG_F, "0"),
                              __av_elem_pv(varbind, VARBIND_IID_F, NULL),
                              oid_arr, &oid_arr_len, NULL);


                    if (oid_arr_len) {
  		       snmp_add_null_var(pdu, oid_arr, oid_arr_len);
		    } else {
                       if (verbose)
                          warn("error: set: unknown object ID");
	               sv_catpv(*err_str_svp,
                               (char*)snmp_api_errstring(SNMPERR_UNKNOWN_OBJID));
                       sv_setiv(*err_num_svp, SNMPERR_UNKNOWN_OBJID);
                       XPUSHs(&sv_undef); /* unknown OID */
		       snmp_free_pdu(pdu);
		       goto done;
		    }


                 } /* if var_ref is ok */
              } /* for all the vars */

              if (SvTRUE(perl_callback)) {
                  xs_cb_data =
                      (snmp_xs_cb_data*)malloc(sizeof(snmp_xs_cb_data));
                 xs_cb_data->perl_cb = newSVsv(perl_callback);
                 xs_cb_data->sess_ref = newSVsv(sess_ref);

                 status = snmp_async_send(ss, pdu, __snmp_xs_cb,
                                          (void*)xs_cb_data);
                 if (status != 0) {
                    XPUSHs(sv_2mortal(newSViv(status))); /* push the reqid?? */
                 } else {
                    snmp_free_pdu(pdu);
                    sv_catpv(*err_str_svp,
                             (char*)snmp_api_errstring(ss->s_snmp_errno));
                    sv_setiv(*err_num_svp, ss->s_snmp_errno);
                    XPUSHs(&sv_undef);
                 }
		 goto done;
              }

	      status = __send_sync_pdu(ss, pdu, &response,
				       NO_RETRY_NOSUCH,
                                       *err_str_svp, *err_num_svp,
				       *err_ind_svp);

	      av_clear(varlist);

	      if(response && response->variables) {
              for(vars = response->variables;
                  vars;
                  vars = vars->next_variable) {

                    varbind = (AV*) newAV();
                    *str_buf = '.';
                    tp = get_symbol(vars->name,vars->name_length,
                                    get_tree_head(),str_buf+1);
                    if (__is_leaf(tp)) {
                       type = tp->type;
                    } else {
                       getlabel_flag |= NON_LEAF_NAME;
                       type = __translate_asn_type(vars->type);
                    }
                    __get_label_iid(str_buf,&label,&iid,getlabel_flag);

		    av_store(varbind, VARBIND_TAG_F,
			     newSVpv(label, strlen(label)));
		    av_store(varbind, VARBIND_IID_F,
			     newSVpv(iid, strlen(iid)));

                    __get_type_str(type, tmp_type_str);
		    av_store(varbind, VARBIND_TYPE_F, newSVpv(tmp_type_str,
				     strlen(tmp_type_str)));

                    len=__sprint_value(str_buf,vars,tp,type,sprintval_flag);
                    tmp_sv = newSVpv((char*)str_buf, len);
		    av_store(varbind, VARBIND_VAL_F, tmp_sv);

		    rv = newRV_noinc((SV *)varbind);
		    sv_bless(rv, gv_stashpv("SNMP::Varbind",0));
		    av_push(varlist, rv);

                    XPUSHs(sv_mortalcopy(tmp_sv));
                 }
              } else {
                    XPUSHs(&sv_undef);
	      }

              if (response) snmp_free_pdu(response);

           } else {
              XPUSHs(&sv_undef); /* no mem or bad args */
	   }
done:
	Safefree(oid_arr);
	}

int
snmp_trapV1(sess_ref,enterprise,agent,generic,specific,uptime,varlist_ref)
        SV *	sess_ref
        char *	enterprise
        char *	agent
        int	generic
        int	specific
        long	uptime
        SV *	varlist_ref
	PPCODE:
	{
           AV *varlist;
           SV **varbind_ref;
           SV **varbind_val_f;
           AV *varbind;
	   I32 varlist_len;
	   I32 varlist_ind;
	   I32 varbind_len;
           SnmpSession *ss;
           struct snmp_pdu *pdu = NULL;
           struct snmp_pdu *response;
           struct variable_list *vars;
           struct variable_list *last_vars;
           struct tree *tp;
	   oid *oid_arr;
	   int oid_arr_len = MAX_OID_LEN;
           SV *tmp_sv;
           snmp_xs_cb_data *xs_cb_data;
           SV **sess_ptr_sv;
           SV **err_str_svp;
           SV **err_num_svp;
           SV **err_ind_svp;
           int status = 0;
           int type;
           int res;
           int verbose = SvIV(perl_get_sv("SNMP::verbose", 0x01 | 0x04));
           int use_enums = SvIV(*hv_fetch((HV*)SvRV(sess_ref),"UseEnums",8,1));
           struct enum_list *ep;

           oid_arr = (oid*)malloc(sizeof(oid) * MAX_OID_LEN);

           if (oid_arr && SvROK(sess_ref)) {

              sess_ptr_sv = hv_fetch((HV*)SvRV(sess_ref), "SessPtr", 7, 1);
	      ss = (SnmpSession *)SvIV((SV*)SvRV(*sess_ptr_sv));
              err_str_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorStr", 8, 1);
              err_num_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorNum", 8, 1);
              err_ind_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorInd", 8, 1);
              sv_setpv(*err_str_svp, "");
              sv_setiv(*err_num_svp, 0);
              sv_setiv(*err_ind_svp, 0);

              pdu = snmp_pdu_create(SNMP_MSG_TRAP);

              if (SvROK(varlist_ref)) {
              varlist = (AV*) SvRV(varlist_ref);
              varlist_len = av_len(varlist);
	      for(varlist_ind = 0; varlist_ind <= varlist_len; varlist_ind++) {
                 varbind_ref = av_fetch(varlist, varlist_ind, 0);
                 if (SvROK(*varbind_ref)) {
                    varbind = (AV*) SvRV(*varbind_ref);

                    tp=__tag2oid(__av_elem_pv(varbind, VARBIND_TAG_F, NULL),
                                 __av_elem_pv(varbind, VARBIND_IID_F, NULL),
                                 oid_arr, &oid_arr_len, &type);

                    if (oid_arr_len == 0) {
                       if (verbose)
                        warn("error:trap: unable to determine oid for object");
                       goto err;
                    }

                    if (type == TYPE_UNKNOWN) {
                      type = __translate_appl_type(
                              __av_elem_pv(varbind, VARBIND_TYPE_F, NULL));
                      if (type == TYPE_UNKNOWN) {
                         if (verbose)
                            warn("error:trap: no type found for object");
                         goto err;
                      }
                    }

	            varbind_val_f = av_fetch(varbind, VARBIND_VAL_F, 0);

                    if (type==TYPE_INTEGER && use_enums && tp && tp->enums) {
                      for(ep = tp->enums; ep; ep = ep->next) {
                        if (varbind_val_f && SvOK(*varbind_val_f) &&
                            !strcmp(ep->label, SvPV(*varbind_val_f,na))) {
                          sv_setiv(*varbind_val_f, ep->value);
                          break;
                        }
                      }
                    }

                    res = __add_var_val_str(pdu, oid_arr, oid_arr_len,
                                  (varbind_val_f && SvOK(*varbind_val_f) ?
                                   SvPV(*varbind_val_f,na):NULL),
                                  (varbind_val_f && SvOK(*varbind_val_f) ?
                                   SvCUR(*varbind_val_f):0),
                                  type);

                    if(res == FAILURE) {
                        if(verbose) warn("error:trap: adding varbind");
                        goto err;
                    }

                 } /* if var_ref is ok */
              } /* for all the vars */
              }

	      pdu->enterprise = (oid *)malloc( MAX_OID_LEN * sizeof(oid));
              tp = __tag2oid(enterprise,NULL, pdu->enterprise,
                             &pdu->enterprise_length, NULL);
  	      if (pdu->enterprise_length == 0) {
		  if (verbose) warn("error:trap:invalid enterprise id: %s", enterprise);
                  goto err;
	      }
              if (agent && strlen(agent)) {
                 SIN_ADDR(pdu->address).s_addr = __parse_address(agent);
                 if (SIN_ADDR(pdu->address).s_addr == -1 && verbose) {
                    warn("error:trap:invalid agent address: %s", agent);
                    goto err;
                 }
              } else {
                 SIN_ADDR(pdu->address).s_addr = get_myaddr();
              }
              pdu->trap_type = generic;
              pdu->specific_type = specific;
              pdu->time = uptime;

              if (snmp_send(ss, pdu) == 0) {
	         snmp_free_pdu(pdu);
              }
              XPUSHs(sv_2mortal(newSVpv(ZERO_BUT_TRUE,0)));
           } else {
err:
              XPUSHs(&sv_undef); /* no mem or bad args */
              if (pdu) snmp_free_pdu(pdu);
           }
	Safefree(oid_arr);
        }


int
snmp_trapV2(sess_ref,uptime,trap_oid,varlist_ref)
        SV *	sess_ref
        char *	uptime
        char *	trap_oid
        SV *	varlist_ref
	PPCODE:
	{
           AV *varlist;
           SV **varbind_ref;
           SV **varbind_val_f;
           AV *varbind;
	   I32 varlist_len;
	   I32 varlist_ind;
	   I32 varbind_len;
           SnmpSession *ss;
           struct snmp_pdu *pdu = NULL;
           struct snmp_pdu *response;
           struct variable_list *vars;
           struct variable_list *last_vars;
           struct tree *tp;
	   oid *oid_arr;
	   int oid_arr_len = MAX_OID_LEN;
           SV *tmp_sv;
           snmp_xs_cb_data *xs_cb_data;
           SV **sess_ptr_sv;
           SV **err_str_svp;
           SV **err_num_svp;
           SV **err_ind_svp;
           int status = 0;
           int type;
           int res;
           int verbose = SvIV(perl_get_sv("SNMP::verbose", 0x01 | 0x04));
           int use_enums = SvIV(*hv_fetch((HV*)SvRV(sess_ref),"UseEnums",8,1));
           struct enum_list *ep;

           oid_arr = (oid*)malloc(sizeof(oid) * MAX_OID_LEN);

           if (oid_arr && SvROK(sess_ref) && SvROK(varlist_ref)) {

              sess_ptr_sv = hv_fetch((HV*)SvRV(sess_ref), "SessPtr", 7, 1);
	      ss = (SnmpSession *)SvIV((SV*)SvRV(*sess_ptr_sv));
              err_str_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorStr", 8, 1);
              err_num_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorNum", 8, 1);
              err_ind_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorInd", 8, 1);
              sv_setpv(*err_str_svp, "");
              sv_setiv(*err_num_svp, 0);
              sv_setiv(*err_ind_svp, 0);

              pdu = snmp_pdu_create(SNMP_MSG_TRAP2);

              varlist = (AV*) SvRV(varlist_ref);
              varlist_len = av_len(varlist);
	      /************************************************/
              res = __add_var_val_str(pdu, sysUpTime, SYS_UPTIME_OID_LEN,
				uptime, strlen(uptime), TYPE_TIMETICKS);

              if(res == FAILURE) {
                if(verbose) warn("error:trap v2: adding sysUpTime varbind");
		goto err;
              }

	      res = __add_var_val_str(pdu, snmpTrapOID, SNMP_TRAP_OID_LEN,
				trap_oid ,strlen(trap_oid) ,TYPE_OBJID);

              if(res == FAILURE) {
                if(verbose) warn("error:trap v2: adding snmpTrapOID varbind");
		goto err;
              }


	      /******************************************************/

	      for(varlist_ind = 0; varlist_ind <= varlist_len; varlist_ind++) {
                 varbind_ref = av_fetch(varlist, varlist_ind, 0);
                 if (SvROK(*varbind_ref)) {
                    varbind = (AV*) SvRV(*varbind_ref);

                    tp=__tag2oid(__av_elem_pv(varbind, VARBIND_TAG_F,NULL),
                                 __av_elem_pv(varbind, VARBIND_IID_F,NULL),
                                 oid_arr, &oid_arr_len, &type);

                    if (oid_arr_len == 0) {
                       if (verbose)
                        warn("error:trap v2: unable to determine oid for object");
                       goto err;
                    }

                    if (type == TYPE_UNKNOWN) {
                      type = __translate_appl_type(
                                 __av_elem_pv(varbind, VARBIND_TYPE_F, NULL));
                      if (type == TYPE_UNKNOWN) {
                         if (verbose)
                            warn("error:trap v2: no type found for object");
                         goto err;
                      }
                    }

	            varbind_val_f = av_fetch(varbind, VARBIND_VAL_F, 0);

                    if (type==TYPE_INTEGER && use_enums && tp && tp->enums) {
                      for(ep = tp->enums; ep; ep = ep->next) {
                        if (varbind_val_f && SvOK(*varbind_val_f) &&
                            !strcmp(ep->label, SvPV(*varbind_val_f,na))) {
                          sv_setiv(*varbind_val_f, ep->value);
                          break;
                        }
                      }
                    }

                    res = __add_var_val_str(pdu, oid_arr, oid_arr_len,
                                  (varbind_val_f && SvOK(*varbind_val_f) ?
                                   SvPV(*varbind_val_f,na):NULL),
                                  (varbind_val_f && SvOK(*varbind_val_f) ?
                                   SvCUR(*varbind_val_f):0),
                                  type);

                    if(res == FAILURE) {
                        if(verbose) warn("error:trap v2: adding varbind");
                        goto err;
                    }

                 } /* if var_ref is ok */
              } /* for all the vars */


              if (snmp_send(ss, pdu) == 0) {
	         snmp_free_pdu(pdu);
              }

              XPUSHs(sv_2mortal(newSVpv(ZERO_BUT_TRUE,0)));
           } else {
err:
              XPUSHs(&sv_undef); /* no mem or bad args */
              if (pdu) snmp_free_pdu(pdu);
           }
	Safefree(oid_arr);
        }



int
snmp_inform(sess_ref,uptime,trap_oid,varlist_ref)
        SV *	sess_ref
        char *	uptime
        char *	trap_oid
        SV *	varlist_ref
	PPCODE:
	{
           AV *varlist;
           SV **varbind_ref;
           SV **varbind_val_f;
           AV *varbind;
	   I32 varlist_len;
	   I32 varlist_ind;
	   I32 varbind_len;
           SnmpSession *ss;
           struct snmp_pdu *pdu = NULL;
           struct snmp_pdu *response;
           struct variable_list *vars;
           struct variable_list *last_vars;
           struct tree *tp;
	   oid *oid_arr;
	   int oid_arr_len = MAX_OID_LEN;
           SV *tmp_sv;
           snmp_xs_cb_data *xs_cb_data;
           SV **sess_ptr_sv;
           SV **err_str_svp;
           SV **err_num_svp;
           SV **err_ind_svp;
           int status = 0;
           int type;
           int res;
           int verbose = SvIV(perl_get_sv("SNMP::verbose", 0x01 | 0x04));
           int use_enums = SvIV(*hv_fetch((HV*)SvRV(sess_ref),"UseEnums",8,1));
           struct enum_list *ep;

           oid_arr = (oid*)malloc(sizeof(oid) * MAX_OID_LEN);

           if (oid_arr && SvROK(sess_ref) && SvROK(varlist_ref)) {

              sess_ptr_sv = hv_fetch((HV*)SvRV(sess_ref), "SessPtr", 7, 1);
	      ss = (SnmpSession *)SvIV((SV*)SvRV(*sess_ptr_sv));
              err_str_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorStr", 8, 1);
              err_num_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorNum", 8, 1);
              err_ind_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorInd", 8, 1);
              sv_setpv(*err_str_svp, "");
              sv_setiv(*err_num_svp, 0);
              sv_setiv(*err_ind_svp, 0);

              pdu = snmp_pdu_create(SNMP_MSG_INFORM);

              varlist = (AV*) SvRV(varlist_ref);
              varlist_len = av_len(varlist);
	      /************************************************/
              res = __add_var_val_str(pdu, sysUpTime, SYS_UPTIME_OID_LEN,
				uptime, strlen(uptime), TYPE_TIMETICKS);

              if(res == FAILURE) {
                if(verbose) warn("error:inform: adding sysUpTime varbind");
		goto err;
              }

	      res = __add_var_val_str(pdu, snmpTrapOID, SNMP_TRAP_OID_LEN,
				trap_oid ,strlen(trap_oid) ,TYPE_OBJID);

              if(res == FAILURE) {
                if(verbose) warn("error:inform: adding snmpTrapOID varbind");
		goto err;
              }


	      /******************************************************/

	      for(varlist_ind = 0; varlist_ind <= varlist_len; varlist_ind++) {
                 varbind_ref = av_fetch(varlist, varlist_ind, 0);
                 if (SvROK(*varbind_ref)) {
                    varbind = (AV*) SvRV(*varbind_ref);

                    tp=__tag2oid(__av_elem_pv(varbind, VARBIND_TAG_F,NULL),
                                 __av_elem_pv(varbind, VARBIND_IID_F,NULL),
                                 oid_arr, &oid_arr_len, &type);

                    if (oid_arr_len == 0) {
                       if (verbose)
                        warn("error:inform: unable to determine oid for object");
                       goto err;
                    }

                    if (type == TYPE_UNKNOWN) {
                      type = __translate_appl_type(
                                 __av_elem_pv(varbind, VARBIND_TYPE_F, NULL));
                      if (type == TYPE_UNKNOWN) {
                         if (verbose)
                            warn("error:inform: no type found for object");
                         goto err;
                      }
                    }

	            varbind_val_f = av_fetch(varbind, VARBIND_VAL_F, 0);

                    if (type==TYPE_INTEGER && use_enums && tp && tp->enums) {
                      for(ep = tp->enums; ep; ep = ep->next) {
                        if (varbind_val_f && SvOK(*varbind_val_f) &&
                            !strcmp(ep->label, SvPV(*varbind_val_f,na))) {
                          sv_setiv(*varbind_val_f, ep->value);
                          break;
                        }
                      }
                    }

                    res = __add_var_val_str(pdu, oid_arr, oid_arr_len,
                                  (varbind_val_f && SvOK(*varbind_val_f) ?
                                   SvPV(*varbind_val_f,na):NULL),
                                  (varbind_val_f && SvOK(*varbind_val_f) ?
                                   SvCUR(*varbind_val_f):0),
                                  type);

                    if(res == FAILURE) {
                        if(verbose) warn("error:inform: adding varbind");
                        goto err;
                    }

                 } /* if var_ref is ok */
              } /* for all the vars */


	      status = __send_sync_pdu(ss, pdu, &response,
				       NO_RETRY_NOSUCH,
                                       *err_str_svp, *err_num_svp,
                                       *err_ind_svp);

              if (response) snmp_free_pdu(response);

              if (status) {
		 XPUSHs(&sv_undef);
	      } else {
                 XPUSHs(sv_2mortal(newSVpv(ZERO_BUT_TRUE,0)));
              }
           } else {
err:
              XPUSHs(&sv_undef); /* no mem or bad args */
              if (pdu) snmp_free_pdu(pdu);
           }
	Safefree(oid_arr);
        }



char *
snmp_get_type(tag)
	char *		tag
	CODE:
	{
	   struct tree *tp  = NULL;
	   static char type_str[MAX_TYPE_NAME_LEN];
           char *ret = NULL;

           if (tag && *tag) tp = __tag2oid(tag, NULL, NULL, NULL, NULL);
           if (tp) __get_type_str(tp->type, ret = type_str);
	   RETVAL = ret;
	}
	OUTPUT:
        RETVAL


void
snmp_dump_packet(flag)
	int		flag
	CODE:
	{
	   snmp_set_dump_packet(flag);
	}


char *
snmp_map_enum(tag, val, iflag)
	char *		tag
	char *		val
	int		iflag
	CODE:
	{
	   struct tree *tp  = NULL;
           struct enum_list *ep;
           char str_buf[STR_BUF_SIZE];
           int ival;

           RETVAL = NULL;

           if (tag && *tag) tp = __tag2oid(tag, NULL, NULL, NULL, NULL);

           if (tp) {
              if (iflag) {
                 ival = atoi(val);
                 for(ep = tp->enums; ep; ep = ep->next) {
                    if (ep->value == ival) {
                       RETVAL = ep->label;
                       break;
                    }
                 }
              } else {
                 for(ep = tp->enums; ep; ep = ep->next) {
                    if (strEQ(ep->label, val)) {
                       sprintf(str_buf,"%ld", ep->value);
                       RETVAL = str_buf;
                       break;
                    }
                 }
              }
           }
	}
	OUTPUT:
        RETVAL

#define SNMP_XLATE_MODE_OID2TAG 1
#define SNMP_XLATE_MODE_TAG2OID 0

char *
snmp_translate_obj(var,mode,use_long,auto_init)
	char *		var
	int		mode
	int		use_long
	int		auto_init
	CODE:
	{
	   char str_buf[STR_BUF_SIZE];
	   oid oid_arr[MAX_OID_LEN];
           int oid_arr_len = MAX_OID_LEN;
           char * label;
           char * iid;
           int status = FAILURE;
           int verbose = SvIV(perl_get_sv("SNMP::verbose", 0x01 | 0x04));

           if (Mib == NULL && auto_init) {
              if (verbose) warn("snmp_translate_obj:initializing MIB\n");
                 init_mib();
              if (Mib) {
                 if (verbose) warn("snmp_translate_obj:done\n");
              } else {
                 if (verbose) warn("snmp_translate_obj:failed\n");
              }
           }

           str_buf[0] = '\0';
  	   switch (mode) {
              case SNMP_XLATE_MODE_TAG2OID:
		if (!__tag2oid(var, NULL, oid_arr, &oid_arr_len, NULL)) {
		   if (verbose) warn("error:snmp_translate_obj:Unknown OID %s\n",var);
                } else {
                   status = __sprint_num_objid(str_buf, oid_arr, oid_arr_len);
                }
                break;
             case SNMP_XLATE_MODE_OID2TAG:
		oid_arr_len = 0;
		__concat_oid_str(oid_arr, &oid_arr_len, var);
		sprint_objid(str_buf, oid_arr, oid_arr_len);
		if (!use_long) {
                  label = NULL; iid = NULL;
		  if (((status=__get_label_iid(str_buf,
		       &label, &iid, NO_FLAGS)) == SUCCESS)
		      && label) {
		     strcpy(str_buf, label);
		     if (iid && *iid) {
		       strcat(str_buf, ".");
		       strcat(str_buf, iid);
		     }
 	          }
	        }
                break;
             default:
	       if (verbose) warn("snmp_translate_obj:unknown translation mode: %s\n", mode);
           }
           if (*str_buf) {
              RETVAL = (char*)str_buf;
           } else {
              RETVAL = (char*)NULL;
           }
	}
        OUTPUT:
        RETVAL

void
snmp_set_save_descriptions(val)
	int	val
	CODE:
	{
	   snmp_set_save_descriptions(val);
	}

void
snmp_set_debugging(val)
	int	val
	CODE:
	{
	   snmp_set_do_debugging(val);
	}

void
snmp_sock_cleanup()
	CODE:
	{
	   SOCK_CLEANUP;
	}

void
snmp_main_loop(timeout_sec,timeout_usec,perl_callback)
	int 	timeout_sec
	int 	timeout_usec
	SV *	perl_callback
	CODE:
	{
        int numfds, fd_count;
        fd_set fdset;
        struct timeval time_val, *tvp;
        struct timeval last_time, *ltvp;
        struct timeval ctimeout, *ctvp;
        struct timeval interval, *itvp;
        int block;
	itvp = &interval;
	itvp->tv_sec = timeout_sec;
	itvp->tv_usec = timeout_usec;
        ctvp = &ctimeout;
        ctvp->tv_sec = -1;
        ltvp = &last_time;
        gettimeofday(ltvp,(struct timezone*)0);
	timersub(ltvp,itvp,ltvp);
        while (1) {
           numfds = 0;
           FD_ZERO(&fdset);
           block = 1;
           tvp = &time_val;
           timerclear(tvp);
           snmp_select_info(&numfds, &fdset, tvp, &block);
           __recalc_timeout(tvp,ctvp,ltvp,itvp,&block);
           # printf("pre-select: numfds = %ld, block = %ld\n", numfds, block);
           if (block == 1) tvp = NULL; /* block without timeout */
           fd_count = select(numfds, &fdset, 0, 0, tvp);
           #printf("post-select: fd_count = %ld,block = %ld\n",fd_count,block);
           if (fd_count > 0) {
                       dSP;
                       ENTER;
                       SAVETMPS;
              snmp_read(&fdset);
                       FREETMPS;
                       LEAVE;

           } else switch(fd_count) {
              case 0:
                 snmp_timeout();
                 if (!timerisset(ctvp)) {
                    if (SvTRUE(perl_callback)) {
                       dSP;
                       ENTER;
                       SAVETMPS;
                       /* sv_2mortal(perl_callback); */
                       __push_cb_args(&perl_callback, NULL);
                       __call_callback(perl_callback, G_DISCARD);
                       FREETMPS;
                       LEAVE;
                       ctvp->tv_sec = -1;
                    } else {
                       goto done;
                    }
                 }
                 break;
              case -1:
                 if (errno == EINTR) {
                    continue;
                 } else {
                    /* snmp_set_detail(strerror(errno)); */
                    /* snmp_errno = SNMPERR_GENERR; */
                 }
              default:;
           }
        }
     done:
           return;
	}


void
snmp_get_select_info()
	PPCODE:
	{
        int numfds, fd_count;
        fd_set fdset;
        struct timeval time_val, *tvp;
        int block;
	int timeout_sec;
	int timeout_usec;
	int i;

        numfds = 0;
        block = 1;
        tvp = &time_val;
        FD_ZERO(&fdset);
        snmp_select_info(&numfds, &fdset, tvp, &block);
	XPUSHs(sv_2mortal(newSViv(block)));
	if(block){
            XPUSHs(sv_2mortal(newSViv(0)));
            XPUSHs(sv_2mortal(newSViv(0)));
	} else {
            XPUSHs(sv_2mortal(newSViv(tvp->tv_sec)));
            XPUSHs(sv_2mortal(newSViv(tvp->tv_usec)));
	}
	if ( numfds ) {
            for(i=0; i<numfds ; i++) {
                if(FD_ISSET(i, &fdset)){
                    XPUSHs(sv_2mortal(newSViv(i)));
                }
            }
	} else {
            XPUSHs(&sv_undef);  /* no mem or bad args */
	}
	}

void
snmp_read_on_fd(fd)
	int fd
	CODE:
	{
           fd_set fdset;

           FD_ZERO(&fdset);
           FD_SET(fd, &fdset);

           snmp_read(&fdset);
	}

void
snmp_check_timeout()
	CODE:
	{
          snmp_timeout();
	}

MODULE = SNMP	PACKAGE = SNMP::MIB::NODE 	PREFIX = snmp_mib_node_
SV *
snmp_mib_node_TIEHASH(class,key,tp=0)
	char *	class
	char *	key
        IV tp
	CODE:
	{
           if (!tp) tp = (IV)__tag2oid(key, NULL, NULL, NULL, NULL);
           if (tp) {
              ST(0) = sv_newmortal();
              sv_setref_iv(ST(0), class, tp);
           } else {
              ST(0) = &sv_undef;
           }

	}

SV *
snmp_mib_node_FETCH(tp_ref, key)
	SV *	tp_ref
	char *	key
	CODE:
	{
	   char c = *key;
	   char str_buf[STR_BUF_SIZE];
           SnmpMibNode *tp = NULL;
           struct index_list *ip;
           struct enum_list *ep;
           struct module *mp;
           SV *child_list_aref, *next_node_href, *mib_tied_href, **nn_hrefp;
           HV *mib_hv, *enum_hv;
           AV *index_av;
           MAGIC *mg;

           if (SvROK(tp_ref)) tp = (SnmpMibNode*)SvIV((SV*)SvRV(tp_ref));

	   ST(0) = sv_newmortal();
           if (tp)
	   switch (c) {
	      case 'o': /* objectID */
                 if (strncmp("objectID", key, strlen(key))) break;
                 __tp_sprint_num_objid(str_buf, tp);
                 sv_setpv(ST(0),str_buf);
                 break;
	      case 'l': /* label */
                 if (strncmp("label", key, strlen(key))) break;
                 sv_setpv(ST(0),tp->label);
                 break;
	      case 's': /* subID */
                 if (strncmp("subID", key, strlen(key))) {
                   if (strncmp("status", key, strlen(key))) {
                      if (strncmp("syntax", key, strlen(key))) break;
                      if (tp->tc_index >= 0) {
                         sv_setpv(ST(0), get_tc_descriptor(tp->tc_index));
                      } else {
                         __get_type_str(tp->type, str_buf);
                         sv_setpv(ST(0), str_buf);
                      }
                      break;
                   }

                   switch(tp->status) {
                     case MIB_STATUS_MANDATORY:
                       sv_setpv(ST(0),"Mandatory");
                       break;
                     case MIB_STATUS_OPTIONAL:
                       sv_setpv(ST(0),"Optional");
                       break;
                     case MIB_STATUS_OBSOLETE:
                       sv_setpv(ST(0),"Obsolete");
                       break;
                     case MIB_STATUS_DEPRECATED:
                       sv_setpv(ST(0),"Deprecated");
                       break;
		     case MIB_STATUS_CURRENT:
                       sv_setpv(ST(0),"Current");
                       break;
                     default:
                       break;
                   }
                 } else {
                   sv_setiv(ST(0),(I32)tp->subid);
                 }
                 break;
	      case 'm': /* moduleID */
                 if (strncmp("moduleID", key, strlen(key))) break;
                 mp = find_module(tp->modid);
                 if (mp) sv_setpv(ST(0), mp->name);
                 break;
	      case 'p': /* parent */
                 if (strncmp("parent", key, strlen(key))) break;
                 tp = tp->parent;
                 if (tp == NULL) {
                    sv_setsv(ST(0), &sv_undef);
                    break;
                 }
                 mib_hv = perl_get_hv("SNMP::MIB", FALSE);
                 if (SvMAGICAL(mib_hv)) mg = mg_find((SV*)mib_hv, 'P');
                 if (mg) mib_tied_href = (SV*)mg->mg_obj;
                 next_node_href = newRV((SV*)newHV());
                 __tp_sprint_num_objid(str_buf, tp);
                 nn_hrefp = hv_fetch((HV*)SvRV(mib_tied_href),
                                     str_buf, strlen(str_buf), 1);
                 if (!SvROK(*nn_hrefp)) {
                 sv_setsv(*nn_hrefp, next_node_href);
                 ENTER ;
                 SAVETMPS ;
                 PUSHMARK(sp) ;
                 XPUSHs(SvRV(*nn_hrefp));
                 XPUSHs(sv_2mortal(newSVpv("SNMP::MIB::NODE",0)));
                 XPUSHs(sv_2mortal(newSVpv(str_buf,0)));
                 XPUSHs(sv_2mortal(newSViv((IV)tp)));
                 PUTBACK ;
                 perl_call_pv("SNMP::_tie",G_VOID);
                 /* pp_tie(ARGS); */
                 SPAGAIN ;
                 FREETMPS ;
                 LEAVE ;
                 }
                 sv_setsv(ST(0), *nn_hrefp);
                 break;
  	      case 'c': /* children */
                 if (strncmp("children", key, strlen(key))) break;
                 child_list_aref = newRV((SV*)newAV());
                 for (tp = tp->child_list; tp; tp = tp->next_peer) {
                    mib_hv = perl_get_hv("SNMP::MIB", FALSE);
                    if (SvMAGICAL(mib_hv)) mg = mg_find((SV*)mib_hv, 'P');
                    if (mg) mib_tied_href = (SV*)mg->mg_obj;
                    next_node_href = newRV((SV*)newHV());
                    __tp_sprint_num_objid(str_buf, tp);
                    nn_hrefp = hv_fetch((HV*)SvRV(mib_tied_href),
                                        str_buf, strlen(str_buf), 1);
                    if (!SvROK(*nn_hrefp)) {
                       sv_setsv(*nn_hrefp, next_node_href);
                       ENTER ;
                       SAVETMPS ;
                       PUSHMARK(sp) ;
                       XPUSHs(SvRV(*nn_hrefp));
                       XPUSHs(sv_2mortal(newSVpv("SNMP::MIB::NODE",0)));
                       XPUSHs(sv_2mortal(newSVpv(str_buf,0)));
                       XPUSHs(sv_2mortal(newSViv((IV)tp)));
                       PUTBACK ;
                       perl_call_pv("SNMP::_tie",G_VOID);
                       /* pp_tie(ARGS); */
                       SPAGAIN ;
                       FREETMPS ;
                       LEAVE ;
                    } /* if SvROK */
                    av_push((AV*)SvRV(child_list_aref), *nn_hrefp);
                 } /* for child_list */
                 sv_setsv(ST(0), child_list_aref);
                 break;
	      case 'n': /* nextNode */
                 if (strncmp("nextNode", key, strlen(key))) break;
                 tp = __get_next_mib_node(tp);
                 if (tp == NULL) {
                    sv_setsv(ST(0), &sv_undef);
                    break;
                 }
                 mib_hv = perl_get_hv("SNMP::MIB", FALSE);
                 if (SvMAGICAL(mib_hv)) mg = mg_find((SV*)mib_hv, 'P');
                 if (mg) mib_tied_href = (SV*)mg->mg_obj;
                 __tp_sprint_num_objid(str_buf, tp);

                 nn_hrefp = hv_fetch((HV*)SvRV(mib_tied_href),
                                     str_buf, strlen(str_buf), 1);
                 /* if (!SvROK(*nn_hrefp)) { */ /* bug in ucd - 2 .0.0 nodes */
                 next_node_href = newRV((SV*)newHV());
                 sv_setsv(*nn_hrefp, next_node_href);
                 ENTER ;
                 SAVETMPS ;
                 PUSHMARK(sp) ;
                 XPUSHs(SvRV(*nn_hrefp));
                 XPUSHs(sv_2mortal(newSVpv("SNMP::MIB::NODE",0)));
                 XPUSHs(sv_2mortal(newSVpv(str_buf,0)));
                 XPUSHs(sv_2mortal(newSViv((IV)tp)));
                 PUTBACK ;
                 perl_call_pv("SNMP::_tie",G_VOID);
                 /* pp_tie(ARGS); */
                 SPAGAIN ;
                 FREETMPS ;
                 LEAVE ;
                 /* } */
                 sv_setsv(ST(0), *nn_hrefp);
                 break;
	      case 't': /* type */
                 if (strncmp("type", key, strlen(key))) {
                    if (strncmp("textualConvention", key, strlen(key))) break;
                    sv_setpv(ST(0), get_tc_descriptor(tp->tc_index));
                    break;
                 }
                 __get_type_str(tp->type, str_buf);
                 sv_setpv(ST(0), str_buf);
                 break;
	      case 'a': /* access */
                 if (strncmp("access", key, strlen(key))) break;
                 switch	(tp->access) {
                   case MIB_ACCESS_READONLY:
                     sv_setpv(ST(0),"ReadOnly");
                     break;
                   case MIB_ACCESS_READWRITE:
                     sv_setpv(ST(0),"ReadWrite");
                     break;
                   case MIB_ACCESS_WRITEONLY:
                     sv_setpv(ST(0),"WriteOnly");
                     break;
                   case MIB_ACCESS_NOACCESS:
                     sv_setpv(ST(0),"NoAccess");
                     break;
                   case MIB_ACCESS_NOTIFY:
                     sv_setpv(ST(0),"Notify");
                     break;
                   case MIB_ACCESS_CREATE:
                     sv_setpv(ST(0),"Create");
                     break;
                   default:
                     break;
                 }
                 break;
	      case 'u': /* units */
                 if (strncmp("units", key, strlen(key))) break;
                 sv_setpv(ST(0),tp->units);
                 break;
	      case 'h': /* hint */
                 if (strncmp("hint", key, strlen(key))) break;
                 sv_setpv(ST(0),tp->hint);
                 break;
	      case 'e': /* enums */
                 if (strncmp("enums", key, strlen(key))) break;
                 enum_hv = newHV();
                 for(ep=tp->enums; ep != NULL; ep = ep->next) {
                   hv_store(enum_hv, ep->label, strlen(ep->label),
                                newSViv(ep->value), 0);
                 }
                 sv_setsv(ST(0), newRV((SV*)enum_hv));
                 break;
              case 'i': /* indexes */
                 if (strncmp("indexes", key, strlen(key))) break;
                 index_av = newAV();
                 for(ip=tp->indexes; ip != NULL; ip = ip->next) {
                    av_push(index_av,newSVpv((ip->ilabel),strlen(ip->ilabel)));
                 }
                sv_setsv(ST(0), newRV((SV*)index_av));
                break;
	      case 'd': /* description */
                 if (strncmp("description", key, strlen(key))) break;
                 sv_setpv(ST(0),tp->description);
                 break;
              default:
                 break;
	   }
	}

MODULE = SNMP	PACKAGE = SnmpSessionPtr	PREFIX = snmp_session_
void
snmp_session_DESTROY(sess_ptr)
	SnmpSession *sess_ptr
	CODE:
	{
           snmp_close( sess_ptr );
	}

