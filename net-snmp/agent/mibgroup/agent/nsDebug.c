#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/scalar.h>

#ifdef HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "agent/nsDebug.h"
#include "util_funcs.h"



/*
 * OIDs for the debugging control scalar objects
 *
 * Note that these we're registering the full object rather
 *  than the (sole) valid instance in each case, in order
 *  to handle requests for invalid instances properly.
 */
oid nsDebugEnabled_oid[]    = { 1, 3, 6, 1, 4, 1, 8072, 1, 7, 1, 1};
oid nsDebugOutputAll_oid[]  = { 1, 3, 6, 1, 4, 1, 8072, 1, 7, 1, 2};
oid nsDebugDumpPdu_oid[]    = { 1, 3, 6, 1, 4, 1, 8072, 1, 7, 1, 3};

/*
 * ... and for the token table.
 * And yes - I am mixing old and new APIs here!
 */

#define  DBGTOKEN_PREFIX	2
#define  DBGTOKEN_ENABLED	3
oid nsDebugTokenTable_oid[] = { 1, 3, 6, 1, 4, 1, 8072, 1, 7, 1, 4, 1};
struct variable2 nsDebugTokenTable_variables[] = {
  { DBGTOKEN_PREFIX,  ASN_OCTET_STR, RWRITE, var_dbgtokens, 1, {2}},
  { DBGTOKEN_ENABLED, ASN_INTEGER,   RWRITE, var_dbgtokens, 1, {3}}
};


void
init_nsDebug(void)
{
    DEBUGMSGTL(("nsDebugScalars", "Initializing\n"));

    /*
     * Register the scalar objects...
     */
    netsnmp_register_scalar(
        netsnmp_create_handler_registration(
            "nsDebugEnabled", handle_nsDebugEnabled,
            nsDebugEnabled_oid, OID_LENGTH(nsDebugEnabled_oid),
            HANDLER_CAN_RWRITE)
        );
    netsnmp_register_scalar(
        netsnmp_create_handler_registration(
            "nsDebugOutputAll", handle_nsDebugOutputAll,
            nsDebugOutputAll_oid, OID_LENGTH(nsDebugOutputAll_oid),
            HANDLER_CAN_RWRITE)
        );
    netsnmp_register_scalar(
        netsnmp_create_handler_registration(
            "nsDebugDumpPdu", handle_nsDebugDumpPdu,
            nsDebugDumpPdu_oid, OID_LENGTH(nsDebugDumpPdu_oid),
            HANDLER_CAN_RWRITE)
        );

    /*
     * ... and the table.
     */
    REGISTER_MIB("nsDebugTokenTable", nsDebugTokenTable_variables,
                variable2, nsDebugTokenTable_oid);
}


int
handle_nsDebugEnabled(netsnmp_mib_handler *handler,
                netsnmp_handler_registration *reginfo,
                netsnmp_agent_request_info *reqinfo,
                netsnmp_request_info *requests)
{
    int enabled;
    netsnmp_request_info *request=NULL;

    switch (reqinfo->mode) {

    case MODE_GET:
	enabled = snmp_get_do_debugging();
	if ( enabled==0 )
	    enabled=2;		/* false */
	for (request = requests; request; request=request->next) {
	    snmp_set_var_typed_value(request->requestvb, ASN_INTEGER,
                                     (u_char*)&enabled, sizeof(enabled));
	}
	break;


    case MODE_SET_RESERVE1:
	for (request = requests; request; request=request->next) {
            if ( request->status != 0 ) {
                return SNMP_ERR_NOERROR;	/* Already got an error */
            }
            if ( request->requestvb->type != ASN_INTEGER ) {
                netsnmp_set_request_error(reqinfo, request, SNMP_ERR_WRONGTYPE);
                return SNMP_ERR_WRONGTYPE;
            }
            if (( *request->requestvb->val.integer != 1 ) &&
                ( *request->requestvb->val.integer != 2 )) {
                netsnmp_set_request_error(reqinfo, request, SNMP_ERR_WRONGVALUE);
                return SNMP_ERR_WRONGVALUE;
            }
        }
        break;

    case MODE_SET_COMMIT:
        enabled = *requests->requestvb->val.integer;
	if (enabled == 2 )	/* false */
	    enabled = 0;
	snmp_set_do_debugging( enabled );
        break;
    }

    return SNMP_ERR_NOERROR;
}


int
handle_nsDebugOutputAll(netsnmp_mib_handler *handler,
                netsnmp_handler_registration *reginfo,
                netsnmp_agent_request_info *reqinfo,
                netsnmp_request_info *requests)
{
    int enabled;
    netsnmp_request_info *request=NULL;

    switch (reqinfo->mode) {

    case MODE_GET:
	enabled = snmp_get_do_debugging();
	if ( enabled==0 )
	    enabled=2;		/* false */
	for (request = requests; request; request=request->next) {
	    snmp_set_var_typed_value(request->requestvb, ASN_INTEGER,
                                     (u_char*)&enabled, sizeof(enabled));
	}
	break;


    case MODE_SET_RESERVE1:
	for (request = requests; request; request=request->next) {
            if ( request->status != 0 ) {
                return SNMP_ERR_NOERROR;	/* Already got an error */
            }
            if ( request->requestvb->type != ASN_INTEGER ) {
                netsnmp_set_request_error(reqinfo, request, SNMP_ERR_WRONGTYPE);
                return SNMP_ERR_WRONGTYPE;
            }
            if (( *request->requestvb->val.integer != 1 ) &&
                ( *request->requestvb->val.integer != 2 )) {
                netsnmp_set_request_error(reqinfo, request, SNMP_ERR_WRONGVALUE);
                return SNMP_ERR_WRONGVALUE;
            }
        }
        break;

    case MODE_SET_COMMIT:
        enabled = *requests->requestvb->val.integer;
	if (enabled == 2 )	/* false */
	    enabled = 0;
	snmp_set_do_debugging( enabled );
        break;
    }

    return SNMP_ERR_NOERROR;
}


int
handle_nsDebugDumpPdu(netsnmp_mib_handler *handler,
                netsnmp_handler_registration *reginfo,
                netsnmp_agent_request_info *reqinfo,
                netsnmp_request_info *requests)
{
    int enabled;
    netsnmp_request_info *request=NULL;

    switch (reqinfo->mode) {

    case MODE_GET:
	enabled = netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
	                                 NETSNMP_DS_LIB_DUMP_PACKET);
	if ( enabled==0 )
	    enabled=2;		/* false */
	for (request = requests; request; request=request->next) {
	    snmp_set_var_typed_value(request->requestvb, ASN_INTEGER,
                                     (u_char*)&enabled, sizeof(enabled));
	}
	break;


    case MODE_SET_RESERVE1:
	for (request = requests; request; request=request->next) {
            if ( request->status != 0 ) {
                return SNMP_ERR_NOERROR;	/* Already got an error */
            }
            if ( request->requestvb->type != ASN_INTEGER ) {
                netsnmp_set_request_error(reqinfo, request, SNMP_ERR_WRONGTYPE);
                return SNMP_ERR_WRONGTYPE;
            }
            if (( *request->requestvb->val.integer != 1 ) &&
                ( *request->requestvb->val.integer != 2 )) {
                netsnmp_set_request_error(reqinfo, request, SNMP_ERR_WRONGVALUE);
                return SNMP_ERR_WRONGVALUE;
            }
        }
        break;

    case MODE_SET_COMMIT:
        enabled = *requests->requestvb->val.integer;
	if (enabled == 2 )	/* false */
	    enabled = 0;
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
	                       NETSNMP_DS_LIB_DUMP_PACKET, enabled);
        break;
    }

    return SNMP_ERR_NOERROR;
}

/*
 * var_tzIntTableFixed():
 *   Handle the tzIntTable as a fixed table of NUMBER_TZ_ENTRIES rows,
 *    with the timezone offset hardwired to be the same as the index.
 */
unsigned char *
var_dbgtokens(struct variable *vp,
    	    oid     *name,
    	    size_t  *length,
    	    int     exact,
    	    size_t  *var_len,
    	    WriteMethod **write_method)
{
  static long long_ret;
  int index;
  int ret;

  DEBUGMSGTL(( "nsDebugTokens", "var_dbgtokens: "));
  DEBUGMSGOID(("nsDebugTokens", vp->name, vp->namelen));
  DEBUGMSG  (( "nsDebugTokens", " %d (%s)\n", vp->magic, (exact?"Get":"GetNext")));

  /* 
   * The list of debug tokens is (almost) a 'simple' table,
   *   with indexes running from 0 to debug_num_tokens-1
   *   We'll just need to tweak the indexing to run from 1 later.
   */
  ret = header_simple_table(vp,name,length,exact,var_len,write_method,
                          debug_num_tokens);


  /*
   * Configure the write-handling routines, so we can create new rows.
   * Note that must be done *after* calling 'header_simple_table'
   *   since this routine resets the write_method hook to NULL.
   */
  switch(vp->magic) {
    case DBGTOKEN_PREFIX:
        *write_method = write_dbgPrefix;
	break;
    case DBGTOKEN_ENABLED:
        *write_method = write_dbgEnabled;
        break;
  }

  if (ret == MATCH_FAILED )
    return NULL;


  /* 
   * 'name' now holds the full OID of the instance being queried.
   * The last subidentifier is the index value, which needs to be
   * tweaked to be 0-based rather than 1-based.
   */
  index = name[(*length)-1];
  index--;

  /*
   * If there are empty slots in the table, we need to skip them
   */
  if (!dbg_tokens[index].token_name) {
      if (exact)
          return NULL;   /* This entry doesn't exist */

      while (++index < MAX_DEBUG_TOKENS) {
          if (dbg_tokens[index].token_name) {
              /* Found one that does, so update 'name' and continue */
              name[(*length)-1] = index+1;
              break;
	  }
      }
      if (index == MAX_DEBUG_TOKENS)
          return NULL;   /* Run out of possible slots */
  }


  /* 
   * this is where we do the value assignments for the mib results.
   */
  switch(vp->magic) {

    case DBGTOKEN_PREFIX:
        *write_method = write_dbgPrefix;
        *var_len      = strlen(dbg_tokens[index].token_name);
        return (unsigned char *) dbg_tokens[index].token_name;

    case DBGTOKEN_ENABLED:
        *write_method = write_dbgEnabled;
        long_ret = (dbg_tokens[index].enabled ? 1 : 2);
        return (unsigned char *) &long_ret;

    default:
      ERROR_MSG("");
  }
  return NULL;
}


int
write_dbgPrefix(int      action,
            u_char   *var_val,
            u_char   var_val_type,
            size_t   var_val_len,
            u_char   *statP,
            oid      *name,
            size_t   name_len)
{
  int index;

  DEBUGMSGTL(( "nsDebugTokens", "write_dbgPrefix: "));
  DEBUGMSGOID(("nsDebugTokens", name, name_len));
  DEBUGMSG  (( "nsDebugTokens", " = %*s ", var_val_len, var_val));
  DEBUGMSG  (( "nsDebugTokens", "pass %d - %s\n", action, (statP ? "update" : "create")));

  /* 
   * 'name' holds the full OID of the instance being set.
   * The last subidentifier is the index value, which needs
   * to be tweaked to be 0-based rather than 1-based.
   */
  index = name[name_len-1];
  index--;

  switch ( action ) {
        case RESERVE1:
             /*
              * Check that the proposed new value is appropriate
              *   (in terms of type, length and actual value).
              */
          if (index>MAX_DEBUG_TOKENS) {
              snmp_log(LOG_ERR, "failed attempt to create a new row (%d)\n", index);
              return SNMP_ERR_NOCREATION;	/* ??? */
          }
          if (var_val_type != ASN_OCTET_STR) {
              snmp_log(LOG_ERR, "write to nsDebugTokenPrefix: bad type (%x)\n", var_val_type);
              return SNMP_ERR_WRONGTYPE;
          }
          break;


        case RESERVE2:
        case FREE:
        case ACTION:
        case UNDO:
             /*
              * We're being lazy and doing everything in the COMMIT phase.
              */
          break;


        case COMMIT:
             /*
              * Insert the new token, and pray that the strdup works!
              */
          if (dbg_tokens[index].token_name)
              free(dbg_tokens[index].token_name);
          dbg_tokens[index].token_name = strdup(var_val);
	  if (index>=debug_num_tokens)
              debug_num_tokens=index+1;
          break;
  }
  return SNMP_ERR_NOERROR;
}


int
write_dbgEnabled(int      action,
            u_char   *var_val,
            u_char   var_val_type,
            size_t   var_val_len,
            u_char   *statP,
            oid      *name,
            size_t   name_len)
{
  int   index;
  long  long_ret;

  DEBUGMSGTL(( "nsDebugTokens", "write_dbgEnabled: "));
  DEBUGMSGOID(("nsDebugTokens", name, name_len));
  DEBUGMSG  (( "nsDebugTokens", " = %*s ", var_val_len, var_val));
  DEBUGMSG  (( "nsDebugTokens", "pass %d - %s\n", action, (statP ? "update" : "create")));

  /* 
   * 'name' holds the full OID of the instance being set.
   * The last subidentifier is the index value, which needs
   * to be tweaked to be 0-based rather than 1-based.
   */
  index = name[name_len-1];
  index--;

  switch ( action ) {
        case RESERVE1:
             /*
              * Check that the proposed new value is appropriate
              *   (in terms of type, length and actual value).
              */
          if (index>MAX_DEBUG_TOKENS) {
              snmp_log(LOG_ERR, "failed attempt to create a new row (%d)\n", index);
              return SNMP_ERR_NOCREATION;	/* ??? */
          }
          if (var_val_type != ASN_INTEGER) {
              snmp_log(LOG_ERR, "write to nsDebugTokenEnabled: bad type (%x)\n", var_val_type);
              return SNMP_ERR_WRONGTYPE;
          }
	  long_ret = *(long *)var_val;
          if (long_ret < 1 ||
              long_ret > 2) {
              snmp_log(LOG_ERR, "write to nsDebugTokenEnabled: bad value (%d)\n", long_ret);
              return SNMP_ERR_WRONGVALUE;
          }
          break;


        case RESERVE2:
        case FREE:
        case ACTION:
        case UNDO:
             /*
              * We're being lazy and doing everything in the COMMIT phase.
              */
          break;


        case COMMIT:
             /*
              * Mark this entry as enabled.
	      * TODO: Check that there is actually a valid token here.
	      * (That means handling nsDebugTokenPrefix SET requests
	      *  properly, i.e. in the ACTION pass, so we can rely on
	      *  it having been processed by this point).
              */
	  long_ret = *(long *)var_val;
	  if (long_ret == 2)
	      long_ret = 0;  /* disabled */
          dbg_tokens[index].enabled = long_ret;
	  if (index>=debug_num_tokens)
              debug_num_tokens=index+1;
          break;
  }
  return SNMP_ERR_NOERROR;
}
