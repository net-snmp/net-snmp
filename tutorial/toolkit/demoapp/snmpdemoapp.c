#include <ucd-snmp/ucd-snmp-config.h>
#include <ucd-snmp/ucd-snmp-includes.h>
#include <ucd-snmp/system.h>   /* remove if included by previous header file */

int main(int argc, char ** argv)
{
    struct snmp_session session, *ss;
    struct snmp_pdu *pdu;
    struct snmp_pdu *response;

    oid anOID[MAX_OID_LEN];
    size_t anOID_len = MAX_OID_LEN;

    struct variable_list *vars;
    int status;

    /*
     * Initialize the SNMP library
     */
    init_snmp("snmpapp");

    /*
     * Initialize a "session" that defines who we're going to talk to
     */
    snmp_sess_init( &session );                   /* set up defaults */
    session.version = SNMP_VERSION_1;
    session.peername = "ucd-snmp.ucdavis.edu";
    session.community = "demopublic";
    session.community_len = strlen(session.community);

    /*
     * Open the session
     */
    SOCK_STARTUP;
    ss = snmp_open(&session);                     /* establish the session */

    /*
     * Create the PDU for the data for our request.
     *   1) We're going to GET the system.sysDescr.0 node.
     */
    pdu = snmp_pdu_create(SNMP_MSG_GET);
    read_objid(".1.3.6.1.2.1.1.1.0", anOID, &anOID_len);

#if OTHER_METHODS
    get_node("sysDescr.0", anOID, &anOID_len);
    read_objid(".1.3.6.1.2.1.1.1.0", anOID, &anOID_len);
    read_objid("system.sysDescr.0", anOID, &anOID_len);
#endif

    snmp_add_null_var(pdu, anOID, anOID_len);
  
    /*
     * Send the Request out.
     */
    status = snmp_synch_response(ss, pdu, &response);

    /*
     * Process the response.
     */
    if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
      /*
       * SUCCESS: Print the result variables
       */

      for(vars = response->variables; vars; vars = vars->next_variable)
        print_variable(vars->name, vars->name_length, vars);

      /* manipuate the information ourselves */
      for(vars = response->variables; vars; vars = vars->next_variable) {
        int count=1;
        if (vars->type == ASN_OCTET_STR) {
	  char *sp = (char *)malloc(1 + vars->val_len);
	  memcpy(sp, vars->val.string, vars->val_len);
	  sp[vars->val_len] = '\0';
          printf("value #%d is a string: %s\n", count++, sp);
	  free(sp);
	}
        else
          printf("value #%d is NOT a string! Ack!\n", count++);
      }
    } else {
      /*
       * FAILURE: print what went wrong!
       */

      if (status == STAT_SUCCESS)
        fprintf(stderr, "Error in packet\nReason: %s\n",
                snmp_errstring(response->errstat));
      else
        snmp_sess_perror("snmpget", ss);

    }

    /*
     * Clean up:
     *  1) free the response.
     *  2) close the session.
     */
    if (response)
      snmp_free_pdu(response);
    snmp_close(ss);

    SOCK_CLEANUP;
    return (0);
} /* main() */
