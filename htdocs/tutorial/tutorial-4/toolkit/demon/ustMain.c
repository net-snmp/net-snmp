#include <ucd-snmp/ucd-snmp-config.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <ucd-snmp/ucd-snmp-includes.h>
#include <ucd-snmp/ucd-snmp-agent-includes.h>
#include <signal.h>

static int keep_running;

RETSIGTYPE
stop_server(int a) {
    keep_running = 0;
}

main () {
  int agentx_subagent=1; /* change this if you're a master agent */

  /* print log errors to stderr */
  snmp_enable_stderrlog();

  /* we're an agentx subagent? */
  if (agentx_subagent) {
    /* make us a agentx client. */
    ds_set_boolean(DS_APPLICATION_ID, DS_AGENT_ROLE, 1);
  }

  /* initialize tcpip, if necessary */
  SOCK_STARTUP;

  /* initialize the agent library */
  init_agent("ustMain");

  /* initialize your mib code here */
  init_ustScalarSet();  /* init_ustScalarSet from ustScalarSet.C */

  /* ustMain will be used to read ustMain.conf files. */
  init_snmp("ustMain");

  /* If we're going to be a snmp master agent */
  if (!agentx_subagent)
    init_master_agent( 161, NULL, NULL );  /* open port 161 (UDP:snmp) */

  /* In case we recevie a request to stop (kill -TERM or kill -INT) */
  keep_running = 1;
  signal(SIGTERM, stop_server);
  signal(SIGINT, stop_server);

  /* you're main loop here... */
  while(keep_running) {
    /* if you use select(), see snmp_select_info() in snmp_api(3) */
    /*     --- OR ---  */
    agent_check_and_process(1); /* 0 == don't block */
  }

  /* at shutdown time */
  snmp_shutdown("ustMain");
  SOCK_SHUTDOWN;
}

