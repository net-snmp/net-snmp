#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <signal.h>

#include <XXX.h>

static int keep_running;

RETSIGTYPE
stop_server(int a) {
    keep_running = 0;
}

int
main (int argc, char **argv) {
  int agentx_subagent=1; /* change this if you're a master agent */
  int background = 0; /* change this if you want to run in the background */
  int syslog = 0; /* change this if you want to use syslog */

  /* print log errors to syslog/stderr */
  if (syslog)
    snmp_enable_calllog();
  else
    snmp_enable_stderrlog();

  /* we're an agentx subagent? */
  if (agentx_subagent) {
    /* make us a agentx client. */
    ds_set_boolean(DS_APPLICATION_ID, DS_AGENT_ROLE, 1);
  }

  /* run in background, if requested */
  if (background && netsnmp_daemonize(1, !syslog))
      exit(1);

  /* initialize the agent library */
  init_agent("ustMain");

  /* initialize your mib code here */
  init_XXX();  /* init_XXX from XXX.C */

  /* ustMain will be used to read ustMain.conf files. */
  init_snmp("ustMain");

  /* If we're going to be a snmp master agent */
  if (!agentx_subagent)
    init_master_agent();  /* open port 161 (UDP:snmp) */

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
/*  snmp_shutdown("ustMain"); */
}

