/* callback.c: A generic callback mechanism */

#include <config.h>
#include <sys/types.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "tools.h"
#include "callback.h"
#include "asn1.h"
#include "snmp_api.h"
#include "snmp_debug.h"

static struct snmp_gen_callback *thecallbacks[MAX_CALLBACK_IDS][MAX_CALLBACK_SUBIDS];

/* the chicken. or the egg.  You pick. */
void
init_callbacks(void) {
  memset(thecallbacks, 0, sizeof(thecallbacks));
}

int
snmp_register_callback(int major, int minor, SNMPCallback *new_callback,
                       void *arg) {

  struct snmp_gen_callback *scp;
  
  if (major > MAX_CALLBACK_IDS || minor > MAX_CALLBACK_SUBIDS) {
    return SNMPERR_GENERR;
  }
  
  if (thecallbacks[major][minor] != NULL) {
    /* get to the end of the list */
    for(scp = thecallbacks[major][minor]; scp->next != NULL; scp = scp->next);

    /* mallocate a new entry */
    scp->next = SNMP_MALLOC_STRUCT(snmp_gen_callback);
    scp = scp->next;
  } else {
    /* mallocate a new entry */
    scp = SNMP_MALLOC_STRUCT(snmp_gen_callback);

    /* make the new node the head */
    thecallbacks[major][minor] = scp;
  }

  if (scp == NULL)
    return SNMPERR_GENERR;

  scp->sc_client_arg = arg;
  scp->sc_callback = new_callback;

  DEBUGMSGTL(("callback","registered callback for maj=%d min=%d\n",
              major, minor));

  return SNMPERR_SUCCESS;
}

int
snmp_call_callbacks(int major, int minor, void *caller_arg) {
  struct snmp_gen_callback *scp;

  if (major > MAX_CALLBACK_IDS || minor > MAX_CALLBACK_SUBIDS) {
    return SNMPERR_GENERR;
  }

  DEBUGMSGTL(("callback","START calling callbacks for maj=%d min=%d\n",
              major, minor));

  /* for each registered callback of type major and minor */
  for(scp = thecallbacks[major][minor]; scp != NULL; scp = scp->next) {

    /* call them */
    (*(scp->sc_callback))(major, minor, caller_arg, scp->sc_client_arg);
  }
  
  DEBUGMSGTL(("callback","END calling callbacks for maj=%d min=%d\n",
              major, minor));

  return SNMPERR_SUCCESS;
}
