#include <config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "mibincl.h"
#include "tools.h"
#include "snmp_agent.h"

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include "null.h"

int register_null(oid *loc, size_t loc_len) {
    handler_registration *reginfo;
    reginfo = SNMP_MALLOC_TYPEDEF(handler_registration);
    reginfo->handlerName = strdup("");
    reginfo->rootoid = loc;
    reginfo->rootoid_len = loc_len;
    reginfo->handler = create_handler("null", null_handler);
    return register_handler(reginfo);
}

int
null_handler(mib_handler               *handler,
             handler_registration      *reginfo,
             agent_request_info        *reqinfo,
             request_info              *requests) {
    DEBUGMSGTL(("helper:null", "Got request\n"));

		DEBUGMSGTL(("helper:null", "  oid:"));
		DEBUGMSGOID(("helper:null", requests->requestvb->name,
								 requests->requestvb->name_length));
		DEBUGMSG(("helper:null", "\n"));

    switch(reqinfo->mode) {
        case MODE_GETNEXT:
        case MODE_GETBULK:
            return SNMP_ERR_NOERROR;

        case MODE_GET:
            set_all_requests_error(reqinfo, requests, SNMP_NOSUCHOBJECT);
            return SNMP_ERR_NOERROR;

        default:
            set_all_requests_error(reqinfo, requests, SNMP_ERR_NOSUCHNAME);
            return SNMP_ERR_NOERROR;
    }
}
