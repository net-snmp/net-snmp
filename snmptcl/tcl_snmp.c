/* tcl_snmp.c
 * SNMP interface for Tcl
 * 
 * Poul-Henning Kamp, phk@data.fls.dk
 * 920319 0.00
 * 920322 0.01
 * 920324 0.02
 */

#include <stdio.h>
#include <malloc.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>


#include <snmp.h>
#include <asn1.h>
#include <snmp_impl.h>
#include <snmp_api.h>
#include <snmp_client.h>
#include <party.h>
#include <context.h>
#include <mib.h>

#include <tcl.h>
#include "tcl_misc.h"

static char *TraceDebug();
static int SnmpProc();
static int SessProc();

int snmp_dump_packet = 0;

typedef struct
{
    int		debug;
    char	where[64];
} t_cldat;

typedef struct
{
    t_cldat	*cd;
    char	name[64] ;
    struct snmp_session *sess,ss;
    struct snmp_pdu *pdu,*response;
    int		status;
    char	where[64];
} t_cldat2;

/****************************************************************************
 *
 * snmp_init(interp)
 * =================
 * 
 * Initialize the snmp interface.
 *
 ****************************************************************************/

void
    snmp_init(interp)
Tcl_Interp	*interp;
{
    t_cldat *cd;
    
    init_mib();
    cd = (t_cldat *)ckalloc(sizeof *cd);
    memset((void*)cd,0,sizeof *cd);
    Tcl_CreateCommand(interp,"snmp",SnmpProc,cd,0);
    Tcl_SetVar(interp,"snmp_debug","0",0);
    Tcl_TraceVar(interp,"snmp_debug",
		 TCL_TRACE_WRITES|TCL_TRACE_UNSETS,TraceDebug,cd);
}

static char*
    TraceDebug(cd,interp,name1,name2,flags)
t_cldat *cd;
Tcl_Interp	*interp;
char *name1;
char *name2;
int flags;
{
    cd->debug=0;
    if(flags & TCL_TRACE_WRITES) 
	cd->debug = atoi(Tcl_GetVar(interp,"snmp_debug",flags&TCL_GLOBAL_ONLY));
    if(flags & TCL_TRACE_UNSETS) 
	Tcl_SetVar(interp,"snmp_debug","0",flags&TCL_GLOBAL_ONLY);
    if(flags & TCL_TRACE_DESTROYED)
	Tcl_TraceVar(interp,"snmp_debug",
		     TCL_TRACE_WRITES|TCL_TRACE_UNSETS,TraceDebug,cd);
    fprintf(stderr,"[SNMP]: debug is now %d\n",cd->debug);
    if(cd->debug > 99)
	snmp_dump_packet = 1;
    else
	snmp_dump_packet = 0;
    return 0;
}

static char *
    stralloc(s)
char *s;
{
    char *t = (char *)ckalloc(strlen(s)+1);
    strcpy(t,s);
    return t;
}

OidCpy(d,dl,s,sl)
    oid *d,*s;
    int *dl,*sl;
{
    memcpy(d,s,(*sl) * sizeof(*d));
    *dl = *sl;
}

int
    OidCmp(d,s,l)
oid *d,*s;
int l;
{
    return memcmp(d,s,l * sizeof(*d));
}

static int
    NextOid(interp,cd2,type,nvar)
Tcl_Interp  *interp;
t_cldat2 *cd2;
int type;
int *nvar;
{
    int i;
    struct variable_list *vars;
    oid name[MAX_NAME_LEN];
    int name_length;
    
    cd2->pdu = snmp_pdu_create(type);
    i=0;
    for(vars=cd2->response->variables;vars;vars=vars->next_variable)
	{
	    OidCpy(name,&name_length,vars->name,&vars->name_length);
	    snmp_add_null_var(cd2->pdu, name, name_length);
	    i++;
	}
    *nvar = i;
    return TCL_OK;
}


static char*
    VarVal(vars)
struct variable_list *vars;
{
    static char buf[8192], *s;
    
    sprint_value(buf,vars->name,vars->name_length,vars);
    for(s=buf;*s && *s != ':';s++) ;
    for(s++;*s && isspace(*s);s++) ;
    return s;
}

static char*
    Raw_Value(vars)
struct variable_list *vars;
{
    char *s1;
    int err = 0;

    static char tmp1[500], tmp2[500], tmp3[500], tmp4[500];
    char *retval;

    /* The tmp's are for a 
     * 1. result string
     * 2. result type
     * 3. result oid
     * 4. result err status
     */ 

    /* Get the result value.
     */

    sprintf(tmp1, "null");
    sprintf(tmp2, "null");
    sprintf(tmp3, "null");
    sprintf(tmp4, "null");
    err = 0;

    switch(vars->type) {
	/* Check for "errors", first */
	case SNMP_ENDOFMIBVIEW: {
	    /* End of MIB... */
	    err = SNMP_ENDOFMIBVIEW;
	    sprintf(tmp1, "null");
	    sprintf(tmp2, "null");
	    sprintf(tmp3, "null");
	    sprintf(tmp4, "end_of_mib");
	    break;
	}
	case SNMP_NOSUCHOBJECT: {
	    /* No such object */
	    err = SNMP_NOSUCHOBJECT;
	    sprintf(tmp1, "null");
	    sprintf(tmp2, "null");
	    sprintf(tmp3, "null");
	    sprintf(tmp4, "no_such_object");
	    break;
	}
	case SNMP_NOSUCHINSTANCE: {
	    /* No such instance */
	    err = SNMP_NOSUCHINSTANCE;
	    sprintf(tmp1, "null");
	    sprintf(tmp2, "null");
	    sprintf(tmp3, "null");
	    sprintf(tmp4, "no_such_instance");
	    break;
	}
	case OBJID: {
	    int j;
	    int noid;
	    int i = 0;

	    sprintf(tmp2, "oid");
	    
	    noid = vars->val_len / sizeof(oid);
	    tmp1[0] = 0;
	    for(j = 0; j < noid; j++) {
		i = strlen(tmp1);
		if (i == 0) {
		    sprintf(&(tmp1[i]), "%i", vars->val.objid[j]);
		} else {
		    sprintf(&(tmp1[i]), ".%i", vars->val.objid[j]);
		}
	    }
	    break;
	}
	case STRING: {
	    /* Some special case code-- check for non-printable chars. */
	    int i, j;

	    i = j = 0;

	    for (i = 0; i < vars->val_len; i++) {
		if (!(isprint(vars->val.string[i]))) {
		    /* Non-print character... We'll parse it differently. */
		    j = 1;
		}
	    }
	    if (!j) {
		sprintf(tmp2, "string");
		
		tmp1[0] = '"';
		bcopy(vars->val.string, (char *) &(tmp1[1]), vars->val_len);
		tmp1[vars->val_len + 1] = '"';
		tmp1[vars->val_len + 2] = 0;
	    } else {
		/* We'll display this sucker in hex. */
		sprintf(tmp2, "hex");
		tmp1[0] = '"';
		tmp1[1] = 0;
		for (i = 0; i < vars->val_len; i++) {
		    j = strlen(tmp1);
		    sprintf(&tmp1[j], " %02X ", (int) vars->val.string[i]);
		}
	        j = strlen(tmp1);
		sprintf(&tmp1[j], " \"");
	    }
	    break;
	}
	case INTEGER: {
	    sprintf(tmp2, "integer");
	    
	    sprintf(tmp1, "%i", *vars->val.integer);
	    break;
	}
	case GAUGE: {
	    sprintf(tmp2, "gauge");
	    sprintf(tmp1, "%i", *vars->val.integer);
	    break;
	}
	case COUNTER: {
	    sprintf(tmp2, "counter");
	    sprintf(tmp1, "%i", *vars->val.integer);
	    break;
	}
	case TIMETICKS: {
	    sprintf(tmp2, "timeticks");
	    sprintf(tmp1, "%i", *vars->val.integer);
	    break;
	}
	default: {
	    sprintf(tmp2, "unrecognized");
	    sprintf(tmp1, "Cannot_Parse_Result");
	    break;
	}
    }
    if (!err) {
	/* Create the oid returned. */
	{
	    int j;
	    int noid;
	    int i = 0;
	    
	    noid = vars->name_length;
	    tmp3[0] = 0;
	    for(j = 0; j < noid; j++) {
		i = strlen(tmp3);
		if (i == 0) {
		    sprintf(&(tmp3[i]), "%i", vars->name[j]);
		} else {
		    sprintf(&(tmp3[i]), ".%i", vars->name[j]);
		}
	    }
	}
    }
    retval = (char *) malloc (strlen(tmp1) + 
			      strlen(tmp2) +
			      strlen(tmp3) +
			      strlen(tmp4) + 10);
    sprintf(retval, "{%s %s %s %s}", tmp1, tmp2, tmp3, tmp4);
    return(retval);

    /* 128.2.232.132 */
}

static int
    ParseOid(interp,arg,cd2,type,nvar)
Tcl_Interp  *interp;
char *arg;
t_cldat2 *cd2;
int type;
int *nvar;
{
    int i;
    oid name[MAX_NAME_LEN];
    int name_length;
    char *s,*t;
    
    cd2->pdu = snmp_pdu_create(type);
    for(i=0,s=arg;*s;s=t,i++)
	{
	    for(;*s && isspace(*s);s++) ;
	    if(!*s) break;
	    for(t=s;*t && !isspace(*t);t++) ;
	    if(*t) *t++ = 0;
	    name_length = MAX_NAME_LEN;
	    if (!read_objid(s, name, &name_length))
		return Error(interp,cd2->where,"OID argument error.");
	    snmp_add_null_var(cd2->pdu, name, name_length);
	}
    if(!i)
	return Error(interp,cd2->where,"OID argument empty.");
    *nvar=i;
    return TCL_OK;
}

static int parse_setoid(interp, cd2, list, length)
    Tcl_Interp  *interp;
    t_cldat2 *cd2;
    char *list;
    int length;
{
    char *value;
    int   value_length;
    char *type;
    int   type_length;
    char *oid_name;
    int   oid_name_length;

    char value_str[100];
    char oid_str[100];

    char *element;
    char *next;
    int   sizePtr;
    int   braced;

    struct variable_list *vars;

    int i;
    oid name[MAX_NAME_LEN];
    int name_length;
    char *s,*t;

    if (!cd2->pdu) {
	cd2->pdu = snmp_pdu_create(SET_REQ_MSG);
    }

    if (!cd2->pdu->variables) {
	cd2->pdu->variables = (struct variable_list *) malloc (sizeof(struct variable_list));
	vars = cd2->pdu->variables;
	vars->next_variable = NULL;
    } else {
	for (vars = cd2->pdu->variables; vars->next_variable; vars = vars->next_variable);
	vars->next_variable = (struct variable_list *) malloc (sizeof(struct variable_list));
	vars = vars->next_variable;
	vars->next_variable = NULL;
    }
    /* At this point, vars points at a subject variable list entry to add. */
    
    value = list;
  
    TclFindElement(interp, list, &element, &next, &sizePtr, &braced);
    value_length = sizePtr;
    type = next;
    list = next;

    TclFindElement(interp, list, &element, &next, &sizePtr, &braced);
    
    type_length = sizePtr;
    oid_name = next;
    list = next;
    oid_name_length = length - ((int)oid_name - (int)value);

    /* At this point, we have delimited the arguments. */

    bcopy(value, value_str, value_length);
    value_str[value_length] = 0;

    bcopy(oid_name, oid_str, oid_name_length);
    oid_str[oid_name_length] = 0;

    /* Okay, now special case for each type... */

    if (!strncmp(type, "integer", 7)) {
	/* We write an integer... */
	vars->type = INTEGER;
	vars->val.integer = (int *) malloc (sizeof(int));
	vars->val_len = sizeof(int);
	*(vars->val.integer) = atoi(value_str);
    } else if (!strncmp(type, "string", 6)) {
	/* We write a string... */
	vars->type = STRING;
	vars->val.string = (u_char *) malloc (value_length);
	bcopy(value_str, vars->val.string, value_length);
    	vars->val_len = value_length;
    } else {
	printf("Haven't done this type yet.");
    }

    /* Okay, parse the oid */
    
    name_length = MAX_NAME_LEN;
    if (!read_objid(oid_str, name, &name_length)) {
	printf("Error parsing oid string");
    }

    vars->name = (oid *) malloc (sizeof(oid) * name_length);
    bcopy((char *) name, (char *) vars->name, name_length * sizeof(oid));
    vars->name_length = name_length;

    return TCL_OK;
}

static int SnmpSet(interp, argc, argv, cd2)
    Tcl_Interp  *interp;
    int argc;
    char **argv;
    t_cldat2 *cd2;
{
    char  *list;
    char *element;
    char *next;
    int   sizePtr;
    int   braced;

    /* We get to parse this list of stuff...
     * (Yay!)
     * (Not!)
     */

    /*
     * Format for snmpset:  
     *  session set "{value type name} [{value type name} [...]]"
     */

    /* There's a handy dandy utility for finding an element. 
     * It's called "TclFindElement".
     */

    if(cd2->response)
	snmp_free_pdu(cd2->response);
    cd2->response = NULL;

    cd2->pdu = NULL;

    next = (char *)1;
    list = argv[1];
    sizePtr = 5;
    while(next && sizePtr) {
	TclFindElement(interp, list, &element, &next, &sizePtr, &braced);
	if (sizePtr) {
	    parse_setoid(interp, cd2, element, sizePtr);
	    list = next;
	}
    }

    /* At this point, we should have a set request ready.
     */
    cd2->status = snmp_synch_response(cd2->sess, cd2->pdu, &cd2->response);

    if (cd2->status == STAT_SUCCESS) {
	if (cd2->response->errstat == SNMP_ERR_NOERROR) {
	    Tcl_SetResult(interp, "Success", TCL_VOLATILE);
	} else {
	    switch (cd2->response->errstat) {
		case SNMP_ERR_READONLY: {
		    Tcl_SetResult(interp, "readonly", TCL_VOLATILE);
		    break;
		} 
		case SNMP_ERR_BADVALUE: {
		    Tcl_SetResult(interp, "badvalue", TCL_VOLATILE);
		    break;
		}
		default: {
		    Tcl_SetResult(interp, "error", TCL_VOLATILE);
		    break;
		}
	    }
	}
    } else {
	Tcl_SetResult(interp, "network_error", TCL_VOLATILE);
    }

    return (TCL_OK);
}

static int SnmpGet(interp,argc,argv,cd2)
    Tcl_Interp  *interp;
    int argc;
    char **argv;
    t_cldat2 *cd2;
{
    int i,j;
    char *responses[200];
    int nresp = 0;
    struct variable_list *vars;
    char *retval;
    int tlen = 0;

    if((j = ParseOid(interp,argv[1],cd2,GET_REQ_MSG,&i)) != TCL_OK)
	return j;
    if(cd2->response)
	snmp_free_pdu(cd2->response);
    cd2->response = NULL;

    cd2->status = snmp_synch_response(cd2->sess,cd2->pdu,&cd2->response);

    if(i >= 1) {
	/* Let's check for a response, too! */
	if (cd2->status == STAT_SUCCESS) {
	    if (cd2->response->errstat == SNMP_ERR_NOERROR) {
		/* We have a valid response! 
		 * Let's return the sucker.  However, 
		 */
		for (nresp = 0, vars = cd2->response->variables; vars; vars = vars->next_variable) {
		    responses[nresp] = Raw_Value(vars);
		    nresp++;
		}
		tlen = 0;
		for (i = 0; i < nresp; i++) {
		    tlen += strlen(responses[i]);
		}
		retval = (char *) malloc(tlen + nresp + 5);
		retval[0] = 0;
		for (i = 0; i < nresp; i++) {
		    j = strlen(retval);
		    sprintf(&retval[j], "%s ", responses[i]);
		}
		Tcl_SetResult(interp, 
			      retval,
			      TCL_DYNAMIC);
	    } else {
		/* We have an error in the get request.
		 * We'll do something about this eventually.
		 */
		if (cd2->response->errstat == SNMP_ERR_NOSUCHNAME) {
		    Tcl_SetResult(interp, "{No_Such_name}", TCL_VOLATILE);
		} else {
		    printf("We have an error, dudes0.\n");
		}
	    }
	} else if (cd2->status == STAT_TIMEOUT) {
	    /* We have a timeout */
	    Tcl_SetResult(interp, "{Timeout}", TCL_VOLATILE);
	} else {
	    /* We have a nastier error of some kind */
	    printf("We have an error, dudes3.\n");
	}
    }
    return TCL_OK;
}

static int SnmpGetNext(interp,argc,argv,cd2)
    Tcl_Interp  *interp;
    int argc;
    char **argv;
    t_cldat2 *cd2;
{
    int i,j;
    char *responses[200];
    int nresp = 0;
    struct variable_list *vars;
    char *retval;
    int tlen = 0;

    if((j = ParseOid(interp,argv[1],cd2,GETNEXT_REQ_MSG,&i)) != TCL_OK)
	return j;
    if(cd2->response)
	snmp_free_pdu(cd2->response);
    cd2->response = NULL;

    cd2->status = snmp_synch_response(cd2->sess,cd2->pdu,&cd2->response);

    if(i >= 1) {
	/* Let's check for a response, too! */
	if (cd2->status == STAT_SUCCESS) {
	    if (cd2->response->errstat == SNMP_ERR_NOERROR) {
		/* We have a valid response! 
		 * Let's return the sucker.  However, 
		 */
		for (nresp = 0, vars = cd2->response->variables; vars; vars = vars->next_variable) {
		    responses[nresp] = Raw_Value(vars);
		    nresp++;
		}
		tlen = 0;
		for (i = 0; i < nresp; i++) {
		    tlen += strlen(responses[i]);
		}
		retval = (char *) malloc(tlen + nresp + 5);
		retval[0] = 0;
		for (i = 0; i < nresp; i++) {
		    j = strlen(retval);
		    sprintf(&retval[j], "%s ", responses[i]);
		}
		Tcl_SetResult(interp, 
			      retval,
			      TCL_DYNAMIC);
	    } else {
		/* We have an error in the get request.
		 * We'll do something about this eventually.
		 */
		if (cd2->response->errstat == SNMP_ERR_NOSUCHNAME) {
		    Tcl_SetResult(interp, "{No_Such_name}", TCL_VOLATILE);
		} else {
		    printf("We have an error, dudes0.\n");
		}
	    }
	} else if (cd2->status == STAT_TIMEOUT) {
	    /* We have a timeout */
	    Tcl_SetResult(interp, "{Timeout}", TCL_VOLATILE);
	} else {
	    /* We have a nastier error of some kind */
	    printf("We have an error, dudes3.\n");
	}
    }
    return TCL_OK;
}

static int SnmpWalk(interp,argc,argv,cd2)
    Tcl_Interp  *interp;
    int argc;
    char **argv;
    t_cldat2 *cd2;
{

#define WIDTH  50
    
    oid rname[WIDTH][MAX_NAME_LEN];
    int rname_length[WIDTH];
    oid oname[WIDTH][MAX_NAME_LEN];
    int oname_length[WIDTH];
    int dead[WIDTH];
    int finished = 0;

    char *retval;

    char *responses[100];

    struct variable_list *vars;

    int i,j;

    int tlen = 0;

    int nvars;
    int nresp;

    bzero((char *) dead, sizeof(dead));

    
    if((j = ParseOid(interp,argv[1],cd2,GETNEXT_REQ_MSG,&i)) != TCL_OK)
	return j;

    nvars = i;
    i = 0;
    for (vars = cd2->pdu->variables; vars; vars = vars->next_variable) {
	/* Copy all the names/lengths out... */
	OidCpy(&(oname[i][0]), &oname_length[i], vars->name, &vars->name_length);
	OidCpy(&(rname[i][0]), &rname_length[i], vars->name, &vars->name_length);
	i++;
    }

    /* Let's nuke that pdu ParseOid created: I'd rather make my own. */

    snmp_free_pdu(cd2->pdu);
    cd2->pdu = NULL;


    /* At this point, oname and rname contain the oids/lengths to request. */
    while (!finished) {
	/* For all the threads not dead... We'll request a packet. */
	finished = 1;
	cd2->pdu = NULL;
	for (i = 0; i < nvars; i++) {
	    if (!dead[i]) {
		if (!cd2->pdu) {
		    finished = 0;
		    cd2->pdu = snmp_pdu_create(GETNEXT_REQ_MSG);
		}
		snmp_add_null_var(cd2->pdu, rname[i], rname_length[i]);
	    }
	}
	if (!finished) {
	    cd2->status = snmp_synch_response(cd2->sess, cd2->pdu, &cd2->response);
	    if (cd2->status == STAT_SUCCESS) {
		if (cd2->response->errstat == SNMP_ERR_NOERROR) {
		    /* We got a successful packet...
		     * I'm going to copy the response parsing code from get.
		     * The name stuff is my own, though.
		     */
		    vars = cd2->response->variables;
		    finished = 1;
		    for (i = 0; i < nvars; i++) {
			if (!dead[i]) {
			    /* If we made a request, read the response. */
			    OidCpy(&(rname[i][0]), &rname_length[i], vars->name, &vars->name_length);
			    
			    /* Check the result value. 
			     * We need to see if we need to stop.
			     */

			    if (rname_length[i] < oname_length[i] || bcmp(oname[i], rname[i], oname_length[i] * sizeof(oid))) {
				/* This is no longer a part of the subtree... */
				dead[i] = 1;
			    } else {
				/* At least one valid response... */
				finished = 0;
			    }
			    vars = vars->next_variable;
			}
		    }
		    /* Now, we want to parse ONLY those values that are alive...
		     * remembering that some of the resoponses just died.
		     * This introduces two "dead" states: state
		     * 1 = Just died; it exists in this packet.
		     * 2 = Long dead; it does not exist in this packet.
		     */
		    nresp = 0;
		    vars = cd2->response->variables;
		    /* Note that this creates a complete response set, filling in blanks. */
		    for (i = 0; i < nvars; i++) {
			if (!dead[i] || dead[i] == 1) {
			    /* We have to do this one...
			     * I'm taking this stuff all from snmpget, now. 
			     */
			    if (dead[i] == 1) {
				dead[i] = 2;
				responses[i] = "{done}";
			    } else {
				responses[i] = Raw_Value(vars);
			    }
			    vars = vars->next_variable;
			    nresp++;
			} else {
			    responses[i] = "{done}";
			}
		    }
		    tlen = 0;
		    for (i = 0; i < nvars; i++) {
			tlen += strlen(responses[i]);
		    }
		    retval = (char *) malloc(tlen + nresp * 2 + 5);
		    retval[0] = 0;
		    for (i = 0; i < nvars; i++) {
			j = strlen(retval);
			sprintf(&retval[j], " %s ", responses[i]);
		    }
		    
		    if(TCL_OK != Tcl_VarEval(interp,argv[2], retval, 0))
			return TCL_ERROR;

		} else {
		    /* We have an error... Probably an end of mib. */
		    Tcl_SetResult(interp, "{End_Of_Mib}", TCL_VOLATILE);
		    return TCL_OK;
		}
	    } else {
		/* We might have a timeout */
		if (cd2->status == STAT_TIMEOUT) {
		    Tcl_SetResult(interp, "{Timeout}", TCL_VOLATILE);
		    return TCL_OK;
		    /* We timed out */
		} else {
		    Tcl_SetResult(interp, "{Error}", TCL_VOLATILE);
		    return TCL_OK;
		    /* Something else bad happened. */
		}
	    }
	}
    }
    Tcl_SetResult(interp, "{Success}", TCL_VOLATILE);
    return TCL_OK;
}

static int SnmpBulk(interp,argc,argv,cd2)
    Tcl_Interp  *interp;
    int argc;
    char **argv;
    t_cldat2 *cd2;
{

#define WIDTH  50
    
    oid rname[WIDTH][MAX_NAME_LEN];
    int rname_length[WIDTH];
    oid oname[WIDTH][MAX_NAME_LEN];
    int oname_length[WIDTH];
    int dead[WIDTH];
    int finished = 0;

    int depth = 0;
    int width = 0;
    int z;

    char *retval;

    char *responses[100];

    struct variable_list *vars, *start;

    int i,j;

    int tlen = 0;

    int nvars;
    int nresp;

    bzero((char *) dead, sizeof(dead));

    
    if((j = ParseOid(interp,argv[1],cd2,GETNEXT_REQ_MSG,&i)) != TCL_OK)
	return j;

    nvars = i;
    i = 0;
    for (vars = cd2->pdu->variables; vars; vars = vars->next_variable) {
	/* Copy all the names/lengths out... */
	OidCpy(&(oname[i][0]), &oname_length[i], vars->name, &vars->name_length);
	OidCpy(&(rname[i][0]), &rname_length[i], vars->name, &vars->name_length);
	i++;
    }

    /* Let's nuke that pdu ParseOid created: I'd rather make my own. */

    snmp_free_pdu(cd2->pdu);
    cd2->pdu = NULL;


    /* At this point, oname and rname contain the oids/lengths to request. */
    while (!finished) {
	/* For all the threads not dead... We'll request a packet. */
	finished = 1;
	cd2->pdu = NULL;
	width = 0;
	for (i = 0; i < nvars; i++) {
	    if (!dead[i]) {
		if (!cd2->pdu) {
		    finished = 0;
		    cd2->pdu = snmp_pdu_create(BULK_REQ_MSG);
		    cd2->pdu->non_repeaters = 0;
		    cd2->pdu->max_repetitions = 1000;
		}
		width++;
		snmp_add_null_var(cd2->pdu, rname[i], rname_length[i]);
	    }
	}
	if (!finished) {
	    cd2->status = snmp_synch_response(cd2->sess, cd2->pdu, &cd2->response);
	    if (cd2->status == STAT_SUCCESS) {
		if (cd2->response->errstat == SNMP_ERR_NOERROR) {
		    /* We got a successful packet...
		     * I'm going to copy the response parsing code from get.
		     * The name stuff is my own, though.
		     *
		     * For bulk: I'm going to count the # response packets.
		     */
		    z = 0;
		    for (vars = cd2->response->variables; vars; vars = vars->next_variable, z++);
		    
		    /* z has the # elements returned... 
		     * divide z/width to get depth..
		     */
		    
		    depth = z / width;

		    /* We want to pass through all this stuff "depth" times...
		     */
		    
		    
		    vars = cd2->response->variables;
		    start = vars;
		    for (z = 0; z < depth && !finished; z++) {
			finished = 1;
			start = vars;
			for (i = 0; i < nvars; i++) {
			    if (!dead[i] || dead[i] == 1) {
				/* If we made a request, read the response. */
				OidCpy(&(rname[i][0]), &rname_length[i], vars->name, &vars->name_length);
				
				/* Check the result value. 
				 * We need to see if we need to stop.
				 */
				
				if (rname_length[i] < oname_length[i] || bcmp(oname[i], rname[i], oname_length[i] * sizeof(oid))) {
				    /* This is no longer a part of the subtree... */
				    dead[i] = 1;
				} else {
				    /* At least one valid response... */
				    finished = 0;
				}
				vars = vars->next_variable;
			    }
			}
			/* Now, we want to parse ONLY those values that are alive...
			 * remembering that some of the resoponses just died.
			 * This introduces two "dead" states: state
			 * 1 = Just died; it exists in this packet.
			 * 2 = Long dead; it does not exist in this packet.
			 */
			nresp = 0;
			vars = start;
			/* Note that this creates a complete response set, filling in blanks. */
			for (i = 0; i < nvars; i++) {
			    if (!dead[i] || dead[i] == 1) {
				/* We have to do this one...
				 * I'm taking this stuff all from snmpget, now. 
				 */
				if (dead[i] == 1) {
				    responses[i] = "{done}";
				} else {
				    responses[i] = Raw_Value(vars);
				}
				vars = vars->next_variable;
				nresp++;
			    } else {
				responses[i] = "{done}";
			    }
			}
			start = vars;
			tlen = 0;
			for (i = 0; i < nvars; i++) {
			    tlen += strlen(responses[i]);
			}
			retval = (char *) malloc(tlen + nresp * 2 + 5);
			retval[0] = 0;
			for (i = 0; i < nvars; i++) {
			    j = strlen(retval);
			    sprintf(&retval[j], " %s ", responses[i]);
			}
			
			if(TCL_OK != Tcl_VarEval(interp,argv[2], retval, 0))
			    return TCL_ERROR;
		    }
		    for (i = 0; i < nvars; i++) {
			if (dead[i] == 1) { 
			    dead[i] = 2;
			}
		    }
		} else {
		    /* We have an error... Probably an end of mib. */
		    Tcl_SetResult(interp, "{End_Of_Mib}", TCL_VOLATILE);
		    return TCL_OK;
		}
	    } else {
		/* We might have a timeout */
		if (cd2->status == STAT_TIMEOUT) {
		    Tcl_SetResult(interp, "{Timeout}", TCL_VOLATILE);
		    return TCL_OK;
		    /* We timed out */
		} else {
		    Tcl_SetResult(interp, "{Error}", TCL_VOLATILE);
		    return TCL_OK;
		    /* Something else bad happened. */
		}
	    }
	}
    }
    Tcl_SetResult(interp, "{Success}", TCL_VOLATILE);
    return TCL_OK;
}


static int
    SnmpGetTable(interp,argc,argv,cd2)
Tcl_Interp  *interp;
int argc;
char **argv;
t_cldat2 *cd2;
{
    oid rname[MAX_NAME_LEN];
    int rname_length;
    int i,j;
    
    if((j = ParseOid(interp,argv[1],cd2,GETNEXT_REQ_MSG,&i)) != TCL_OK)
	return j;
    OidCpy(rname,&rname_length,
	   cd2->pdu->variables->name,&cd2->pdu->variables->name_length);
    
    for(;;)
	{
	    if(cd2->response)
		snmp_free_pdu(cd2->response);
	    cd2->response=0;
	    cd2->status = snmp_synch_response(cd2->sess,cd2->pdu,&cd2->response);
	    if(cd2->response->errstat == SNMP_ERR_NOSUCHNAME)
		return TCL_OK;
	    if(cd2->response->variables->name_length >= rname_length)
		if(OidCmp(rname, cd2->response->variables->name, rname_length))
		    return TCL_OK;
	    if(TCL_OK != Tcl_VarEval(interp,argv[2],0))
		return TCL_ERROR;
	    if((j = NextOid(interp,cd2,GETNEXT_REQ_MSG,&i)) != TCL_OK)
		return j;
	}
}


static int
    SnmpClose(interp,argc,argv,cd2)
Tcl_Interp  *interp;
int argc;
char **argv;
t_cldat2 *cd2;
{
    if(cd2->response)
	snmp_free_pdu(cd2->response);
    cd2->response=0;
    ckfree(cd2->sess);
    Tcl_DeleteCommand(interp,cd2->name);
    ckfree(cd2);
    return TCL_OK;
}

static int
    SnmpOid(interp,argc,argv,cd2)
Tcl_Interp  *interp;
int argc;
char **argv;
t_cldat2 *cd2;
{
    struct variable_list *vars;
    int i;
    char buf[8192];
    
    i = 0;
    /* process options here */
    if(argc > 1)
	i = atoi(argv[1]);
    for(vars=cd2->response->variables;vars;vars=vars->next_variable)
	if(!i--)
	    break;
    if(!vars)
	return TCL_ERROR;
    *buf = 0;
    for(i=0;i<vars->name_length;i++)
	sprintf(buf+strlen(buf)," %d",vars->name[i]);
    Tcl_SetResult(interp,buf+1,TCL_VOLATILE);
    return TCL_OK;
}

static int
    SnmpPrettyOid(interp,argc,argv,cd2)
Tcl_Interp  *interp;
int argc;
char **argv;
t_cldat2 *cd2;
{
    struct variable_list *vars;
    int i;
    char buf[8192];
    
    i = 0;
    /* process options here */
    if(argc > 1)
	i = atoi(argv[1]);
    for(vars=cd2->response->variables;vars;vars=vars->next_variable)
	if(!i--)
	    break;
    if(!vars)
	return TCL_ERROR;
    *buf = 0;
    sprint_objid(buf, vars->name, vars->name_length);
    Tcl_SetResult(interp,buf,TCL_VOLATILE);
    return TCL_OK;
}

static int
    SnmpVal(interp,argc,argv,cd2)
Tcl_Interp  *interp;
int argc;
char **argv;
t_cldat2 *cd2;
{
    struct variable_list *vars;
    int i;
    
    i = 0;
    /* process options here */
    if(argc > 1)
	i = atoi(argv[1]);
    for(vars=cd2->response->variables;vars;vars=vars->next_variable)
	if(!i--)
	    break;
    if(!vars)
	return TCL_ERROR;
    Tcl_SetResult(interp,VarVal(vars),TCL_VOLATILE);
    return TCL_OK;
}


snmp_usage(){
    fprintf(stderr, "Usage: open snmp sess-name -v 1 hostname community      or:\n");
    fprintf(stderr, "Usage: open snmp sess-name [-v 2 ] hostname noAuth      or:\n");
    fprintf(stderr, "Usage: open snmp sess-name [-v 2 ] hostname srcParty dstParty context\n");
}


static int
    SnmpProc(cd,interp,argc,argv)
t_cldat *cd;
Tcl_Interp  *interp;
int argc;
char **argv;
{
    /* Variables from snmpwalk.c for parsing*/
    struct snmp_pdu *pdu, *response;
    struct variable_list *vars;
    int arg;
    char *hostname = NULL;
    char *community = NULL;
    int gotroot = 0, version = 2;
    oid name[MAX_NAME_LEN];
    int name_length;
    oid root[MAX_NAME_LEN];
    int rootlen, count;
    int running;
    int status;
    int port_flag = 0;
    int dest_port = 0;
    oid src[MAX_NAME_LEN], dst[MAX_NAME_LEN], context[MAX_NAME_LEN];
    int srclen = 0, dstlen = 0, contextlen = 0;
    u_long      srcclock, dstclock;
    int clock_flag = 0;
    struct partyEntry *pp;
    struct contextEntry *cxp;
    int trivialSNMPv2 = FALSE;
    struct hostent *hp;
    u_long destAddr;
    char result[1000];
    /* End of snmmpwalk.c vars for parsing*/
    
    int exit_flag=FALSE;
    int sess_num = 0;
    int i;    
    t_cldat2 *cd2;
    
    if(cd->debug)
	{
	    fprintf(stderr,"[SNMP]: SnmpProc %d ",argc);
	    for(i=0;i<argc;i++)
		fprintf(stderr,"{%s} ",argv[i]);
	    fprintf(stderr,"\n");
	}
    
    strcpy(cd->where,"[SNMP] ");
    strcat(cd->where,argv[0]);
    argc--; argv++;
    if(argc < 2){
	return Error(interp,cd->where,"no args.");
    }
    strcat(cd->where," ");
    strcat(cd->where,argv[0]);

    IFW("tran") {
	CHKNARG(2, 2, cd->where);
	name_length = MAX_NAME_LEN;
	if (!read_objid(argv[1], name, &name_length)) {
	    /* Error */
	    Tcl_SetResult(interp, "{Invalid_Oid}", TCL_VOLATILE);
	} else {
	    /* Not error */
	    bzero((char *) result, sizeof(result));
	    sprint_objid(result, name, name_length);
	    Tcl_SetResult(interp, result, TCL_VOLATILE);
	}
    }	

    IFW("open")
	/*
	 * snmpwalk -v 1 hostname community
	 * snmpwalk [-v 2 ] hostname noAuth
	 * snmpwalk [-v 2 ] hostname srcParty dstParty context
	 */

	{
	    /*    CHKNARG(3,4,cd->where); */
	    /* Snmpwalk parsing code */
	    for(arg = 1; arg < argc; arg++){
		if (argv[arg][0] == '-'){
		    switch(argv[arg][1]){
			case 'd': {
			    snmp_dump_packet++;
			    break;
			}
			case 'p':{
			    port_flag++;
			    dest_port = atoi(argv[++arg]);
			    break;
			}
			case 'c':{
			    clock_flag++;
			    srcclock = atoi(argv[++arg]);
			    dstclock = atoi(argv[++arg]);
			    break;
			}
			case 'v':{
			    version = atoi(argv[++arg]);
			    break;
			}
			default:{
			    printf("invalid option: -%c\n", argv[arg][1]);
			    break;
			}
		    }
		    continue;
		}
		if (sess_num == 0){
		    sess_num = arg;
		} else if (hostname == NULL){
		    hostname = argv[arg];
		} else if (version == 1 && community == NULL){
		    community = argv[arg];
		} else if (version == 2 && srclen == 0 && !trivialSNMPv2){
		    if (read_party_database("/etc/party.conf") > 0){
			fprintf(stderr,
				"Couldn't read party database from /etc/party.conf\n");
			exit_flag=1;
		    }
		    if (read_context_database("/etc/context.conf") > 0){
			fprintf(stderr,
				"Couldn't read context database from /etc/context.conf\n");
			exit_flag=1;
		    }
		    if (read_acl_database("/etc/acl.conf") > 0){
			fprintf(stderr,"Couldn't read access control database from /etc/acl.conf\n");
			exit_flag=1;
		    }
		    if (!strcasecmp(argv[arg], "noauth")){
			trivialSNMPv2 = TRUE;
		    } else {
			party_scanInit();
			for(pp = party_scanNext(); pp; pp = party_scanNext()){
			    if (!strcasecmp(pp->partyName, argv[arg])){
				srclen = pp->partyIdentityLen;
				bcopy(pp->partyIdentity, src,
				      srclen * sizeof(oid));
				break;
			    }
			}
			if (!pp){
			    srclen = MAX_NAME_LEN;
			    if (!read_objid(argv[arg], src, &srclen)){
				printf("Invalid source party: %s\n",
				       argv[arg]);
				srclen = 0;
				snmp_usage();
				exit_flag=1;
			    }
			}
		    }
		} else if (version == 2 && dstlen == 0 && !trivialSNMPv2){
		    dstlen = MAX_NAME_LEN;
		    party_scanInit();
		    for(pp = party_scanNext(); pp; pp = party_scanNext()){
			if (!strcasecmp(pp->partyName, argv[arg])){
			    dstlen = pp->partyIdentityLen;
			    bcopy(pp->partyIdentity, dst, dstlen * sizeof(oid));
			    break;
			}
		    }
		    if (!pp){
			if (!read_objid(argv[arg], dst, &dstlen)){
			    printf("Invalid destination party: %s\n", argv[arg]);
			    dstlen = 0;
			    snmp_usage();
			    exit_flag=1;
			}
		    }
		} else if (version == 2 && contextlen == 0 && !trivialSNMPv2){
		    contextlen = MAX_NAME_LEN;
		    context_scanInit();
		    for(cxp = context_scanNext(); cxp;
			cxp = context_scanNext()){
			if (!strcasecmp(cxp->contextName, argv[arg])){
			    contextlen = cxp->contextIdentityLen;
			    bcopy(cxp->contextIdentity, context,
				  contextlen * sizeof(oid));
			    break;
			}
		    }
		    if (!cxp){
			if (!read_objid(argv[arg], context, &contextlen)){
			    printf("Invalid context: %s\n", argv[arg]);
			    contextlen = 0;
			    snmp_usage();
			    exit_flag = 1;
			}
		    }
		}
	    }
	    
	    if (!hostname || (version < 1) || (version > 2)
		|| (version == 1 && !community)
		|| (version == 2 && (!srclen || !dstlen || !contextlen)
		    && !trivialSNMPv2)){
		snmp_usage();
		exit_flag=1;
	    }
	    
	    if (trivialSNMPv2){
		if ((destAddr = inet_addr(hostname)) == -1){
		    hp = gethostbyname(hostname);
		    if (hp == NULL){
			fprintf(stderr, "unknown host: %s\n", hostname);
			exit(1);
		    } else {
			bcopy((char *)hp->h_addr, (char *)&destAddr,
			      hp->h_length);
		    }
		}
		srclen = dstlen = contextlen = MAX_NAME_LEN;
		ms_party_init(destAddr, src, &srclen, dst, &dstlen,
			      context, &contextlen);
	    }

	    if (clock_flag){
		pp = party_getEntry(src, srclen);
		if (pp){
		    pp->partyAuthClock = srcclock;
		    gettimeofday(&pp->tv, (struct timezone *)0);
		    pp->tv.tv_sec -= pp->partyAuthClock;
		}
		pp = party_getEntry(dst, dstlen);
		if (pp){
		    pp->partyAuthClock = dstclock;
		    gettimeofday(&pp->tv, (struct timezone *)0);
		    pp->tv.tv_sec -= pp->partyAuthClock;
		}
	    }
	    
	    if(!exit_flag) {
		cd2 = (t_cldat2 *)ckalloc(sizeof *cd2);
		memset((void*)cd2,0,sizeof *cd2);
		cd2->cd=cd;
		cd2->sess = &cd2->ss;
		cd2->sess->peername = hostname;
		cd2->sess->timeout = 3000000;
		if (version == 1){
		    cd2->sess->version = SNMP_VERSION_1;
		    cd2->sess->community = (u_char *)community;
		    cd2->sess->community_len = strlen((char *)community);
		} else if (version ==2){
		    cd2->sess->version = SNMP_VERSION_2;
		    cd2->sess->srcParty = src;
		    cd2->sess->srcPartyLen = srclen;
		    cd2->sess->dstParty = dst;
		    cd2->sess->dstPartyLen = dstlen;
		    cd2->sess->context = context;
		    cd2->sess->contextLen = contextlen;
		}
		cd2->sess->retries = 4;
		cd2->sess->timeout = 500000;
		cd2->sess->authenticator = NULL;
		snmp_synch_setup(cd2->sess);
		cd2->sess = snmp_open(cd2->sess);
		if(!cd2->sess)
		    return Failed(interp,cd->where,"snmp_open");
		Tcl_CreateCommand(interp,argv[sess_num],SessProc,cd2,0);
		strcpy(cd2->name,argv[sess_num]);
		return TCL_OK;
	    } else{
		return Error(interp, cd->where, "no args");
	    }
	}

    return HUH(interp,cd->where);
}



static int
    SessProc(cd2,interp,argc,argv)
t_cldat2 *cd2;
Tcl_Interp  *interp;
int argc;
char **argv;
{
    int i;
    
    if(cd2->cd->debug)
	{
	    fprintf(stderr,"[SNMP]: SessProc %d ",argc);
	    for(i=0;i<argc;i++)
		fprintf(stderr,"{%s} ",argv[i]);
	    fprintf(stderr,"\n");
	}
    
    strcpy(cd2->where,"[SNMP] ");
    strcat(cd2->where,argv[0]);
    if(argc < 2)	
return Error(interp,cd2->where,"no args.");
    argc--; argv++;
    strcat(cd2->where," ");
    strcat(cd2->where,argv[0]);
    
    IFW("get")
	/*XX <sess> get {<oid>|<loid>}*/
	{
	    CHKNARG(2,2,cd2->where);
	    return SnmpGet(interp,argc,argv,cd2);
	}
    IFW("getnext")
	/*XX <sess> get {<oid>|<loid>}*/
	{
	    CHKNARG(2,2,cd2->where);
	    return SnmpGetNext(interp,argc,argv,cd2);
	}
    IFW("set")
	/*XX <sess> set {<oid>|<loid>}*/
	{
	    CHKNARG(2,2,cd2->where);
	    return SnmpSet(interp,argc,argv,cd2);
	}
    IFW("gettable")
	/*XX <sess> gettable {<oid>|<loid>} <proc> */
	{
	    CHKNARG(3,3,cd2->where);
	    return SnmpGetTable(interp,argc,argv,cd2);
	}
    IFW("walk")
	/*XX <sess> gettable {<oid>|<loid>} <proc> */
	{
	    CHKNARG(3,3,cd2->where);
	    return SnmpWalk(interp,argc,argv,cd2);
	}
    IFW("bulk")
	/*XX <sess> gettable {<oid>|<loid>} <proc> */
	{
	    CHKNARG(3,3,cd2->where);
	    return SnmpBulk(interp,argc,argv,cd2);
	}
    IFW("val")
	/*XX <sess> val [index] */
	{
	    CHKNARG(1,2,cd2->where);
	    return SnmpVal(interp,argc,argv,cd2);
	}
    IFW("oid")
	/*XX <sess> oid [index] */
	{
	    CHKNARG(1,2,cd2->where);
	    return SnmpOid(interp,argc,argv,cd2);
	}
    IFW("prettyoid")
	/*XX <sess> prettyoid [index] */
	{
	    CHKNARG(1,2,cd2->where);
	    return SnmpPrettyOid(interp,argc,argv,cd2);
	}
    IFW("close")
	/*XX <sess> close */
	{
	    CHKNARG(1,1,cd2->where);
	    return SnmpClose(interp,argc,argv,cd2);
	}
    
    IFW("retries")
	/*XX <sess> retries  [num] */
	{
	    CHKNARG(2, 2, cd2->where);
	    cd2->sess->retries = atoi(argv[2]);
	    printf("SNMP retries set to %d.\n",  cd2->sess->retries);
	    return 0;
	}
    
    IFW("timeout")
	/*XX <sess> timeout  [num] */
	{
	    CHKNARG(2, 2, cd2->where);
	    cd2->sess->timeout = atoi(argv[2]);
	    printf("SNMP timeout set to %d uS.\n",  cd2->sess->timeout);
	    return 0;
	}
    
    return HUH(interp,cd2->where);
}
