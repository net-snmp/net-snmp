/*
 *  registry:  displays a list of all loaded mib modules.
 *
 */

#include <config.h>
#include <sys/types.h>
#if STDC_HEADERS
#include <stdlib.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "mibincl.h"
#include "registry.h"
#include "../../../snmplib/system.h"

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

extern int subtree_size;
extern struct subtree *subtrees;

#define MATCH_FAILED	-1

void init_registry(void) 
{

  struct variable2 registry_variables[] = {
    { REGISTRYINDEX,  ASN_OBJECT_ID, RONLY, var_registry, 1, {1}},
    { REGISTRYNAME,   ASN_OCTET_STR, RONLY, var_registry, 1, {2}}
  };

  /* Define the OID pointer to the top of the mib tree that we're
   registering underneath */
  oid registry_variables_oid[] = { 1,3,6,1,4,1,2021,102,1 };

    /* register ourselves with the agent to handle our mib tree */
  REGISTER_MIB("ucd-snmp/registery", registry_variables, variable2, \
               registry_variables_oid);

}

static struct subtree *
header_registry(struct variable *vp,
		oid *name,
		int *length,
		int exact,
		int *var_len,
		WriteMethod **write_method)
{
#define REGISTRY_NAME_LENGTH	10
    oid newname[MAX_NAME_LEN];
    char c_oid[MAX_NAME_LEN];
    struct subtree *mine = NULL;
    
    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGMSGTL(("ucd-snmp/registry", "var_registry: %s\n", c_oid));
    }
    if (*length < REGISTRY_NAME_LENGTH ||
        snmp_oid_compare(name, *length, vp->name, vp->namelen) < 1)
      mine = subtrees;
    else
      mine = find_subtree_next(&(name[REGISTRY_NAME_LENGTH]),
                               *length-REGISTRY_NAME_LENGTH,
                               subtrees);

    if (mine != NULL) {
      memcpy( (char *)newname,(char *)vp->name, (int)vp->namelen * sizeof(oid));
      memcpy( (char *)name,(char *)newname,
              ((int)vp->namelen + 1) * sizeof(oid));
      memcpy((char *)(name+vp->namelen), (char *)mine->name,
            ((int)mine->namelen) * sizeof(oid));
      *length = vp->namelen + mine->namelen;
    }

    sprint_objid (c_oid, name, *length);
    return mine;
}


	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/

u_char	*
var_registry(struct variable *vp,
	     oid *name,
	     int *length,
	     int exact,
	     int *var_len,
	     WriteMethod **write_method)
{
  struct subtree *index;
    if ((index =
         header_registry(vp, name, length, exact, var_len, write_method))
        == NULL )
      return NULL;

    switch (vp->magic){
	case REGISTRYINDEX:
            *var_len = sizeof(oid)*(index->namelen);
            return (u_char *) index->name;
        case REGISTRYNAME:
            *var_len = strlen(index->label);
            return (u_char *) index->label;
        default:
            ERROR_MSG("");
    }
    return NULL;
}
