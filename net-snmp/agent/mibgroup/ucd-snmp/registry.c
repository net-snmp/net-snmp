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
static struct subtree *header_registry __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));

static struct subtree *
header_registry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
#define REGISTRY_NAME_LENGTH	10
    oid newname[MAX_NAME_LEN];
    char c_oid[MAX_NAME_LEN];
    struct subtree *mine = NULL;
    
    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP ("var_registry: %s\n", c_oid);
    }
    if (*length < REGISTRY_NAME_LENGTH ||
        compare(name, *length, vp->name, vp->namelen) < 1)
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
var_registry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
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
