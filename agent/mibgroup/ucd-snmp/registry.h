/*
 *  registry:  displays a list of all loaded mib modules.
 *
 */
#ifndef _MIBGROUP_REGISTRY_H
#define _MIBGROUP_REGISTRY_H

extern u_char	*var_registry __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));

#define	REGISTRYINDEX		1
#define	REGISTRYNAME		2

#endif /* _MIBGROUP_REGISTRY_H */
