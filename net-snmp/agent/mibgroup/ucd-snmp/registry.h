/*
 *  registry:  displays a list of all loaded mib modules.
 *
 */
#ifndef _MIBGROUP_REGISTRY_H
#define _MIBGROUP_REGISTRY_H

void init_registry(void);

extern FindVarMethod var_registry;

#define	REGISTRYINDEX		1
#define	REGISTRYNAME		2

#endif /* _MIBGROUP_REGISTRY_H */
