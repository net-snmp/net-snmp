/*
 *  registry:  displays a list of all loaded mib modules.
 *
 */
#ifndef _MIBGROUP_REGISTRY_H
#define _MIBGROUP_REGISTRY_H

extern u_char	*var_registry __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));

#define	REGISTRYINDEX		1
#define	REGISTRYNAME		2
#define	REGISTRYOID		3

#ifdef IN_SNMP_VARS_C

struct variable2 registry_variables[] = {
    { REGISTRYINDEX,  ASN_OBJECT_ID, RONLY, var_registry, 1, {1}},
    { REGISTRYNAME,   ASN_OCTET_STR, RONLY, var_registry, 1, {2}}
};
config_load_mib(1.3.6.1.4.1.2021.102.1, 9, registry_variables)

#endif
#endif /* _MIBGROUP_REGISTRY_H */
