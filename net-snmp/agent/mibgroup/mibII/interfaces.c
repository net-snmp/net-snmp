/*
 *  Interfaces MIB group implementation - interfaces.c
 *
 */

/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/*
 * Portions of this file are copyrighted by:
 * Copyright © 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */

#include <net-snmp/net-snmp-config.h>
#include "interfaces_includes.h"

static void     parse_interface_config(const char *, char *);
static void     free_interface_config(void);

struct variable3 interfaces_variables[] = {
    {IFNUMBER, ASN_INTEGER, RONLY, var_interfaces, 1, {1}},
    {IFINDEX, ASN_INTEGER, RONLY, var_ifEntry, 3, {2, 1, 1}},
    {IFDESCR, ASN_OCTET_STR, RONLY, var_ifEntry, 3, {2, 1, 2}},
    {IFTYPE, ASN_INTEGER, RONLY, var_ifEntry, 3, {2, 1, 3}},
    {IFMTU, ASN_INTEGER, RONLY, var_ifEntry, 3, {2, 1, 4}},
    {IFSPEED, ASN_GAUGE, RONLY, var_ifEntry, 3, {2, 1, 5}},
    {IFPHYSADDRESS, ASN_OCTET_STR, RONLY, var_ifEntry, 3, {2, 1, 6}},
#ifdef WIN32
    {IFADMINSTATUS, ASN_INTEGER, RWRITE, var_ifEntry, 3, {2, 1, 7}},
#else
    {IFADMINSTATUS, ASN_INTEGER, RONLY, var_ifEntry, 3, {2, 1, 7}},
#endif
    {IFOPERSTATUS, ASN_INTEGER, RONLY, var_ifEntry, 3, {2, 1, 8}},
    {IFLASTCHANGE, ASN_TIMETICKS, RONLY, var_ifEntry, 3, {2, 1, 9}},
    {IFINOCTETS, ASN_COUNTER, RONLY, var_ifEntry, 3, {2, 1, 10}},
    {IFINUCASTPKTS, ASN_COUNTER, RONLY, var_ifEntry, 3, {2, 1, 11}},
    {IFINNUCASTPKTS, ASN_COUNTER, RONLY, var_ifEntry, 3, {2, 1, 12}},
    {IFINDISCARDS, ASN_COUNTER, RONLY, var_ifEntry, 3, {2, 1, 13}},
    {IFINERRORS, ASN_COUNTER, RONLY, var_ifEntry, 3, {2, 1, 14}},
    {IFINUNKNOWNPROTOS, ASN_COUNTER, RONLY, var_ifEntry, 3, {2, 1, 15}},
    {IFOUTOCTETS, ASN_COUNTER, RONLY, var_ifEntry, 3, {2, 1, 16}},
    {IFOUTUCASTPKTS, ASN_COUNTER, RONLY, var_ifEntry, 3, {2, 1, 17}},
    {IFOUTNUCASTPKTS, ASN_COUNTER, RONLY, var_ifEntry, 3, {2, 1, 18}},
    {IFOUTDISCARDS, ASN_COUNTER, RONLY, var_ifEntry, 3, {2, 1, 19}},
    {IFOUTERRORS, ASN_COUNTER, RONLY, var_ifEntry, 3, {2, 1, 20}},
    {IFOUTQLEN, ASN_GAUGE, RONLY, var_ifEntry, 3, {2, 1, 21}},
    {IFSPECIFIC, ASN_OBJECT_ID, RONLY, var_ifEntry, 3, {2, 1, 22}}
};

/*
 * Define the OID pointer to the top of the mib tree that we're
 * registering underneath, and the OID of the MIB module 
 */
oid             interfaces_variables_oid[] = { SNMP_OID_MIB2, 2 };
oid             interfaces_module_oid[] = { SNMP_OID_MIB2, 31 };

void
init_interfaces(void)
{
    /*
     * register ourselves with the agent to handle our mib tree 
     */
    REGISTER_MIB("mibII/interfaces", interfaces_variables, variable3,
                 interfaces_variables_oid);
    REGISTER_SYSOR_ENTRY(interfaces_module_oid,
                         "The MIB module to describe generic objects for network interface sub-layers");

    snmpd_register_config_handler("interface", parse_interface_config,
                                  free_interface_config,
                                  "name type speed");

    Interface_Scan_Get_Count();
#ifndef USE_SYSCTL_IFLIST
#if HAVE_NET_IF_MIB_H
    init_interfaces_setup();
#endif
#endif
#ifdef solaris2
    init_kernel_sunos5();
#endif
}

static void
parse_interface_config(const char *token, char *cptr)
{
    conf_if_list   *if_ptr, *if_new;
    char           *name, *type, *speed, *ecp;

    name = strtok(cptr, " \t");
    if (!name) {
        config_perror("Missing NAME parameter");
        return;
    }
    type = strtok(NULL, " \t");
    if (!type) {
        config_perror("Missing TYPE parameter");
        return;
    }
    speed = strtok(NULL, " \t");
    if (!speed) {
        config_perror("Missing SPEED parameter");
        return;
    }
    if_ptr = conf_list;
    while (if_ptr)
        if (strcmp(if_ptr->name, name))
            if_ptr = if_ptr->next;
        else
            break;
    if (if_ptr)
        config_pwarn("Duplicate interface specification");
    if_new = (conf_if_list *) malloc(sizeof(conf_if_list));
    if (!if_new) {
        config_perror("Out of memory");
        return;
    }
    if_new->speed = strtoul(speed, &ecp, 0);
    if (*ecp) {
        config_perror("Bad SPEED value");
        free(if_new);
        return;
    }
    if_new->type = strtol(type, &ecp, 0);
    if (*ecp || if_new->type < 0) {
        config_perror("Bad TYPE");
        free(if_new);
        return;
    }
    if_new->name = strdup(name);
    if (!if_new->name) {
        config_perror("Out of memory");
        free(if_new);
        return;
    }
    if_new->next = conf_list;
    conf_list = if_new;
}

static void
free_interface_config(void)
{
    conf_if_list   *if_ptr = conf_list, *if_next;
    while (if_ptr) {
        if_next = if_ptr->next;
        free(if_ptr->name);
        free(if_ptr);
        if_ptr = if_next;
    }
    conf_list = NULL;
}



/*
 * header_ifEntry(...
 * Arguments:
 * vp     IN      - pointer to variable entry that points here
 * name    IN/OUT  - IN/name requested, OUT/name found
 * length  IN/OUT  - length of IN/OUT oid's 
 * exact   IN      - TRUE if an exact match was requested
 * var_len OUT     - length of variable or 0 if function returned
 * write_method
 * 
 */
