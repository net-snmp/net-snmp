/*
 * binary_array.h
 * $Id$
 */

#ifndef BINARY_ARRAY_H
#define BINARY_ARRAY_H

#ifdef __cplusplus
extern          "C" {
#endif

#include <net-snmp/library/asn1.h>
#include <net-snmp/library/container.h>
#include <net-snmp/library/factory.h>

    /*
     * get an container which uses an binary_array for storage
     */
    netsnmp_container *   netsnmp_container_get_binary_array(void);
    int netsnmp_container_get_binary_array_noalloc(netsnmp_container *c);

    /*
     * get a factory for producing binary_array objects
     */
    netsnmp_factory *     netsnmp_container_get_binary_array_factory(void);

#ifdef __cplusplus
}
#endif
#endif
