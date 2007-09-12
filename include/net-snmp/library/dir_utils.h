/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/*
 * Portions of this file are copyrighted by:
 * Copyright (C) 2007 Apple, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */
#ifndef NETSNMP_DIR_UTILS_H
#define NETSNMP_DIR_UTILS_H

#ifdef _cplusplus
extern "C" {
#endif

    /*------------------------------------------------------------------
     *
     * Prototypes
     */
    netsnmp_container * netsnmp_directory_container_read(netsnmp_container *c,
                                                         const char *dir,
                                                         u_int flags);
    void netsnmp_directory_container_free(netsnmp_container *c);

        

    /*------------------------------------------------------------------
     *
     * flags
     */
#define NETSNMP_DIR_RECURSE                           0x1

    
        
#ifdef _cplusplus
}
#endif

#endif /* NETSNMP_DIR_UTILS_H */
