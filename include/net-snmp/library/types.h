#ifndef NET_SNMP_LIBRARY_TYPES_H
#define NET_SNMP_LIBRARY_TYPES_H

#ifndef NET_SNMP_CONFIG_H
#error "Please include <net-snmp/net-snmp-config.h> before this file"
#endif


#include <net-snmp/types.h>

#ifdef __cplusplus
extern          "C" {
#endif

    typedef struct netsnmp_index_s {
       size_t      len;
       oid         *oids;
    } netsnmp_index;


    typedef struct netsnmp_void_array_s {
       size_t  size;
       void * *array;
    } netsnmp_void_array;

    /*
     * references to various types
     */
    typedef struct netsnmp_ref_void {
       void * val;
    } netsnmp_ref_void;

    typedef union {
        u_long  ul;
        u_int   ui;
        u_short us;
        u_char  uc;
        long    sl;
        int     si;
        short   ss;
        char    sc;
        char *  cp;
        void *  vp;
    } netsnmp_cvalue;

    typedef struct netsnmp_ref_size_t_s {
       size_t val;
    } * netsnmp_ref_size_t;



/**
 * Structure for holding a set of file descriptors, similar to fd_set.
 *
 * This structure however can hold so-called large file descriptors
 * (>= FD_SETSIZE or 1024) on Unix systems or more than FD_SETSIZE (64)
 * sockets on Windows systems.
 *
 * It is safe to allocate this structure on the stack.
 *
 * This structure must be initialized by calling netsnmp_large_fd_set_init()
 * and must be cleaned up via netsnmp_large_fd_set_cleanup(). If this last
 * function is not called this may result in a memory leak.
 */
typedef struct netsnmp_large_fd_set_s {
    /** Maximum set size. */
    unsigned        lfs_setsize;
    /**
     * Points to lfs_set if lfs_setsize <= FD_SETSIZE, and otherwise
     * to dynamically allocated memory.
     */
    fd_set         *lfs_setptr;
    /** File descriptor / socket set data if lfs_setsize <= FD_SETSIZE. */
    fd_set          lfs_set;
} netsnmp_large_fd_set;
#ifdef __cplusplus
}
#endif

#endif                          /* NET_SNMP_LIBRARY_TYPES_H */
