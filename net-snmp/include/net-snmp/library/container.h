#ifndef NETSNMP_CONTAINER_H
#define NETSNMP_CONTAINER_H

/*
 * WARNING: This is a recently created file, and all of it's contents are
 *          subject to change at any time.
 *
 * A basic container template. A generic way for code to store and
 * retrieve data. Allows for interchangable storage algorithms.
 */

#include <net-snmp/types.h>

#ifdef  __cplusplus
extern "C" {
#endif

    /*************************************************************************
     *
     * function pointer definitions
     *
     *************************************************************************/
    
    struct netsnmp_container_s; /** forward declare */
    
    typedef int (netsnmp_container_rc)(struct netsnmp_container_s *);
    typedef size_t (netsnmp_container_size)(struct netsnmp_container_s *);
    typedef int (netsnmp_container_op)(struct netsnmp_container_s *,
                                       void *data);
    typedef void * (netsnmp_container_rtn)(struct netsnmp_container_s *,
                                           void *data);
    typedef netsnmp_void_array * (netsnmp_container_set)
        (struct netsnmp_container_s *, void *data);
    typedef int (netsnmp_container_compare)(const void *lhs,
                                            const void *rhs);

    /*************************************************************************
     *
     * Basic container
     *
     *************************************************************************/
    typedef struct netsnmp_container_s {
       
       /*
        * pointer for container
        */
       void *         private;

       /*
        * returns the number of items in a container
        */
       netsnmp_container_size  *get_size;
       
       /*
        * initialize a container
        */
       netsnmp_container_rc    *init;

       /*
        * release memory used by a container.
        *
        * Note: if your data structures contained allcoated
        * memory, you are responsible for releasing that
        * memory before calling this function!
        */
       netsnmp_container_rc    *free;

       /*
        * add an entry to the container
        */
       netsnmp_container_op    *insert_data;

       /*
        * remove an entry from the container
        */
       netsnmp_container_op    *remove_data;

       /*
        * find the entry in the container with the same key
        *
        * Note: do not change the key!  If you need to
        * change a key, remove the entry, change the key,
        * and the re-add the entry.
        */
       netsnmp_container_rtn   *find_data;


       netsnmp_container_compare        *compare;
       
    } netsnmp_container;

    void
    netsnmp_init_container(netsnmp_container         *c,
                           netsnmp_container_rc      *init,
                           netsnmp_container_rc      *free,
                           netsnmp_container_size    *size,
                           netsnmp_container_compare *cmp,
                           netsnmp_container_op      *ins,
                           netsnmp_container_op      *rem,
                           netsnmp_container_rtn     *fnd);


    /*************************************************************************
     *
     * Sorted container
     *
     *************************************************************************/
    typedef struct netsnmp_sorted_container_s {
       
       netsnmp_container                bc;
       
       /*
        * methods to manipulate container
        */

       netsnmp_container_rtn            *first;
       netsnmp_container_rtn            *next;
       netsnmp_container_set            *subset;
       
    } netsnmp_sorted_container;
    

    void
    netsnmp_init_sorted_container(netsnmp_sorted_container  *sc,
                                  netsnmp_container_rtn     *first,
                                  netsnmp_container_rtn     *next,
                                  netsnmp_container_set     *subset);
    
    
    
#ifdef  __cplusplus
};
#endif

#endif /** NETSNMP_CONTAINER_H */
