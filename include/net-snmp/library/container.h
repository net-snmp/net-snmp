#ifndef NETSNMP_CONTAINER_H
#define NETSNMP_CONTAINER_H

/*
 * WARNING: This is a recently created file, and all of it's contents are
 *          subject to change at any time.
 *
 * A basic container template. A generic way for code to store and
 * retrieve data. Allows for interchangable storage algorithms.
 */

#ifdef  __cplusplus
extern "C" {
#endif
    
    struct netsnmp_container_s; /** forward declare */
    
    typedef int (netsnmp_container_op)(struct netsnmp_container_s *,
                                       void *data);
    typedef void * (netsnmp_container_rtn)(struct netsnmp_container_s *,
                                           void *data);
    typedef int (netsnmp_container_compare)(const void *lhs,
                                            const void *rhs);

    /*
     * basic container structure
     */
    typedef struct netsnmp_container_s {
       
       /*
        * pointer for container
        */
       void *         private;
       
       /*
        * methods to manipulate container
        */
       netsnmp_container_op    *insert_data;
       netsnmp_container_op    *remove_data;
       netsnmp_container_rtn   *find_data;
       
    } netsnmp_container;
    
    
#ifdef  __cplusplus
};
#endif

#endif /** NETSNMP_CONTAINER_H */
