#ifndef OID_STASH_H
#define OID_STASH_H

/*
 * designed to store/retrieve information associated with a given oid.
 * * Storage is done in an efficient manner for fast lookups.
 */

#define OID_STASH_CHILDREN_SIZE 31

#ifdef __cplusplus
extern          "C" {
#endif

    typedef struct netsnmp_oid_stash_node_s {
        oid             value;
        struct netsnmp_oid_stash_node_s **children;     /* array of children */
        size_t          children_size;
        struct netsnmp_oid_stash_node_s *next_sibling;  /* cache too small links */
        struct netsnmp_oid_stash_node_s *prev_sibling;
        /*
         * struct netsnmp_oid_stash_node_s *parent; 
 *//*
 * XXX? 
 */

        void           *thedata;
    } netsnmp_oid_stash_node;

    int             netsnmp_oid_stash_add_data(netsnmp_oid_stash_node
                                               **root, oid * lookup,
                                               size_t lookup_len,
                                               void *mydata);
    netsnmp_oid_stash_node
        *netsnmp_oid_stash_get_node(netsnmp_oid_stash_node *root,
                                    oid * lookup, size_t lookup_len);
    void           *netsnmp_oid_stash_get_data(netsnmp_oid_stash_node
                                               *root, oid * lookup,
                                               size_t lookup_len);

    netsnmp_oid_stash_node *netsnmp_oid_stash_create_sized_node(size_t
                                                                mysize);
    netsnmp_oid_stash_node *netsnmp_oid_stash_create_node(void);        /* returns a malloced node */


#ifdef __cplusplus
}
#endif
#endif                          /* OID_STASH_H */
