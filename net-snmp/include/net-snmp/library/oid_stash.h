#ifndef OID_STASH_H
#define OID_STASH_H

/* designed to store/retrieve information associated with a given oid.
 * Storage is done in an efficient manner for fast lookups.
 */

#define OID_STASH_CHILDREN_SIZE 31

#ifdef __cplusplus
extern          "C" {
#endif

typedef struct oid_stash_node_s {
   oid value;
   struct oid_stash_node_s **children; /* array of children */
   size_t children_size;
   struct oid_stash_node_s *next_sibling; /* cache too small links */
   struct oid_stash_node_s *prev_sibling;
   /* struct oid_stash_node_s *parent; */ /* XXX? */

   void *thedata;
} oid_stash_node;

int oid_stash_add_data(oid_stash_node **root,
                       oid *lookup, size_t lookup_len, void *mydata);
oid_stash_node *oid_stash_get_node(oid_stash_node *root,
                                   oid *lookup, size_t lookup_len);
void *oid_stash_get_data(oid_stash_node *root,
                         oid *lookup, size_t lookup_len);

oid_stash_node *oid_stash_create_sized_node(size_t mysize);
oid_stash_node *oid_stash_create_node(void); /* returns a malloced node */


#ifdef __cplusplus
}
#endif
#endif /* OID_STASH_H */
