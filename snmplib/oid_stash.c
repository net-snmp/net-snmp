#include <net-snmp/net-snmp-config.h>

#include <string.h>

#include <stdlib.h>
#include <sys/types.h>
#include <asn1.h>
#include <snmp_impl.h>
#include <snmp.h>
#include <snmp_api.h>
#include <tools.h>
#include <oid_stash.h>

oid_stash_node *
oid_stash_create_sized_node(size_t mysize) 
{
    oid_stash_node *ret;
    ret = SNMP_MALLOC_TYPEDEF(oid_stash_node);
    if (!ret)
        return NULL;
    ret->children = calloc(mysize, sizeof(oid_stash_node *));
    if (!ret->children) {
        free(ret);
        return NULL;
    }
    ret->children_size = mysize;
    return ret;
}

inline
oid_stash_node *
oid_stash_create_node(void) 
{
    return oid_stash_create_sized_node(OID_STASH_CHILDREN_SIZE);
}

/** adds data to the stash at a given oid.
 * returns SNMPERR_SUCCESS on success.
 * returns SNMPERR_GENERR if data is already there.
 * returns SNMPERR_MALLOC on malloc failures or if arguments passed in
 *   with NULL values.
 */
int
oid_stash_add_data(oid_stash_node **root,
                   oid *lookup, size_t lookup_len, void *mydata) 
{
    oid_stash_node *curnode, *tmpp, *loopp;
    int i;

    if (!root || !lookup || lookup_len == 0)
        return SNMPERR_GENERR;
    
    if (!*root)
        *root = oid_stash_create_node();
    if (!*root)
        return SNMPERR_MALLOC;
    for(curnode = *root, i = 0; i < lookup_len; i++) {
        tmpp = curnode->children[lookup[i] % curnode->children_size];
        if (!tmpp) {
            /* node child in array at all */
            tmpp = curnode->children[lookup[i] % curnode->children_size] =
                oid_stash_create_node();
            tmpp->value = lookup[i];
        } else {
            for(loopp = tmpp; loopp; loopp = loopp->next_sibling) {
                if (loopp->value == lookup[i])
                    break;
            }
            if (loopp) {
                tmpp = loopp;
            } else {
                /* none exists.  Create it */
                loopp = oid_stash_create_node();
                loopp->value = lookup[i];
                loopp->next_sibling = tmpp;
                tmpp->prev_sibling = loopp;
                curnode->children[lookup[i] % curnode->children_size] = loopp;
                tmpp = loopp;
            }
            /* tmpp now points to the proper node */
        }
        curnode = tmpp;
    }
    /* tmpp now points to the exact match */
    if (curnode->thedata)
        return SNMPERR_GENERR;
    tmpp->thedata = mydata;
    return SNMPERR_SUCCESS;
}

/** returns a node associated with a given OID.
 */
oid_stash_node *
oid_stash_get_node(oid_stash_node *root,
                   oid *lookup, size_t lookup_len) 
{
    oid_stash_node *curnode, *tmpp, *loopp;
    int i;
    
    if (!root)
        return NULL;
    for(curnode = root, i = 0; i < lookup_len; i++) {
        tmpp = curnode->children[lookup[i] % curnode->children_size];
        if (!tmpp) {
            return NULL;
        } else {
            for(loopp = tmpp; loopp; loopp = loopp->next_sibling) {
                if (loopp->value == lookup[i])
                    break;
            }
            if (loopp) {
                tmpp = loopp;
            } else {
                return NULL;
            }
        }
        curnode = tmpp;
    }
    return tmpp;
}

/** returns a data pointer associated with a given OID.
 */
void *
oid_stash_get_data(oid_stash_node *root,
                   oid *lookup, size_t lookup_len) 
{
    oid_stash_node *ret;
    ret = oid_stash_get_node(root, lookup, lookup_len);
    if (ret) 
        return ret->thedata;
    return NULL;
}

void
oid_stash_dump(oid_stash_node *root, char *prefix) 
{
    char myprefix[MAX_OID_LEN * 4];
    oid_stash_node *tmpp;
    int prefix_len = strlen(prefix) + 1; /* actually it's +2 */
    int i;
    
    memset(myprefix, ' ', MAX_OID_LEN * 4);
    myprefix[prefix_len] = '\0';

    for(i = 0; i < root->children_size; i++) {
        if (root->children[i]) {
            for(tmpp = root->children[i]; tmpp; tmpp = tmpp->next_sibling) {
                printf("%s%ld@%d:\n", prefix, tmpp->value, i);
                oid_stash_dump(tmpp, myprefix);
            }
        }
    }
}

