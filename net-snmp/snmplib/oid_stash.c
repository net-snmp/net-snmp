#include <net-snmp/net-snmp-config.h>

#include <string.h>

#include <stdlib.h>
#include <sys/types.h>

#include <net-snmp/types.h>
#include <net-snmp/utilities.h>

#include <net-snmp/library/snmp_api.h>
#include <net-snmp/library/oid_stash.h>

netsnmp_oid_stash_node *
netsnmp_oid_stash_create_sized_node(size_t mysize)
{
    netsnmp_oid_stash_node *ret;
    ret = SNMP_MALLOC_TYPEDEF(netsnmp_oid_stash_node);
    if (!ret)
        return NULL;
    ret->children = calloc(mysize, sizeof(netsnmp_oid_stash_node *));
    if (!ret->children) {
        free(ret);
        return NULL;
    }
    ret->children_size = mysize;
    return ret;
}

inline netsnmp_oid_stash_node *
netsnmp_oid_stash_create_node(void)
{
    return netsnmp_oid_stash_create_sized_node(OID_STASH_CHILDREN_SIZE);
}

/** adds data to the stash at a given oid.
 * returns SNMPERR_SUCCESS on success.
 * returns SNMPERR_GENERR if data is already there.
 * returns SNMPERR_MALLOC on malloc failures or if arguments passed in
 *   with NULL values.
 */
int
netsnmp_oid_stash_add_data(netsnmp_oid_stash_node **root,
                           oid * lookup, size_t lookup_len, void *mydata)
{
    netsnmp_oid_stash_node *curnode, *tmpp, *loopp;
    unsigned int    i;

    if (!root || !lookup || lookup_len == 0)
        return SNMPERR_GENERR;

    if (!*root)
        *root = netsnmp_oid_stash_create_node();
    if (!*root)
        return SNMPERR_MALLOC;
    for (curnode = *root, i = 0; i < lookup_len; i++) {
        tmpp = curnode->children[lookup[i] % curnode->children_size];
        if (!tmpp) {
            /*
             * node child in array at all 
             */
            tmpp = curnode->children[lookup[i] % curnode->children_size] =
                netsnmp_oid_stash_create_node();
            tmpp->value = lookup[i];
        } else {
            for (loopp = tmpp; loopp; loopp = loopp->next_sibling) {
                if (loopp->value == lookup[i])
                    break;
            }
            if (loopp) {
                tmpp = loopp;
            } else {
                /*
                 * none exists.  Create it 
                 */
                loopp = netsnmp_oid_stash_create_node();
                loopp->value = lookup[i];
                loopp->next_sibling = tmpp;
                tmpp->prev_sibling = loopp;
                curnode->children[lookup[i] % curnode->children_size] =
                    loopp;
                tmpp = loopp;
            }
            /*
             * tmpp now points to the proper node 
             */
        }
        curnode = tmpp;
    }
    /*
     * tmpp now points to the exact match 
     */
    if (curnode->thedata)
        return SNMPERR_GENERR;
    tmpp->thedata = mydata;
    return SNMPERR_SUCCESS;
}

/** returns a node associated with a given OID.
 */
netsnmp_oid_stash_node *
netsnmp_oid_stash_get_node(netsnmp_oid_stash_node *root,
                           oid * lookup, size_t lookup_len)
{
    netsnmp_oid_stash_node *curnode, *tmpp, *loopp;
    unsigned int    i;

    if (!root)
        return NULL;
    for (curnode = root, i = 0; i < lookup_len; i++) {
        tmpp = curnode->children[lookup[i] % curnode->children_size];
        if (!tmpp) {
            return NULL;
        } else {
            for (loopp = tmpp; loopp; loopp = loopp->next_sibling) {
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
void           *
netsnmp_oid_stash_get_data(netsnmp_oid_stash_node *root,
                           oid * lookup, size_t lookup_len)
{
    netsnmp_oid_stash_node *ret;
    ret = netsnmp_oid_stash_get_node(root, lookup, lookup_len);
    if (ret)
        return ret->thedata;
    return NULL;
}

void
oid_stash_dump(netsnmp_oid_stash_node *root, char *prefix)
{
    char            myprefix[MAX_OID_LEN * 4];
    netsnmp_oid_stash_node *tmpp;
    int             prefix_len = strlen(prefix) + 1;    /* actually it's +2 */
    unsigned int    i;

    memset(myprefix, ' ', MAX_OID_LEN * 4);
    myprefix[prefix_len] = '\0';

    for (i = 0; i < root->children_size; i++) {
        if (root->children[i]) {
            for (tmpp = root->children[i]; tmpp; tmpp = tmpp->next_sibling) {
                printf("%s%ld@%d:\n", prefix, tmpp->value, i);
                oid_stash_dump(tmpp, myprefix);
            }
        }
    }
}
