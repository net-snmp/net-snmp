/*
 * oid_array.h
 * $Id$
 *
 * External definitions for functions and variables in oid_array.c.
 *
 * The basic idea is to keep an array of data items (or, more
 * likely, pointers to data items) sorted by their index oid.
 *
 * Inspired by agent/mibgroup/util_funcs.c
 *
 *
 * Note: These arrays are sorted lazily. Thus, some methods
 * have a sort parameter in case you don't care is the array
 * has been sorted since it was last changed.
 *
 *
 * EXAMPLE:
 * ------------------------------------------------------------
 * typedef struct my_row_s {
 *   oid_header index;
 *   int column_a;
 *   int column_b;
 * } my_row;
 *
 * oid_array my_table;
 * struct variable_list *var = NULL;
 * int idx1;
 *
 * my_table = Initialise_oid_array( sizeof(my_row*) );
 *
 * 
 * my_row* new_row = (my_row*)calloc(sizeof(my_row));
 * new_row->column_a = 10;
 * new_row->column_b = 20;
 * idx1 = 22;
 * snmp_varlist_add_variable(&var, NULL, 0, ASN_INTEGER,
 *                           &idx1, sizeof(idx1));
 * snmp_varlist_add_variable(&var, NULL, 0, ASN_OCTET_STR,
 *                           "skiddo", strln("skiddo"));
 * build_oid( &my_row->index.idx, &my_row->index.idx_len,
 *            NULL, 0, var);
 * Add_oid_data( my_table, new_row );
 *
 * ------------------------------------------------------------
 */

#ifndef OID_ARRAY_H
#define OID_ARRAY_H

#ifdef __cplusplus
extern          "C" {
#endif

#include "asn1.h"

    typedef void   *oid_array;

    /*
     * since I didn't want to re-write qsort and such, your data
     * structure must start with this header. (Ok, not really, but
     * the first two elements of your data structure better be a
     * pointer to the index oid and the lenght of the index!)
     */
    typedef struct oid_array_header_s {
        oid            *idx;
        int             idx_len;
    } oid_array_header;

    typedef struct oid_array_header_wrapper_s {
        oid            *idx;
        int             idx_len;
        void           *data;
    } oid_array_header_wrapper;

    typedef void    (ForEach) (oid_array_header *, void *context);

    /*
     * compare to entries. Nothing fancy, just a wrapper around
     * snmp_oid_compare.
     */
    int             array_compare(const void *lhs, const void *rhs);

    /*
     * initialise an oid array which will contain data.
     *
     * data_size  should be the size of each item
     */
    oid_array       Initialise_oid_array(int data_size);

    /*
     * add an entry to an array.
     *
     * returns 0 on success, -1 on failure
     */
    int             Add_oid_data(oid_array a, void *);

    /*
     * replace an entry to an array.
     *
     * returns 0 on success, -1 on failure
     */
    int             Replace_oid_data(oid_array a, void *key);

    /*
     * find the entry in the array with the same index
     *
     * Note: do not change the index!  If you need to
     * change an index, remove the entry, change the index,
     * and the re-add the entry.
     */
    void           *Get_oid_data(oid_array a, void *, int exact);

    /*
     * remove an entry
     *
     * if save is not null, the entry will be copied to the address
     * save points at.
     */
    int             Remove_oid_data(oid_array a, void *key, void *save);

    /*
     * release memory used by a table.
     *
     * Note: if your data structure contained allcoated
     * memory, you are responsible for releasing that
     * memory before calling this function!
     */
    void            Release_oid_array(oid_array a);

    /*
     * call a function for each entry (useful for cleanup).
     *
     * The ForEach function will be called with a pointer
     * to an entry and the context pointer.
     *
     * If sort = 1, entries will be in sorted order. Otherwise
     * the order is not defined.
     */
    void            For_each_oid_data(oid_array a, ForEach *,
                                      void *context, int sort);

    /*
     * get internal pointer to array (DANGER WILL ROBINSON!)
     *
     * standard disclaimer: DO NOT USE THIS METHOD!
     *
     * Ok, you can use it. Just don't muck about with the
     * ordering or indexes and expect anything to still work.
     *
     * size will be set to the number of elements. If sort is set,
     * the table will be sorted. If sort is not set, the order is
     * not defined.
     */
    void           *Retrieve_oid_array(oid_array a, int *size, int sort);

#ifdef __cplusplus
}
#endif
#endif
