/*
 *  header_complex.h:  More complex storage and data sorting for mib modules
 */
#ifndef _MIBGROUP_HEADER_COMPLEX_H
#define _MIBGROUP_HEADER_COMPLEX_H

struct header_complex_index {
   struct variable_list *vars;
   void *data;
   struct header_complex_index *next;
   struct header_complex_index *prev;
};

void *header_complex(struct header_complex_index *datalist, struct variable *vp,
                     oid *name, int *length, int exact, int *var_len,
                     WriteMethod **write_method);

#endif /* _MIBGROUP_HEADER_COMPLEX_H */

