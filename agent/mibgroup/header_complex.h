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
                     oid *name, size_t *length, int exact, size_t *var_len,
                     WriteMethod **write_method);

int header_complex_generate_varoid(struct variable_list *var);
int header_complex_parse_oid(oid *oidIndex, size_t oidLen,
                             struct variable_list *data);
void header_complex_generate_oid(oid *name, size_t *length, oid *prefix,
                                 size_t prefix_len,
                                 struct header_complex_index *data);
int header_complex_var_compare(struct variable_list *varl,
                               struct variable_list *varr);
struct header_complex_index *
  header_complex_add_data(struct header_complex_index **thedata,
                          struct variable_list *var, void *data);


#endif /* _MIBGROUP_HEADER_COMPLEX_H */

