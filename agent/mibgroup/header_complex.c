/* header complex:  More complex storage and data sorting for mib modules */

#include <config.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include "mibincl.h"
#include "header_complex.h"

int
header_complex_generate_varoid(struct variable_list *var) {

  int i;
  
  if (var->name == NULL) {
    /* assume cached value is correct */
    switch(var->type) {
      case ASN_INTEGER:
      case ASN_COUNTER:
      case ASN_GAUGE:
      case ASN_TIMETICKS:
        var->name_length = 1;
        var->name = (oid *) malloc(sizeof(oid));
        var->name[0] = *(var->val.integer);
        break;

      case ASN_OPAQUE:
      case ASN_OCTET_STR:
        var->name_length = var->val_len+1;
        var->name = (oid *) malloc(sizeof(oid) * var->val_len);
        var->name[0] = var->val_len;
        for(i=0; i < var->val_len; i++)
          var->name[i+1] = var->val.string[i];
        break;
      
      default:
        DEBUGMSGTL(("header_complex_generate_varoid",
                    "invalid asn type: %d\n", var->type));
        return SNMPERR_GENERR;
    }
  }
}

/* header_complex_parse_oid(): parses an index to the usmTable to
   break it down into a engineID component and a name component.
   The results are stored in:

   **engineID:   a newly malloced string.
   *engineIDLen: The length of the malloced engineID string above.
   **name:       a newly malloced string.
   *nameLen:     The length of the malloced name string above.

   returns 1 if an error is encountered, or 0 if successful.
*/
int
header_complex_parse_oid(oid *oidIndex, int oidLen,
                         struct header_complex_index *data) {
}


void
header_complex_generate_oid(oid *name, /* out */
                            int *length, /* out */
                            oid *prefix,
                            int prefix_len,
                            struct header_complex_index *data) {

  struct variable_list *var = NULL;
  oid *oidptr;
  
  if (prefix) {
    memcpy(name, prefix, prefix_len * sizeof(oid));
    oidptr = (name + (prefix_len));
    *length = prefix_len;
  } else {
    oidptr = name;
    *length = 0;
  }
    
  for(var = data->vars; var != NULL; var = var->next_variable) {
    header_complex_generate_varoid(var);
    memcpy(oidptr, var->name, sizeof(oid) * var->name_length);
    oidptr = oidptr + var->name_length;
    *length += var->name_length;
  }
  
  DEBUGMSGTL(("header_complex_generate_oid", "generated: "));
  DEBUGMSGOID(("header_complex_generate_oid", name, *length));
  DEBUGMSG(("header_complex_generate_oid", "\n"));
}


void *
header_complex(struct header_complex_index *datalist,
               struct variable *vp,
	       oid *name,
	       int *length,
	       int exact,
	       int *var_len,
	       WriteMethod **write_method) {

  struct header_complex_index *nptr, *pptr, *found = NULL;
  oid indexOid[MAX_OID_LEN];
  int len, i, result;
  
  /* set up some nice defaults for the user */
  if (write_method)
    *write_method = NULL;
  if (var_len)
    *var_len = sizeof (long);

  for(nptr = datalist; nptr != NULL && found == NULL; nptr = nptr->next) {
    if (vp)
      header_complex_generate_oid(indexOid, &len, vp->name, vp->namelen, nptr);
    else
      header_complex_generate_oid(indexOid, &len, NULL, 0, nptr);

    result = snmp_oid_compare(name, *length, indexOid, len);
    DEBUGMSGTL(("header_complex", "Checking: "));
    DEBUGMSGOID(("header_complex", indexOid, len));
    DEBUGMSG(("header_complex", "\n"));

    if (exact) {
      if (result == 0) {
        found = nptr;
      }
    } else {
      if (result == 0) {
        /* found an exact match.  Need the next one for !exact */
        if (nptr->next)
          found = nptr->next;
      } else if (result == -1) {
        found = nptr;
      }
    }
  }
  if (found) {
    if (vp)
      header_complex_generate_oid(name, length, vp->name, vp->namelen, found);
    return found->data;
  }
    
  return NULL;
}

int
header_complex_var_compare(struct variable_list *varl,
                           struct variable_list *varr) {
  int ret;

  for(; varl != NULL && varr != NULL;
      varl = varl->next_variable, varr = varr->next_variable) {
    header_complex_generate_varoid(varl);
    header_complex_generate_varoid(varr);
    ret = snmp_oid_compare(varl->name, varl->name_length,
                           varr->name, varr->name_length);
    if (ret != 0)
      return ret;
  }
  if (varr != NULL)
    return -1;
  if (varl != NULL)
    return 1;
  return 0;
}

struct header_complex_index *
header_complex_add_data(struct header_complex_index **thedata,
                        struct variable_list *var, void *data) {
  struct header_complex_index *hciptrn, *hciptrp, *ourself;

  if (thedata == NULL || var == NULL || data == NULL)
    return NULL;
  
  header_complex_generate_varoid(var);

  for(hciptrn = *thedata, hciptrp = NULL;
      hciptrn != NULL;
      hciptrp = hciptrn, hciptrn = hciptrn->next)
    if (header_complex_var_compare(hciptrn->vars, var) > 0)
      break;
  
  /* nptr should now point to the spot that we need to add ourselves
     in front of, and pptr should be our new 'prev'. */

  /* create ourselves */
  ourself = (struct header_complex_index *)
    malloc(sizeof(struct header_complex_index));
  memset(ourself, 0, sizeof(struct header_complex_index));

  /* change our pointers */
  ourself->prev = hciptrp;
  ourself->next = hciptrn;
    
  if (ourself->next)
    ourself->next->prev = ourself;

  if (ourself->prev)
    ourself->prev->next = ourself;

  ourself->data = data;
  ourself->vars = var;

  /* rewind to the head of the list and return it (since the new head
     could be us, we need to notify the above routine who the head now is. */
  for(hciptrp = ourself; hciptrp->prev != NULL; hciptrp = hciptrp->prev);

  *thedata = hciptrp;
  DEBUGMSGTL(("header_complex_add_data", "adding something...\n"));
  return hciptrp;
}

header_complex_dump(struct header_complex_index *thestuff) {
  struct header_complex_index *hciptr;
  oid oidsave[MAX_OID_LEN];
  int len;
  
  for(hciptr = thestuff; hciptr != NULL; hciptr = hciptr->next) {
    DEBUGMSGTL(("header_complex_dump", "var:  "));
    header_complex_generate_oid(oidsave, &len, NULL, 0, hciptr);
    DEBUGMSGOID(("header_complex_dump", oidsave, len));
    DEBUGMSG(("header_complex_dump", "\n"));
  }
}

#ifdef TESTING

main() {
  oid oidsave[MAX_OID_LEN];
  int len = MAX_OID_LEN, len2;
  struct variable_list *vars;
  long ltmp = 4242, ltmp2=88, ltmp3 = 1;
  oid ourprefix[] = { 1,2,3,4};
  char *string="wes", *string2 = "dawn";

  struct header_complex_index *thestorage = NULL;

  debug_register_tokens("header_complex_dump");
  snmp_set_do_debugging(1);
  
  vars = NULL;
  len2 = sizeof(ltmp);
  snmp_varlist_add_variable(&vars, NULL, 0, ASN_INTEGER, (char *) &ltmp, len2);
  header_complex_add_data(&thestorage, vars, ourprefix);

  vars = NULL;
  len2 = strlen(string);
  snmp_varlist_add_variable(&vars, NULL, 0, ASN_OCTET_STR, string, len2);
  header_complex_add_data(&thestorage, vars, ourprefix);

  vars = NULL;
  len2 = sizeof(ltmp2);
  snmp_varlist_add_variable(&vars, NULL, 0, ASN_INTEGER, (char *) &ltmp2, len2);
  header_complex_add_data(&thestorage, vars, ourprefix);

  vars = NULL;
  len2 = strlen(string2);
  snmp_varlist_add_variable(&vars, NULL, 0, ASN_OCTET_STR, string2, len2);
  header_complex_add_data(&thestorage, vars, ourprefix);

  vars = NULL;
  len2 = sizeof(ltmp3);
  snmp_varlist_add_variable(&vars, NULL, 0, ASN_INTEGER, (char *) &ltmp3, len2);
  header_complex_add_data(&thestorage, vars, ourprefix);

  header_complex_dump(thestorage);
}
#endif
