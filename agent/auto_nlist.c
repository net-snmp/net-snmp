
#include <config.h>

#ifdef CAN_USE_NLIST
#ifdef HAVE_NLIST_H
#include <nlist.h>
#endif
#include <stdio.h>
#include "auto_nlist.h"
#include "autonlist.h"

struct autonlist *nlists = 0;

int
auto_nlist_value(string)
  char *string;
{
  struct autonlist **ptr, *it=0;
  int cmp;

  if (string == 0)
    return 0;

  ptr = &nlists;
  while(*ptr != 0 && it == 0) {
    cmp = strcmp((*ptr)->symbol, string);
    if (cmp == 0)
      it = *ptr;
    else if (cmp < 0) {
      ptr = &((*ptr)->left);
      DEBUGP("auto_nlist:  Its a jump to the left: %s\n",string);
    } else {
      ptr = &((*ptr)->right);
      DEBUGP("auto_nlist:  And a step to the righhhhhttt...: %s\n",string);
    }
  }
  if (*ptr == 0) {
    *ptr = (struct autonlist *) malloc(sizeof (struct autonlist));
    it = *ptr;
    it->left = 0;
    it->right = 0;
    it->symbol = (char *) malloc(strlen(string)+1);
    strcpy(it->symbol,string);
    /* allocate an extra byte for inclusion of a preceding '_' later */
    it->nl[0].n_name = (char *) malloc(strlen(string)+2);
    strcpy(it->nl[0].n_name,string);
    it->nl[1].n_name = 0;
    init_nlist(it->nl);
    if (it->nl[0].n_type == 0) {
      sprintf(it->nl[0].n_name,"_%s",string);
      init_nlist(it->nl);
    }
    if (it->nl[0].n_type == 0) {
      DEBUGP("nlist err:  neither %s nor _%s found.\n", string, string);
      return( -1 );
    } else {
      DEBUGP("nlist:  found symbol %s at %x.\n", it->symbol, it->nl[0].n_value);
      return( it->nl[0].n_value );
    }
  }
  else
    return( it->nl[0].n_value );
}

int
auto_nlist(string, var, size)
  char *string;
  char *var;
  int size;
{
  int result;
  int ret;

  result = auto_nlist_value(string);
  if (result!= -1) {
    if (var != 0) {
      ret =  klookup(result, var, size);
      if (!ret)
        DEBUGP("auto_nlist failed on %s at location %x\n",
               string, result);
      return ret;
    } else
      return 1;
  }
  return 0;
}
#ifdef TESTING
void
auto_nlist_print_tree(indent, ptr)
  int indent;
  struct autonlist *ptr;
{
  char buf[1024];
  if (indent == -2) {
    fprintf(stderr, "nlist tree:\n");
    auto_nlist_print_tree(12,nlists);
  } else {
    if (ptr == 0)
      return;
    sprintf(buf,"%%%ds\n",indent);
/*    DEBUGP("buf: %s\n",buf); */
    fprintf(stderr, buf, ptr->symbol);
    auto_nlist_print_tree(indent+2,ptr->left);
    auto_nlist_print_tree(indent+2,ptr->right);
  }
}
#endif
#endif /* CAN_USE_NLIST */
