
#include <config.h>

#ifdef CAN_USE_NLIST
#ifdef HAVE_NLIST_H
#include <nlist.h>
#endif
#include "auto_nlist.h"
#include "autonlist.h"

struct autonlist *nlists = 0;

int
auto_nlist_value(string)
  char *string;
{
  struct autonlist **ptr, *it;
  int cmp;

  if (string == 0)
    return 0;

  ptr = &nlists;
  while(*ptr != 0 && it == 0) {
    cmp = strcmp((*ptr)->symbol, string);
    if (cmp == 0)
      it = *ptr;
    else if (cmp < 0)
      ptr = &((*ptr)->left);
    else
      ptr = &((*ptr)->right);
  }
  if (*ptr == 0) {
    *ptr = (struct autonlist *) malloc(sizeof (struct autonlist));
    it = *ptr;
    strcpy(it->symbol,string);
    strcpy(it->nl[0].n_name,string);
    it->nl[1].n_name = 0;
    init_nlist(it->nl);
    if (it->nl[0].n_type == 0) {
      sprintf(it->symbol,"_%s",string);
      init_nlist(it->nl);
    }
    if (it->nl[0].n_type == 0) {
      DEBUGP("nlist err:  neither %s nor _%s found.\n",string);
      return( -1 );
    } else {
      DEBUGP("nlist:  found symbol %s.\n",it->symbol);
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

  result = auto_nlist_value(string);
  if (result!= -1) {
    if (var != 0)
      return klookup(result, var, size);
    else
      return 1;
  }
  return 0;
}

#endif /* CAN_USE_NLIST */
