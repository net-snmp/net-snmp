
#include <config.h>

#ifdef CAN_USE_NLIST

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <stdio.h>
#include <fcntl.h>
#include <netinet/in.h>
#ifdef HAVE_NLIST_H
#include <nlist.h>
#endif
#if HAVE_KVM_H
#include <kvm.h>
#endif

#include "auto_nlist.h"
#include "autonlist.h"
#include "kernel.h"
#include "../snmplib/system.h"

struct autonlist *nlists = 0;
static void init_nlist __P((struct nlist *));

long
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
    } else {
      ptr = &((*ptr)->right);
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
    sprintf(it->nl[0].n_name,"_%s",string);
    it->nl[1].n_name = 0;
    init_nlist(it->nl);
    if (it->nl[0].n_type == 0) {
      strcpy(it->nl[0].n_name,string);
      init_nlist(it->nl);
    }
    if (it->nl[0].n_type == 0) {
      fprintf(stderr, "nlist err: neither %s nor _%s found.\n", string, string);
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
  long result;
  int ret;

  result = auto_nlist_value(string);
  if (result != -1) {
    if (var != NULL) {
      ret = klookup(result, var, size);
      if (!ret)
        fprintf(stderr, "auto_nlist failed on %s at location %lx\n",
               string, result);
      return ret;
    } else
      return 1;
  }
  return 0;
}
 
static void
init_nlist(nl)
  struct nlist nl[];
{
#ifdef CAN_USE_NLIST
  int ret;
#if HAVE_KVM_OPENFILES
  kvm_t *kernel;
  char kvm_errbuf[4096];

  if((kernel = kvm_openfiles(KERNEL_LOC, NULL, NULL, O_RDONLY, kvm_errbuf)) == NULL) {
      fprintf(stderr, "kvm_openfiles: %s\n", kvm_errbuf);
      exit(1);
  }
  if ((ret = kvm_nlist(kernel, nl)) == -1) {
      perror("kvm_nlist");
      exit(1);
  }
  kvm_close(kernel);
#else
  if ((ret = nlist(KERNEL_LOC,nl)) == -1) {
    perror("nlist");
    exit(1);
  }
#endif
  for(ret = 0; nl[ret].n_name != NULL; ret++) {
#ifdef aix4
      if (nl[ret].n_type == 0 && nl[ret].n_value != 0)
	nl[ret].n_type = 1;
#endif
      if (nl[ret].n_type == 0) {
	  DEBUGP("nlist err:  %s not found\n",nl[ret].n_name);
      } else {
	  DEBUGP("nlist: %s 0x%X\n", nl[ret].n_name,
		  (unsigned int)nl[ret].n_value);
      }
  }
#endif
}

int KNLookup(nl, nl_which, buf, s)
    struct nlist nl[];
    int nl_which;
    char *buf;
    int s;
{   struct nlist *nlp = &nl[nl_which];

    if (nlp->n_value == 0) {
        fprintf (stderr, "Accessing non-nlisted variable: %s\n", nlp->n_name);
	nlp->n_value = -1;	/* only one error message ... */
	return 0;
    }
    if (nlp->n_value == -1)
        return 0;

    return klookup(nlp->n_value, buf, s);
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
