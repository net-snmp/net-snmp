#include "wes.h"

#define WESMIB 1,3,6,1,4,10,1

u_char *var_wes_proc();

struct variable2 wes_proc_variables[] = {
  {WESNAMES, STRING, RONLY, var_wes_proc, 1, {1}},
};


u_char *var_wes_proc(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;   /* IN - pointer to variable entry that points here */
    register oid	*name;	    /* IN/OUT - input name requested, output name found */
    register int	*length;    /* IN/OUT - length of input and output oid's */
    int			exact;	    /* IN - TRUE if an exact match was requested. */
    int			*var_len;   /* OUT - length of variable or 0 if function returned. */
    int			(**write_method)(); /* OUT - pointer to function to set variable, otherwise 0 */
{

  oid newname[MAX_NAME_LEN];
  int count, result,i, rtest=0;
  register int interface;
  char *test="test";
  
  bcopy((char *) vp->name, (char *)newname, (int)vp->namelen * sizeof (oid));
  result = compare(name, *length, newname, (int)vp->namelen + 1);
  for(i=0; i < *length; i++) {
    printf(".%d",name[i]);
    if (name[i] != vp->name[i]) {
      rtest = 1;
    }
  }
  printf("\ntest: %d\tresult:%d\texact:%d\n",rtest,result,exact);
/*  if ((exact && (result != 0)) || (!exact && (result >= 0))){ */
  if (rtest != 0) {
    printf("returning...\n");
    return NULL;
  }
/*  newname[vp->namelen] = 12;
  bcopy((char *)newname, (char *)name, ((int)vp->namelen + 1) * sizeof(oid));
  *length = vp->namelen + 1;
  */

  *write_method = 0;
  *length = vp->namelen + 1;
  switch (vp->magic) {
    case WESNAMES:
      *var_len = strlen(test);
      return((u_char *) test);
  }
}

int random()
{
  return(rand());
}

void srandom (seed)
  unsigned int seed;
{
  srand(seed);
}
