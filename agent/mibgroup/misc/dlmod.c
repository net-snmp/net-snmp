#include <config.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <stdio.h>
#if HAVE_STRINGS_H
#include <strings.h>
#else
#if STDC_HEADERS
#include <string.h>
#endif
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <dlfcn.h>

#if 0
#include "mibincl.h"
#include "struct.h"
#include "util_funcs.h"
#include "read_config.h"
#include "snmp_api.h"
#endif

#ifndef _DLMOD_PATH
#define _DLMOD_PATH "/usr/local/lib/snmp/dlmod"
#endif

struct dlmod {
	struct dlmod *next;
	char name[64];
	char path[255];
	void *handle;
};

struct dlmod *dlmods = NULL;

int numdlmods = 0;

void dlmod_parse_config(word,cptr)
  char *word;
  char *cptr;
{
  struct dlmod **pdlmod = &dlmods, *ptmp;
  char *dl_name, *dl_path;
  char sym_init[64];
  int (*dl_init)(void);
  int i;
  
  ptmp = calloc(1, sizeof(struct dlmod));
  if (ptmp == NULL) 
	return;

  if (cptr == NULL) {
	config_perror("Bad dlmod line");
	return;
  }
  /* remove comments */
  *(cptr + strcspn(cptr, "#;\r\n")) = '\0';
 
  /* dynamic module name */
  dl_name = strtok(cptr, "\t "); 
  if (dl_name == NULL) {
	config_perror("Bad dlmod line");
	free(ptmp);
	return;
  }
  strncpy(ptmp->name, dl_name, sizeof(ptmp->name));

  /* dynamic module path */
  dl_path = strtok(NULL, "\t ");
  if (dl_path == NULL) 
	snprintf(ptmp->path, sizeof(ptmp->path), 
		"%s/%s.so", _DLMOD_PATH, ptmp->name);
  else if (dl_path[0] == '/') 
	strncpy(ptmp->path, dl_path, sizeof(ptmp->path));
  else
	snprintf(ptmp->path, sizeof(ptmp->path), "%s/%s", _DLMOD_PATH, dl_path);

  ptmp->handle = dlopen(ptmp->path, RTLD_NOW);
  if (ptmp->handle == NULL) {
	config_perror(dlerror());
	free(ptmp);
	return;
  }
  snprintf(sym_init, sizeof(sym_init), "_%s_init", ptmp->name);
  dl_init = dlsym(ptmp->handle, sym_init);
  if (dl_init == NULL) {
	config_perror(dlerror());
	free(ptmp);
	return;
  }
	
  if (dl_init()) {
	config_perror("init failed");
	free(ptmp);
	return;
  }

  while(*pdlmod != NULL)
    pdlmod = &((*pdlmod)->next);
  (*pdlmod) = ptmp;

  numdlmods++;

}

void dlmod_free_config __P((void)) {
  struct dlmod *dtmp, *dtmp2;
  char sym_deinit[64];
  int (* dl_deinit)(void);
  
  for (dtmp = dlmods; dtmp != NULL;) {
    dtmp2 = dtmp;
    dtmp = dtmp->next;
	snprintf(sym_deinit, sizeof(sym_deinit), "_%s_deinit", dtmp2->name);
	dl_deinit = dlsym(dtmp2->handle, sym_deinit);
	if (dl_deinit) 
		dl_deinit();
	dlclose(dtmp2->handle);
    
    free(dtmp2);
  }
  dlmods = NULL;
  numdlmods = 0;
}

