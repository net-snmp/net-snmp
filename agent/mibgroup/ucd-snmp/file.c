#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include "mibincl.h"
#include "struct.h"

#include "../util_funcs.h"
#include "file.h"

#define MAXFILE   20

struct filestat fileTable[MAXFILE];
int fileCount;
	
void init_file(void) 
{
  struct variable2 file_table[] = {
    {FILE_INDEX,  ASN_INTEGER,   RONLY, var_file_table, 1, {1}},
    {FILE_NAME,   ASN_OCTET_STR, RONLY, var_file_table, 1, {2}},
    {FILE_SIZE,   ASN_INTEGER,   RONLY, var_file_table, 1, {3}},
    {FILE_MAX,    ASN_INTEGER,   RONLY, var_file_table, 1, {4}},
    {FILE_ERROR,  ASN_INTEGER,   RONLY, var_file_table, 1, {100}},
    {FILE_MSG,    ASN_OCTET_STR, RONLY, var_file_table, 1, {101}}
  };

/* Define the OID pointer to the top of the mib tree that we're
   registering underneath */
  oid file_variables_oid[] = { EXTENSIBLEMIB,15,1 };

  /* register ourselves with the agent to handle our mib tree */
  REGISTER_MIB("mibII/file", file_table, variable2, file_variables_oid);

  snmpd_register_config_handler("file", file_parse_config, file_free_config,
                                "file [maxsize]");

}

void file_free_config(void) 
{
    fileCount = 0;
}

void file_parse_config(char *word, char* cptr)
{
    if (fileCount < MAXFILE)
    {
	fileTable[fileCount].max = -1;

	sscanf(cptr, "%s %d", 
	       fileTable[fileCount].name, 
	       &fileTable[fileCount].max);

	fileCount++;
    }
}

void updateFile(int index)
{
    struct stat sb;
    
    if (stat(fileTable[index].name, &sb) == 0)
	fileTable[index].size = sb.st_size >> 10;
}

/* OID functions */

unsigned char *var_file_table(struct variable *vp,
		oid *name,
		int *length,
		int exact,
		int *var_len,
		int (**write_method) (int, u_char *,u_char, int, u_char *,oid*, int))
{
  static long long_ret;
  static char error[256];
  int index;
  struct filestat *file;

  if (!checkmib(vp, name, length, exact, var_len, write_method, fileCount))
      return(NULL);
  
  index = name[*length-1]-1;

  updateFile(index);

  file = &fileTable[index];
  
  switch (vp->magic) 
  {
  case FILE_INDEX:
      long_ret = index+1;
      return (u_char *)&long_ret;

  case FILE_NAME:
      *var_len = strlen(file->name);
      return (u_char *)file->name;
      
  case FILE_SIZE:
      long_ret = file->size;
      return (u_char *)&long_ret;
      
  case FILE_MAX:
      long_ret = file->max;
      return (u_char *)&long_ret;
      
  case FILE_ERROR:
      if (file->max >= 0 && file->size > file->max)
	  long_ret = 1;
      else
	  long_ret = 0;

      return (u_char *)&long_ret;
      
  case FILE_MSG:
      if (file->max >= 0 && file-> size > file->max)
	  sprintf(error, FILE_ERROR_MSG, file->name, file->max, file->size);
      else
	  strcpy(error, "");

      *var_len = strlen(error);
      return (u_char *)error;
      
  default:
      ERROR_MSG("");
  }
  
  return NULL;
}
