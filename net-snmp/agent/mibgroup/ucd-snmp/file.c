#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "mibincl.h"
#include "struct.h"

#include "file.h"

#define MAXFILE   20


struct filestat fileTable[MAXFILE];
int fileCount;
	
void file_free_config(void) 
{
    fileCount = 0;
}

void file_parse_config(word,cptr)
  char *word;
  char *cptr;
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

unsigned char *var_file_table(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
/* IN - pointer to variable entry that points here */
    register oid	*name;
/* IN/OUT - input name requested, output name found */
    register int	*length;
/* IN/OUT - length of input and output oid's */
    int			exact;
/* IN - TRUE if an exact match was requested. */
    int			*var_len;
/* OUT - length of variable or 0 if function returned. */
    int			(**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
/* OUT - pointer to function to set variable, otherwise 0 */
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
      if (file->size > file->max)
	  long_ret = 1;
      else
	  long_ret = 0;

      return (u_char *)&long_ret;
      
  case FILE_MSG:
      if (file-> size > file->max)
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
