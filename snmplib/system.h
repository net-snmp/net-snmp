/***********************************************************
        Copyright 1993 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/
/*
 * Definitions for the system dependent library file
 */
#include <config.h>
#ifdef WIN32
#include <sys/timeb.h>
#include <time.h>
// structure of a directory entry
typedef struct direct 
{
	long	d_ino;		// inode number (not used by MS-DOS) 
	int	d_namlen;		// Name length 
	char	d_name[257];// file name 
} _DIRECT;

// structure for dir operations 
typedef struct _dir_struc
{
	char	*start;			// Starting position
	char	*curr;			// Current position
	long	size;			// Size of string table
	long	nfiles;			// number if filenames in table
	struct direct dirstr;	// Directory structure to return
} DIR;

DIR *opendir __P((char *filename));
struct direct *readdir __P((DIR *dirp));
int closedir __P((DIR *dirp));

int gettimeofday __P((struct timeval *, struct timezone *tz));

char * winsock_startup __P((void));
void winsock_cleanup __P((void));

#define SOCK_STARTUP winsock_startup()
#define SOCK_CLEANUP winsock_cleanup()
#else
#define SOCK_STARTUP
#define SOCK_CLEANUP
#endif

in_addr_t get_myaddr __P((void));
long get_uptime __P((void));
