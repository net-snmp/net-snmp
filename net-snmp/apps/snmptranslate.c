/*
 *
 */
/************************************************************************
	Copyright 1988, 1989, 1991, 1992 by Carnegie Mellon University

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

#include <config.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#else
#include <string.h>
#endif
#include <sys/types.h>

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <stdio.h>
#include <ctype.h>

#include "asn1.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "mib.h"
#include "snmp.h"

int main __P((int, char **));

extern int  errno;
extern int save_mib_descriptions;
extern int mib_warnings;

int
main(argc, argv)
    int	    argc;
    char    *argv[];
{
    int	arg, count;
    char *current_name = NULL;
    oid name[MAX_NAME_LEN];
    int name_length;
    int tosymbolic = 0;
    int description = 0;
    int random_access = 0;
    int print = 0;
    
    /*
     * usage: snmptranslate name
     */
    for(arg = 1; arg < argc; arg++){
	if (argv[arg][0] == '-'){
	    switch(argv[arg][1]){
	      case 'n':
		tosymbolic = 1;
		break;	     
	      case 'd':
		description = 1;
		save_mib_descriptions = 1;
		break;
	      case 'r':
		random_access = 1;
		break;
              case 'w':
                mib_warnings = 1;
                break;
              case 'W':
                mib_warnings = 2;
                break;
              case 'p':
                print = 1;
                break;
	      default:
		fprintf(stderr,"invalid option: -%c\n", argv[arg][1]);
		break;
	    }
	    continue;
	}
	current_name = argv[arg];
    }
    
    if (current_name == NULL && !print){
      fprintf(stderr,
              "usage: snmptranslate [-n] [-d] [-r] [-w|-W] [-p] objectID\n");
      exit(1);
    }
    
    init_mib();
    if (print) print_mib (stdout);
    if (!current_name) exit (0);

    name_length = MAX_NAME_LEN;
    if (random_access){
	if (!get_node(current_name, name, &name_length)){
	    printf("Unknown object descriptor %s\n", current_name);
	    exit(2);
	}
    } else {
	if (!read_objid(current_name, name, &name_length)){
	    printf("Invalid object identifier: %s\n", current_name);
	}
    }
    if (tosymbolic){
	print_objid(name, name_length);
    } else {
	for(count = 0; count < name_length; count++)
	    printf(".%ld", name[count]);
	printf("\n");
    }
    if (description){
	printf("\n");
	print_description(name, name_length);
    }
    exit (0);
}
