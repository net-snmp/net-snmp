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
#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <ctype.h>

#include "snmp.h"
#include "asn1.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"

extern int  errno;
int	snmp_dump_packet = 0;

main(argc, argv)
    int	    argc;
    char    *argv[];
{
    int	arg, count;
    char *current_name = NULL;
    char *cp, buf[256];
    oid name[MAX_NAME_LEN];
    int name_length;
    int tosymbolic = 0;
    int description = 0;
    int random_access = 0;
    
    init_mib();
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
		break;
	      case 'r':
		random_access = 1;
		break;
	      default:
		printf("invalid option: -%c\n", argv[arg][1]);
		break;
	    }
	    continue;
	}
	current_name = argv[arg];
    }
    
    if (current_name == NULL){
	printf("usage: snmptranslate [-n] [-d] [-r] object-identifier\n");
	exit(1);
    }
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
	    printf(".%d", name[count]);
	printf("\n");
    }
    if (description){
	printf("\n");
	print_description(name, name_length);
    }
}

