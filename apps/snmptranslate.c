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
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#include <sys/types.h>
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <stdio.h>
#include <ctype.h>

#if HAVE_WINSOCK_H
#include <winsock.h>
#endif

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "snmp_client.h"
#include "parse.h"
#include "mib.h"
#include "snmp.h"
#include "../snmplib/system.h"

#include "version.h"

int main __P((int, char **));

void
usage __P((void))
{
  fprintf(stderr,
	  "usage: snmptranslate [-V|-p|-a] [-w|-W] [-R] [-D] [-m <MIBS>] [-M <MIBDIRS] [-n] [-d] [-f|-s|-S] [<objectID>]\n\n");
  fprintf(stderr,
          "  -V\t\tPrint snmptranslate version then exit.\n");
  fprintf(stderr,
          "  -p\t\tPrint MIB symbol table report.\n");
  fprintf(stderr,
          "  -a\t\tPrint MIB ascii symbol table.\n");
  fprintf(stderr,
          "  -m <MIBS>\tuse MIBS list instead of the default mib list.\n");
  fprintf(stderr,
	  "  -D\t\tenable snmplib debugging messages\n");
  fprintf(stderr,
          "  -M <MIBDIRS>\tuse MIBDIRS as the location to look for mibs.\n");
  fprintf(stderr,
          "  -w\t\tEnable warnings of MIB symbol conflicts.\n");
  fprintf(stderr,
          "  -W\t\tEnable detailed warnings of MIB symbol conflicts.\n");
  fprintf(stderr,
          "  -R\t\tUse \"random access\" to access objectID.\n");
  fprintf(stderr,
          "  -r\t\tUse \"random access\" to access objectID. (Obsolete, -R preferred)\n");
  fprintf(stderr,
          "  -n\t\tDisplay OID in symbolic form for objectID.\n");
  fprintf(stderr,
          "  -d\t\tDisplay detailed information for objectID.\n");
  fprintf(stderr,
          "  -f\t\tDisplay full OID for objectID.\n");
  fprintf(stderr,
          "  -s\t\tDisplay last symbolic part of OID for objectID.\n");
  fprintf(stderr,
          "  -S\t\tDisplay MIB and last symbolic part of OID for objectID.\n");
  exit(1);
}

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
	      case 'h':
		usage();
                exit(1);
	      case 'n':
		tosymbolic = 1;
		break;	     
	      case 'd':
		description = 1;
		snmp_set_save_descriptions(1);
		break;
	      case 'r':
	      case 'R':
		random_access = 1;
		break;
              case 'w':
                snmp_set_mib_warnings(1);
                break;
              case 'W':
                snmp_set_mib_warnings(2);
                break;
              case 'p':
                print = 1;
                break;
              case 'a':
                print = 2;
                break;
	      case 'f':
		snmp_set_full_objid(1);
		break;
	      case 's':
		snmp_set_suffix_only(1);
		tosymbolic = 1;
		break;
	      case 'S':
		snmp_set_suffix_only(2);
		tosymbolic = 1;
		break;
              case 'm':
                if (argv[arg][2] != 0)
                  setenv("MIBS",&argv[arg][2], 1);
                else if (++arg < argc)
                  setenv("MIBS",argv[arg], 1);
                else {
                  fprintf(stderr,"Need MIBS after -m flag.\n");
                  usage();
                  exit(1);
                }
                break;
              case 'M':
                if (argv[arg][2] != 0)
                  setenv("MIBDIRS",&argv[arg][2], 1);
                else if (++arg < argc)
                  setenv("MIBDIRS",argv[arg], 1);
                else {
                  fprintf(stderr,"Need MIBDIRS after -M flag.\n");
                  usage();
                  exit(1);
                }
                break;
	      case 'D':
		snmp_set_do_debugging(1);
		break;
              case 'V':
                fprintf(stderr,"UCD-snmp version: %s\n", VersionInfo);
                exit(0);
                break;

	      default:
		fprintf(stderr,"invalid option: -%c\n", argv[arg][1]);
                usage();
		break;
	    }
	    continue;
	}
	current_name = argv[arg];
    }
    
    if (current_name == NULL && !print){
      fprintf(stderr,
              "usage: snmptranslate [-n] [-d] [-R] [-w|-W] [-f|-s|-S] [-p] objectID\n");
      exit(1);
    }
    
    init_mib();
    if (print == 1) print_mib (stdout);
    if (print == 2) print_ascii_dump (stdout);
    if (!current_name) exit (0);

    name_length = MAX_NAME_LEN;
    if (random_access){
	if (!get_node(current_name, name, &name_length)){
	    fprintf(stderr, "Unknown object identifier: %s\n", current_name);
	    exit(2);
	}
    } else {
	if (!read_objid(current_name, name, &name_length)){
	    fprintf(stderr, "Invalid object identifier: %s\n", current_name);
	    exit(2);
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
	print_description(name, name_length);
    }
    return (0);
}
