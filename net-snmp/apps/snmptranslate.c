/*
 * snmptranslate.c - report or translate info about oid from mibs
 *
 * Update: 1998-07-17 <jhy@gsu.edu>
 * Added support for dumping alternate oid reports (-t and -T options).
 * Added more detailed (useful?) usage info.
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
#include <getopt.h>

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
#include "snmp_debug.h"
#include "../snmplib/system.h"

#include "version.h"

void usage(void)
{
  fprintf(stderr,
	  "usage: snmptranslate [-V|-p|-a] [-R] [-D] [-m <MIBS>] [-M <MIBDIRS] [-n] [-d] [-f|-s|-S] [<objectID>]\n\n");
  fprintf(stderr, "  -h\t\tPrint this help message.\n");
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
          "  -t\t\tPrint MIB symbol table report in alternate format. (Same as -Tt)\n");
  fprintf(stderr,
          "  -T <lost>\tPrint one or more MIB symbol reports.\n");
  fprintf(stderr,
          "  Where <lost> is one or more of the following:\n");
  fprintf(stderr,
          "  \tl\tEnable labeled OID report.\n");
  fprintf(stderr,
          "  \to\tEnable OID report.\n");
  fprintf(stderr,
          "  \ts\tEnable dotted symbolic report.\n");
  fprintf(stderr,
          "  \tt\tEnable alternately formatted symbolic suffix report.\n");
  fprintf(stderr,
          "  -R\t\tUse \"random access\" to access objectID.\n");
  fprintf(stderr,
          "  -n\t\tDisplay OID in symbolic form for objectID.\n");
  fprintf(stderr,
          "  -d\t\tDisplay detailed information for objectID.\n");
  fprintf(stderr, "  -P <MIBOPTS>\tToggle various defaults controlling mib parsing:\n");
  snmp_mib_toggle_options_usage("\t\t", stderr);
  fprintf(stderr, "  -O <OIDOPTS>\tToggle various defaults controlling oid printing:\n");
  snmp_oid_toggle_options_usage("\t\t", stderr);
  exit(1);
}

int main(int argc, char *argv[])
{
    int	arg, count;
    char *current_name = NULL, *cp;
    oid name[MAX_OID_LEN];
    size_t name_length;
    int tosymbolic = 0;
    int description = 0;
    int random_access = 0;
    int print = 0;
    int find_best = 0;
    
    /*
     * usage: snmptranslate name
     */
    while ((arg = getopt(argc, argv, "VhndRrwWbpafsSm:M:D:P:tT:O:")) != EOF){
	switch(arg) {
	case 'h':
	    usage();
            exit(1);
	case 'b':
            find_best = 1;
            break;
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
            setenv("MIBS", optarg, 1);
            break;
        case 'M':
            setenv("MIBDIRS", optarg, 1);
            break;
	case 'D':
            debug_register_tokens(optarg);
	    snmp_set_do_debugging(1);
	    break;
        case 'V':
            fprintf(stderr,"UCD-snmp version: %s\n", VersionInfo);
            exit(0);
            break;
	case 'P':
	    cp = snmp_mib_toggle_options(optarg);
	    if (cp != NULL) {
		fprintf(stderr,"Unknown parser option to -P: %c.\n", *cp);
		usage();
		exit(1);
	    }
	    break;
	case 'O':
	    cp = snmp_oid_toggle_options(optarg);
	    if (cp != NULL) {
		fprintf(stderr, "Unknown OID option to -O: %c.\n", *cp);
		usage();
		exit(1);
	    }
	case 't':
            print = 3;
            print_oid_report_enable_suffix();
            break;
        case 'T':
            for(cp = optarg; *cp; cp++)
            {
                switch(*cp)
                {
                  case 'l':
                    print_oid_report_enable_labeledoid();
                    break;
                  case 'o':
                    print_oid_report_enable_oid();
                    break;
                  case 's':
                    print_oid_report_enable_symbolic();
                    break;
                  case 't':
                    print_oid_report_enable_suffix();
                    break;
                  default:
                    fprintf(stderr,"Invalid <lost> character: %c\n", *cp);
                    usage();
                    exit(1);
                    break;
                }
            }
            break;
        default:
	    fprintf(stderr,"invalid option: -%c\n", arg);
            usage();
            exit(1);
	    break;
	}
    }
    
    if (optind < argc)
	current_name = argv[optind];
    else if (!print) {
        usage(); 
        exit(1);
    }
    
    init_snmp("snmpapp");
    if (print == 1 && current_name == NULL)
        print_mib_tree (stdout, get_tree_head());
    if (print == 2) print_ascii_dump (stdout);
    if (print == 3) print_oid_report (stdout);
    if (!current_name) exit (0);

    name_length = MAX_OID_LEN;
    if (random_access){
	if (!get_node(current_name, name, &name_length)){
	    fprintf(stderr, "Unknown object identifier: %s\n", current_name);
	    exit(2);
	}
    } else if (find_best) {
        u_int result;
        struct tree *tp = find_best_tree_node(current_name, 0, &result);
        if (!tp) {
            printf("Unable to find a matching object identifier for \"%s\"\n",
                   current_name);
            exit(1);
        }
        get_node(tp->label, name, &name_length);
    } else {
	if (!read_objid(current_name, name, &name_length)){
	    fprintf(stderr, "Invalid object identifier: %s\n", current_name);
	    exit(2);
	}
    }
    

    if (print == 1) {
        struct tree *tp;
        tp = get_tree(name, name_length, get_tree_head());
        print_mib_tree (stdout, tp);
        exit(0);
    }

    if (tosymbolic){
	print_objid(name, name_length);
    } else {
	for(count = 0; count < (int)name_length; count++)
	    printf(".%ld", name[count]);
	printf("\n");
    }
    if (description){
	print_description(name, name_length);
    }
    return (0);
}
