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
#include "default_store.h"
#include "../snmplib/system.h"

#include "version.h"

void usage(void)
{
  fprintf(stderr,
	  "usage: snmptranslate [options] [<objectID>]\n\n");
  fprintf(stderr, "  -h\t\tPrint this help message.\n");
  fprintf(stderr,
          "  -V\t\tPrint snmptranslate version then exit.\n");
  fprintf(stderr,
          "  -m <MIBS>\tuse MIBS list instead of the default mib list.\n");
  fprintf(stderr,
	  "  -D\t\tenable snmplib debugging messages\n");
  fprintf(stderr,
          "  -M <MIBDIRS>\tuse MIBDIRS as the location to look for mibs.\n");
  fprintf(stderr,
          "  -T <TRANSOPTS> Print one or more MIB symbol reports.\n");
  fprintf(stderr,
          "  \t\tTRANSOPTS values:\n");
  fprintf(stderr,
          "  \t\t    d: Print full details of the given OID.\n");
  fprintf(stderr,
          "  \t\t    p: Print tree format symbol table.\n");
  fprintf(stderr,
          "  \t\t    a: Print ascii format symbol table.\n");
  fprintf(stderr,
          "  \t\t    l: Enable labeled OID report.\n");
  fprintf(stderr,
          "  \t\t    o: Enable OID report.\n");
  fprintf(stderr,
          "  \t\t    s: Enable dotted symbolic report.\n");
  fprintf(stderr,
          "  \t\t    t: Enable alternately formatted symbolic suffix report.\n");
  fprintf(stderr, "  -P <MIBOPTS>\tToggle various defaults controlling mib parsing:\n");
  snmp_mib_toggle_options_usage("\t\t", stderr);
  fprintf(stderr, "  -O <OIDOPTS>\tToggle various defaults controlling oid printing:\n");
  snmp_oid_toggle_options_usage("\t\t", stderr);
  exit(1);
}

int main(int argc, char *argv[])
{
    int	arg;
    char *current_name = NULL, *cp;
    oid name[MAX_OID_LEN];
    size_t name_length;
    int description = 0;
    int print = 0;
    int find_best = 0;
    char n_opt[] = "n";
    
    /*
     * usage: snmptranslate name
     */
    snmp_oid_toggle_options(n_opt);
    while ((arg = getopt(argc, argv, "VhndRrwWbpafsSm:M:D:P:tT:O:")) != EOF){
	switch(arg) {
	case 'h':
	    usage();
            exit(1);
	case 'b':
            find_best = 1;
            break;
	case 'n':
	    fprintf(stderr, "Warning: -n option is deprecated - use -On\n");
	    snmp_oid_toggle_options(n_opt);
	    break;	     
	case 'd':
	    fprintf(stderr, "Warning: -d option is deprecated - use -Td\n");
	    description = 1;
	    snmp_set_save_descriptions(1);
	    break;
	case 'r':
	case 'R':
	    fprintf(stderr, "Warning: -%c option is deprecated - use -OR\n", arg);
	    snmp_set_random_access(1);
	    break;
        case 'w':
	    fprintf(stderr, "Warning: -w option is deprecated - use -Pw\n");
            snmp_set_mib_warnings(1);
            break;
        case 'W':
	    fprintf(stderr, "Warning: -W option is deprecated - use -PW\n");
            snmp_set_mib_warnings(2);
            break;
        case 'p':
	    fprintf(stderr, "Warning: -p option is deprecated - use -Tp\n");
            print = 1;
            break;
        case 'a':
	    fprintf(stderr, "Warning: -a option is deprecated - use -Ta\n");
            print = 2;
            break;
	case 'f':
	    fprintf(stderr, "Warning: -f option is deprecated - use -Of\n");
	    snmp_set_full_objid(1);
	    break;
	case 's':
	    fprintf(stderr, "Warning: -s option is deprecated - use -Os\n");
	    snmp_set_suffix_only(1);
	    break;
	case 'S':
	    fprintf(stderr, "Warning: -S option is deprecated - use -OS\n");
	    snmp_set_suffix_only(2);
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
	    break;
	case 't':
	    fprintf(stderr, "Warning: this option is deprecated - use -Tt\n");
            print = 3;
            print_oid_report_enable_suffix();
            break;
        case 'T':
            for(cp = optarg; *cp; cp++)
            {
                switch(*cp)
                {
                  case 'l':
		    print = 3;
                    print_oid_report_enable_labeledoid();
                    break;
                  case 'o':
		    print = 3;
                    print_oid_report_enable_oid();
                    break;
                  case 's':
		    print = 3;
                    print_oid_report_enable_symbolic();
                    break;
                  case 't':
		    print = 3;
                    print_oid_report_enable_suffix();
                    break;
		  case 'd':
		    description = 1;
		    snmp_set_save_descriptions(1);
		    break;
		  case 'p':
		    print = 1;
		    break;
		  case 'a':
		    print = 2;
		    break;
                  default:
                    fprintf(stderr,"Invalid -T<lostpad> character: %c\n", *cp);
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
    if (current_name == NULL) {
        switch (print) {
        case 1:
            print_mib_tree (stdout, get_tree_head());
            break;
        case 2:
            print_ascii_dump (stdout);
            break;
        case 3:
            print_oid_report (stdout);
            break;
        }
        exit (0);
    }

    name_length = MAX_OID_LEN;
    if (snmp_get_random_access()){
	if (!get_node(current_name, name, &name_length)){
	    fprintf(stderr, "Unknown object identifier: %s\n", current_name);
	    exit(2);
	}
    } else if (find_best) {
        if (0 == get_wild_node(current_name, name, &name_length)) {
            fprintf(stderr, "Unable to find a matching object identifier for \"%s\"\n",
                   current_name);
            exit(1);
        }
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

    print_objid(name, name_length);
    if (description){
	print_description(name, name_length);
    }
    return (0);
}
