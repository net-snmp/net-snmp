#ifndef MIB_H
#define MIB_H

#ifdef __cplusplus
extern "C" {
#endif
/*
 * mib.h - Definitions for the variables as defined in the MIB
 *
 * Update: 1998-07-17 <jhy@gsu.edu>
 * Added prototypes for print_oid_report* functions.
 */
/***********************************************************
	Copyright 1988, 1989 by Carnegie Mellon University

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

#include <stdio.h> /* for FILE */

#define MIB 1, 3, 6, 1, 2, 1

#define MIB_IFTYPE_OTHER		    1
#define MIB_IFTYPE_REGULAR1822		    2
#define MIB_IFTYPE_HDH1822		    3
#define MIB_IFTYPE_DDNX25		    4
#define MIB_IFTYPE_RFC877X25		    5
#define MIB_IFTYPE_ETHERNETCSMACD	    6
#define MIB_IFTYPE_ISO88023CSMACD	    7
#define MIB_IFTYPE_ISO88024TOKENBUS	    8
#define MIB_IFTYPE_ISO88025TOKENRING	    9
#define MIB_IFTYPE_ISO88026MAN		    10
#define MIB_IFTYPE_STARLAN		    11
#define MIB_IFTYPE_PROTEON10MBIT	    12
#define MIB_IFTYPE_PROTEON80MBIT	    13
#define MIB_IFTYPE_HYPERCHANNEL		    14
#define MIB_IFTYPE_FDDI			    15
#define MIB_IFTYPE_LAPB			    16
#define MIB_IFTYPE_SDLC			    17
#define MIB_IFTYPE_T1CARRIER		    18
#define MIB_IFTYPE_CEPT			    19
#define MIB_IFTYPE_BASICISDN		    20
#define MIB_IFTYPE_PRIMARYISDN		    21
#define MIB_IFTYPE_PROPPOINTTOPOINTSERIAL   22

#define MIB_IFSTATUS_UP		1
#define MIB_IFSTATUS_DOWN	2
#define MIB_IFSTATUS_TESTING	3

#define MIB_FORWARD_GATEWAY	1
#define MIB_FORWARD_HOST	2

#define MIB_IPROUTETYPE_OTHER	1
#define MIB_IPROUTETYPE_INVALID	2
#define MIB_IPROUTETYPE_DIRECT	3
#define MIB_IPROUTETYPE_REMOTE	4

#define MIB_IPROUTEPROTO_OTHER	    1
#define MIB_IPROUTEPROTO_LOCAL	    2
#define MIB_IPROUTEPROTO_NETMGMT    3
#define MIB_IPROUTEPROTO_ICMP	    4
#define MIB_IPROUTEPROTO_EGP	    5
#define MIB_IPROUTEPROTO_GGP	    6
#define MIB_IPROUTEPROTO_HELLO	    7
#define MIB_IPROUTEPROTO_RIP	    8
#define MIB_IPROUTEPROTO_ISIS	    9
#define MIB_IPROUTEPROTO_ESIS	    10
#define MIB_IPROUTEPROTO_CISCOIGRP  11
#define MIB_IPROUTEPROTO_BBNSPFIGP  12
#define MIB_IPROUTEPROTO_OIGP	    13

#define MIB_TCPRTOALG_OTHER	1
#define MIB_TCPRTOALG_CONSTANT	2
#define MIB_TCPRTOALG_RSRE	3
#define MIB_TCPRTOALG_VANJ	4

#define MIB_TCPCONNSTATE_CLOSED		1
#define MIB_TCPCONNSTATE_LISTEN		2
#define MIB_TCPCONNSTATE_SYNSENT	3
#define MIB_TCPCONNSTATE_SYNRECEIVED	4
#define MIB_TCPCONNSTATE_ESTABLISHED	5
#define MIB_TCPCONNSTATE_FINWAIT1	6
#define MIB_TCPCONNSTATE_FINWAIT2	7
#define MIB_TCPCONNSTATE_CLOSEWAIT	8
#define MIB_TCPCONNSTATE_LASTACK	9
#define MIB_TCPCONNSTATE_CLOSING	10
#define MIB_TCPCONNSTATE_TIMEWAIT	11

#define MIB_EGPNEIGHSTATE_IDLE		1
#define MIB_EGPNEIGHSTATE_AQUISITION	2
#define MIB_EGPNEIGHSTATE_DOWN		3
#define MIB_EGPNEIGHSTATE_UP		4
#define MIB_EGPNEIGHSTATE_CEASE		5

struct variable_list;
struct enum_list;

void print_mib (FILE *);
void print_ascii_dump (FILE *);
int read_objid (const char *, oid *, size_t *);
void register_mib_handlers (void);
void init_mib (void);
void shutdown_mib (void);
void print_variable (const oid *, size_t, struct variable_list *);
void fprint_variable (FILE *, const oid *, size_t, struct variable_list *);
void sprint_variable (char *, const oid *, size_t, struct variable_list *);

int sprint_realloc_variable(u_char **buf, size_t *buf_len,
			    size_t *out_len, int allow_realloc,
			    const oid *objid, size_t objidlen,
			    struct variable_list *variable);

int sprint_realloc_objid   (u_char **buf, size_t *buf_len,
			    size_t *out_len, int allow_realloc, 
			    const oid *objid, size_t objidlen);

int
sprint_realloc_by_type(u_char **buf, size_t *buf_len, size_t *out_len,
		       int allow_realloc,
		       struct variable_list *var,
		       struct enum_list *enums,
		       const char *hint,
		       const char *units);

void print_value (oid *, size_t, struct variable_list *);
void fprint_value (FILE *, oid *, size_t, struct variable_list *);
void sprint_value (char *, oid *, size_t, struct variable_list *);
void print_objid (oid *, size_t);
void fprint_objid (FILE *, oid *, size_t);
char *sprint_objid (char *, oid *, size_t);
void print_description (oid *, size_t, int);
void fprint_description (FILE *, oid *, size_t, int);
int get_module_node (const char *, const char *, oid *, size_t *);
int get_wild_node(const char *, oid *, size_t *);
int get_node (const char *, oid *, size_t *);
oid *snmp_parse_oid (const char *,oid *,size_t *);
struct tree *get_symbol (oid *, size_t, struct tree *, char *);
struct tree *get_tree (oid *, size_t, struct tree *);
struct tree *get_tree_head (void);
void  set_function (struct tree *);

void sprint_hexstring (char *, const u_char *, size_t);
void sprint_asciistring(char *buf, const u_char *cp, size_t len);

void sprint_by_type (char *, struct variable_list *, struct enum_list *,
                     const char *, const char *);
void sprint_octet_string (char *, struct variable_list *, struct enum_list *,
                          const char *, const char *);
void sprint_opaque (char *, struct variable_list *, struct enum_list *,
                    const char *, const char *);
void sprint_object_identifier (char *, struct variable_list *,
                               struct enum_list *, const char *, const char *);
void sprint_timeticks (char *, struct variable_list *, struct enum_list *,
                       const char *, const char *);
void sprint_hinted_integer (char *, long, const char *, const char *);
void sprint_integer (char *, struct variable_list *, struct enum_list *,
                     const char *, const char *);
void sprint_uinteger (char *, struct variable_list *, struct enum_list *,
                      const char *, const char *);
void sprint_gauge (char *, struct variable_list *, struct enum_list *,
                   const char *, const char *);
void sprint_counter (char *, struct variable_list *, struct enum_list *,
                     const char *, const char *);
void sprint_networkaddress (char *, struct variable_list *,
                            struct enum_list *, const char *, const char *);
void sprint_ipaddress (char *, struct variable_list *, struct enum_list *,
                       const char *, const char *);
void sprint_null (char *, struct variable_list *, struct enum_list *,
                  const char *, const char *);
void sprint_bitstring (char *, struct variable_list *, struct enum_list *,
                       const char *, const char *);
void sprint_nsapaddress (char *, struct variable_list *, struct enum_list *,
                         const char *, const char *);
void sprint_counter64 (char *, struct variable_list *, struct enum_list *,
                       const char *, const char *);
void sprint_unknowntype (char *, struct variable_list *, struct enum_list *,
                         const char *, const char *);
void sprint_badtype (char *, struct variable_list *, struct enum_list *,
                     const char *, const char *);
#ifdef OPAQUE_SPECIAL_TYPES
void sprint_float (char *, struct variable_list *, struct enum_list *,
                   const char *, const char *);
void sprint_double (char *, struct variable_list *, struct enum_list *,
                    const char *, const char *);
#endif

int parse_one_oid_index(oid **oidStart, size_t *oidLen,
						struct variable_list *data, int complete);
int parse_oid_indexes(oid *oidIndex, size_t oidLen, struct variable_list *data);
int build_oid_noalloc(oid *in, size_t in_len, size_t *out_len,
											oid *prefix, size_t prefix_len,
											struct variable_list *indexes);
int build_oid(oid **out, size_t *out_len, oid *prefix, size_t prefix_len,
              struct variable_list *indexes);
int build_oid_segment(struct variable_list *var);
    
int sprint_realloc_hexstring	(u_char **buf, size_t *buf_len,
				 size_t *out_len, int allow_realloc,
				 const u_char *, size_t);

int sprint_realloc_asciistring	(u_char **buf, size_t *buf_len,
				 size_t *out_len, int allow_realloc,
				 const u_char *cp, size_t len);

int sprint_realloc_by_type	(u_char **buf, size_t *buf_len,
				 size_t *out_len, int allow_realloc,
				 struct variable_list *, struct enum_list *,
				 const char *, const char *);

int sprint_realloc_octet_string (u_char **buf, size_t *buf_len,
				 size_t *out_len, int allow_realloc,
				 struct variable_list *, struct enum_list *,
				 const char *, const char *);

int sprint_realloc_opaque	(u_char **buf, size_t *buf_len,
				 size_t *out_len, int allow_realloc,
				 struct variable_list *, struct enum_list *,
				 const char *, const char *);

int sprint_realloc_object_identifier(u_char **buf, size_t *buf_len,
				 size_t *out_len, int allow_realloc,
				 struct variable_list *, struct enum_list *,
				 const char *, const char *);

int sprint_realloc_timeticks	(u_char **buf, size_t *buf_len,
				 size_t *out_len, int allow_realloc,
				 struct variable_list *, struct enum_list *,
				 const char *, const char *);

int sprint_realloc_hinted_integer(u_char **buf, size_t *buf_len,
				  size_t *out_len, int allow_realloc,
				  long, const char, const char *,const char *);

int sprint_realloc_integer	(u_char **buf, size_t *buf_len,
				 size_t *out_len, int allow_realloc,
				 struct variable_list *, struct enum_list *,
				 const char *, const char *);

int sprint_realloc_uinteger	(u_char **buf, size_t *buf_len,
				 size_t *out_len, int allow_realloc,
				 struct variable_list *, struct enum_list *,
				 const char *, const char *);

int sprint_realloc_gauge	(u_char **buf, size_t *buf_len,
				 size_t *out_len, int allow_realloc,
				 struct variable_list *, struct enum_list *,
				 const char *, const char *);

int sprint_realloc_counter	(u_char **buf, size_t *buf_len,
				 size_t *out_len, int allow_realloc,
				 struct variable_list *, struct enum_list *,
				 const char *, const char *);

int sprint_realloc_networkaddress(u_char **buf, size_t *buf_len,
				 size_t *out_len, int allow_realloc,
				 struct variable_list *, struct enum_list *,
				 const char *, const char *);

int sprint_realloc_ipaddress	(u_char **buf, size_t *buf_len,
				 size_t *out_len, int allow_realloc,
				 struct variable_list *, struct enum_list *,
				 const char *, const char *);

int sprint_realloc_null 	(u_char **buf, size_t *buf_len,
				 size_t *out_len, int allow_realloc,
				 struct variable_list *, struct enum_list *,
				 const char *, const char *);

int sprint_realloc_bitstring	(u_char **buf, size_t *buf_len,
				 size_t *out_len, int allow_realloc,
				 struct variable_list *, struct enum_list *,
				 const char *, const char *);

int sprint_realloc_nsapaddress	(u_char **buf, size_t *buf_len,
				 size_t *out_len, int allow_realloc,
				 struct variable_list *, struct enum_list *,
				 const char *, const char *);

int sprint_realloc_counter64	(u_char **buf, size_t *buf_len,
				 size_t *out_len, int allow_realloc,
				 struct variable_list *, struct enum_list *,
				 const char *, const char *);

int sprint_realloc_badtype	(u_char **buf, size_t *buf_len,
				 size_t *out_len, int allow_realloc,
				 struct variable_list *, struct enum_list *,
				 const char *, const char *);

#ifdef OPAQUE_SPECIAL_TYPES
int sprint_realloc_float	(u_char **buf, size_t *buf_len,
				 size_t *out_len, int allow_realloc,
				 struct variable_list *, struct enum_list *,
				 const char *, const char *);

int sprint_realloc_double	(u_char **buf, size_t *buf_len,
				 size_t *out_len, int allow_realloc,
				 struct variable_list *, struct enum_list *,
				 const char *, const char *);
#endif

void print_oid_report (FILE *);
void print_oid_report_enable_labeledoid (void);
void print_oid_report_enable_oid (void);
void print_oid_report_enable_suffix (void);
void print_oid_report_enable_symbolic (void);

void clear_tree_flags(register struct tree *tp);

char *snmp_out_toggle_options(char *);
void snmp_out_toggle_options_usage(const char *, FILE *);
char *snmp_in_toggle_options(char *);
void snmp_in_toggle_options_usage(const char *, FILE *);
u_char mib_to_asn_type(int mib_type);


int netsnmp_str2oid( const char * S, oid * O, int L );

#ifdef __cplusplus
}
#endif

#endif /* MIB_H */
