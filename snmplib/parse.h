/***********************************************************
        Copyright 1989 by Carnegie Mellon University

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
 * parse.h
 */

#define MAXLABEL        64      /* maximum characters in a label */
#define MAXTOKEN        128     /* maximum characters in a token */
#define MAXQUOTESTR     4096    /* maximum characters in a quoted string */

struct variable_list;

/*
 * A linked list of tag-value pairs for enumerated integers.
 */
struct enum_list {
    struct enum_list *next;
    int value;
    char *label;
};

/*
 * A linked list of nodes.
 */
struct node {
    struct node *next;
    char *label;                /* This node's (unique) textual name */
    u_long  subid;              /* This node's integer subidentifier */
    int     modid;              /* The module containing this node */
    char *parent;               /* The parent's textual name */
    int tc_index;               /* index into tclist (-1 if NA) */
    int type;                   /* The type of object this represents */
    int access;
    int status;
    struct enum_list *enums;    /* (optional) list of enumerated integers */
    char *hint;
    char *units;
    char *description;          /* description (a quoted string) */
};

/*
 * A tree in the format of the tree structure of the MIB.
 */
struct tree {
    struct tree *child_list;    /* list of children of this node */
    struct tree *next_peer;     /* Next node in list of peers */
    struct tree *next;          /* Next node in hashed list of names */
    struct tree *parent;
    char *label;                /* This node's textual name */
    u_long subid;               /* This node's integer subidentifier */
    int     modid;              /* The module containing this node */
    int     number_modules;
    int    *module_list;        /* To handle multiple modules */
    int tc_index;               /* index into tclist (-1 if NA) */
    int type;                   /* This node's object type */
    int access;			/* This nodes access */
    int status;			/* This nodes status */
    struct enum_list *enums;    /* (optional) list of enumerated integers */
    char *hint;
    char *units;
    void (*printer) __P((char *, struct variable_list *, struct enum_list *,
                         char *, char *));	/* Value printing function */
    char *description;          /* description (a quoted string) */
};

/*
 * Information held about each MIB module
 */
struct module_import {
    char *label;                /* The descriptor being imported */
    int   modid;                /* The module imported from */
};
struct module {
    char *name;                 /* This module's name */
    char *file;                 /* The file containing the module */
    struct module_import *imports;  /* List of descriptors being imported */
    int  no_imports;            /* The number of such import descriptors */
                     /* -1 implies the module hasn't been read in yet */
    int   modid;                /* The index number of this module */
    struct module *next;        /* Linked list pointer */
};

struct module_compatability {
    char *old_module;
    char *new_module;
    char *tag;		/* NULL implies unconditional replacement,
				otherwise node identifier or prefix */
    int   tag_len;	/* 0 implies exact match (or unconditional) */
    struct module_compatability *next;	/* linked list */
};


/* non-aggregate types for tree end nodes */
#define TYPE_OTHER          0
#define TYPE_OBJID          1
#define TYPE_OCTETSTR       2
#define TYPE_INTEGER        3
#define TYPE_NETADDR        4
#define TYPE_IPADDR         5
#define TYPE_COUNTER        6
#define TYPE_GAUGE          7
#define TYPE_TIMETICKS      8
#define TYPE_OPAQUE         9
#define TYPE_NULL           10
#define TYPE_COUNTER64      11
#define TYPE_BITSTRING      12
#define TYPE_NSAPADDRESS    13
#define TYPE_UINTEGER       14

#define ACCESS_READONLY    18
#define ACCESS_READWRITE   19
#define	ACCESS_WRITEONLY   20
#define ACCESS_NOACCESS    21
#define ACCESS_NOTIFY      67
#define ACCESS_CREATE      48

#define STATUS_MANDATORY   23
#define STATUS_OPTIONAL    24
#define STATUS_OBSOLETE    25
#define STATUS_DEPRECATED  39


#define	ANON	"anonymous#"
#define	ANON_LEN  strlen(ANON)

struct tree *read_module __P((char *));
struct tree *read_mib __P((char *));
struct tree *read_all_mibs __P((void));
int  add_mibdir __P((char *));
void add_module_replacement __P(( char *, char *, char *, int));
void print_subtree __P((FILE *, struct tree *, int));
void print_ascii_dump_tree __P((FILE *, struct tree *, int));
 /* backwards compatability */
struct tree *find_node __P((char *, struct tree*));
