/******************************************************************
        Copyright 1989, 1991, 1992 by Carnegie Mellon University

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
 * parse.c
 */
#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>

/* Wow.  This is ugly.  -- Wes */
#if HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif
#if HAVE_WINSOCK_H
#include <winsock.h>
#endif

#include "system.h"
#include "parse.h"

/* A quoted string value-- too long for a general "token" */
char quoted_string_buffer[MAXQUOTESTR];

/*
 * This is one element of an object identifier with either an integer
 * subidentifier, or a textual string label, or both.
 * The subid is -1 if not present, and label is NULL if not present.
 */
struct subid {
    int subid;
    int modid;
    char *label;
};

#define MAXTC   256
struct tc {     /* textual conventions */
    int type;
    int modid;
    char *descriptor;
    char *hint;
    struct enum_list *enums;
} tclist[MAXTC];



int Line = 1;
char File[300];
int save_mib_descriptions = 0;
int mib_warnings = 0;
static int anonymous = 0;

#define SYNTAX_MASK     0x80
/* types of tokens
 Tokens wiht the SYNTAX_MASK bit set are syntax tokens */
#define CONTINUE    -1
#define ENDOFFILE   0
#define LABEL       1
#define SUBTREE     2
#define SYNTAX      3
#define OBJID       (4 | SYNTAX_MASK)
#define OCTETSTR    (5 | SYNTAX_MASK)
#define INTEGER     (6 | SYNTAX_MASK)
#define INTEGER32   INTEGER
#define NETADDR     (7 | SYNTAX_MASK)
#define IPADDR      (8 | SYNTAX_MASK)
#define COUNTER     (9 | SYNTAX_MASK)
#define GAUGE       (10 | SYNTAX_MASK)
#define TIMETICKS   (11 | SYNTAX_MASK)
#define KW_OPAQUE   (12 | SYNTAX_MASK)
#define NUL         (13 | SYNTAX_MASK)
#define SEQUENCE    14
#define OF          15  /* SEQUENCE OF */
#define OBJTYPE     16
#define ACCESS      17
#define READONLY    18
#define READWRITE   19
#define WRITEONLY   20
#define NOACCESS    21
#define STATUS      22
#define MANDATORY   23
#define KW_OPTIONAL    24
#define OBSOLETE    25
/* #define RECOMMENDED 26 */
#define PUNCT       27
#define EQUALS      28
#define NUMBER      29
#define LEFTBRACKET 30
#define RIGHTBRACKET 31
#define LEFTPAREN   32
#define RIGHTPAREN  33
#define COMMA       34
#define DESCRIPTION 35
#define QUOTESTRING 36
#define INDEX       37
#define DEFVAL      38
#define DEPRECATED  39
#define SIZE        40
#define BITSTRING   (41 | SYNTAX_MASK)
#define NSAPADDRESS (42 | SYNTAX_MASK)
#define COUNTER64   (43 | SYNTAX_MASK)
#define OBJGROUP    44
#define NOTIFTYPE   45
#define AUGMENTS    46
#define COMPLIANCE  47
#define READCREATE  48
#define UNITS       49
#define REFERENCE   50
#define NUM_ENTRIES 51
#define MODULEIDENTITY 52
#define LASTUPDATED 53
#define ORGANIZATION 54
#define CONTACTINFO 55
#define UINTEGER32 (56 | SYNTAX_MASK)
#define CURRENT     57
#define DEFINITIONS 58
#define END         59
#define SEMI        60
#define TRAPTYPE    61
#define ENTERPRISE  62
/* #define DISPLAYSTR (63 | SYNTAX_MASK) */
#define BEGIN       64
#define IMPORTS     65
#define EXPORTS     66
#define ACCNOTIFY   67
#define BAR         68
#define RANGE       69
#define CONVENTION  70
#define DISPLAYHINT 71
#define FROM        72

struct tok {
    char *name;                 /* token name */
    int len;                    /* length not counting nul */
    int token;                  /* value */
    int hash;                   /* hash of name */
    struct tok *next;           /* pointer to next in hash table */
};


struct tok tokens[] = {
    { "obsolete", sizeof ("obsolete")-1, OBSOLETE },
    { "Opaque", sizeof ("Opaque")-1, KW_OPAQUE },
    { "optional", sizeof ("optional")-1, KW_OPTIONAL },
    { "LAST-UPDATED", sizeof ("LAST-UPDATED")-1, LASTUPDATED },
    { "ORGANIZATION", sizeof ("ORGANIZATION")-1, ORGANIZATION },
    { "CONTACT-INFO", sizeof ("CONTACT-INFO")-1, CONTACTINFO },
    { "MODULE-IDENTITY", sizeof ("MODULE-IDENTITY")-1, MODULEIDENTITY },
    { "MODULE-COMPLIANCE", sizeof ("MODULE-COMPLIANCE")-1, COMPLIANCE },
    { "DEFINITIONS", sizeof("DEFINITIONS")-1, DEFINITIONS},
    { "END", sizeof("END")-1, END},
    { ";", sizeof(";")-1, SEMI},
    { "AUGMENTS", sizeof ("AUGMENTS")-1, AUGMENTS },
    { "not-accessible", sizeof ("not-accessible")-1, NOACCESS },
    { "write-only", sizeof ("write-only")-1, WRITEONLY },
    { "NsapAddress", sizeof("NsapAddress")-1, NSAPADDRESS},
    { "UNITS", sizeof("Units")-1, UNITS},
    { "REFERENCE", sizeof("REFERENCE")-1, REFERENCE},
    { "NUM-ENTRIES", sizeof("NUM-ENTRIES")-1, NUM_ENTRIES},
    { "BITSTRING", sizeof("BITSTRING")-1, BITSTRING},
    { "BIT", sizeof("BIT")-1, CONTINUE},
    { "BITS", sizeof("BITS")-1, CONTINUE},
    { "Counter64", sizeof("Counter64")-1, COUNTER64},
    { "TimeTicks", sizeof ("TimeTicks")-1, TIMETICKS },
    { "NOTIFICATION-TYPE", sizeof ("NOTIFICATION-TYPE")-1, NOTIFTYPE },
    { "OBJECT-GROUP", sizeof ("OBJECT-GROUP")-1, OBJGROUP },
    { "OBJECT-IDENTITY", sizeof ("OBJECT-IDENTITY")-1, OBJGROUP },
    { "OBJECTIDENTIFIER", sizeof ("OBJECTIDENTIFIER")-1, OBJID },
    { "OBJECT", sizeof ("OBJECT")-1, CONTINUE },
    { "NetworkAddress", sizeof ("NetworkAddress")-1, NETADDR },
    { "Gauge", sizeof ("Gauge")-1, GAUGE },
    { "Gauge32", sizeof ("Gauge32")-1, GAUGE },
    { "Unsigned32", sizeof ("Unsigned32")-1, GAUGE },
    { "read-write", sizeof ("read-write")-1, READWRITE },
    { "read-create", sizeof ("read-create")-1, READCREATE },
    { "OCTETSTRING", sizeof ("OCTETSTRING")-1, OCTETSTR },
    { "OCTET", sizeof ("OCTET")-1, CONTINUE },
    { "OF", sizeof ("OF")-1, OF },
    { "SEQUENCE", sizeof ("SEQUENCE")-1, SEQUENCE },
    { "NULL", sizeof ("NULL")-1, NUL },
    { "IpAddress", sizeof ("IpAddress")-1, IPADDR },
    { "UInteger32", sizeof ("UInteger32")-1, UINTEGER32 },
    { "INTEGER", sizeof ("INTEGER")-1, INTEGER },
    { "Integer32", sizeof ("Integer32")-1, INTEGER32 },
    { "Counter", sizeof ("Counter")-1, COUNTER },
    { "Counter32", sizeof ("Counter32")-1, COUNTER },
    { "read-only", sizeof ("read-only")-1, READONLY },
    { "DESCRIPTION", sizeof ("DESCRIPTION")-1, DESCRIPTION },
    { "INDEX", sizeof ("INDEX")-1, INDEX },
    { "DEFVAL", sizeof ("DEFVAL")-1, DEFVAL },
    { "deprecated", sizeof ("deprecated")-1, DEPRECATED },
    { "SIZE", sizeof ("SIZE")-1, SIZE },
    { "MAX-ACCESS", sizeof ("MAX-ACCESS")-1, ACCESS },
    { "ACCESS", sizeof ("ACCESS")-1, ACCESS },
    { "mandatory", sizeof ("mandatory")-1, MANDATORY },
    { "current", sizeof ("current")-1, CURRENT },
    { "STATUS", sizeof ("STATUS")-1, STATUS },
    { "SYNTAX", sizeof ("SYNTAX")-1, SYNTAX },
    { "OBJECT-TYPE", sizeof ("OBJECT-TYPE")-1, OBJTYPE },
    { "{", sizeof ("{")-1, LEFTBRACKET },
    { "}", sizeof ("}")-1, RIGHTBRACKET },
    { "::=", sizeof ("::=")-1, EQUALS },
    { "(", sizeof ("(")-1, LEFTPAREN },
    { ")", sizeof (")")-1, RIGHTPAREN },
    { ",", sizeof (",")-1, COMMA },
    { "TRAP-TYPE", sizeof ("TRAP-TYPE")-1, TRAPTYPE },
    { "ENTERPRISE", sizeof ("ENTERPRISE")-1, ENTERPRISE },
    { "BEGIN", sizeof ("BEGIN")-1, BEGIN },
    { "IMPORTS", sizeof ("IMPORTS")-1, IMPORTS },
    { "EXPORTS", sizeof ("EXPORTS")-1, EXPORTS },
    { "accessible-for-notify", sizeof ("accessible-for-notify")-1, ACCNOTIFY },
    { "|", sizeof ("|")-1, BAR },
    { "..", sizeof ("..")-1, RANGE },
    { "TEXTUAL-CONVENTION", sizeof ("TEXTUAL-CONVENTION")-1, CONVENTION },
    { "NOTIFICATION-GROUP", sizeof ("NOTIFICATION-GROUP")-1, NOTIFTYPE },
    { "DISPLAY-HINT", sizeof ("DISPLAY-HINT")-1, DISPLAYHINT },
    { "FROM", sizeof ("FROM")-1, FROM },
    { NULL }
};

struct module_compatability *module_map_head;
struct module_compatability module_map[] = {
	{"RFC1065-SMI",	"RFC1155-SMI",	NULL,	0},
	{"RFC1066-MIB",	"RFC1156-MIB",	NULL,	0},
				/* 'mib' -> 'mib-2' */
	{"RFC1156-MIB",	"RFC1158-MIB",	NULL,	0},
				/* 'snmpEnableAuthTraps' -> 'snmpEnableAuthenTraps' */
	{"RFC1158-MIB",	"RFC1213-MIB",	NULL,	0},
				/* 'nullOID' -> 'zeroDotZero' */
	{"RFC1155-SMI",	"SNMPv2-SMI",	NULL,	0},
	{"RFC1213-MIB",	"SNMPv2-SMI",	"mib-2", 0},
	{"RFC1213-MIB",	"SNMPv2-MIB",	"sys",	3},
	{"RFC1213-MIB",	"IF-MIB",	"if",	2},
	{"RFC1213-MIB",	"IP-MIB",	"ip",	2},
	{"RFC1213-MIB",	"IP-MIB",	"icmp",	4},
	{"RFC1213-MIB",	"TCP-MIB",	"tcp",	3},
	{"RFC1213-MIB",	"UDP-MIB",	"udp",	3},
	{"RFC1213-MIB",	"SNMPv2-SMI",	"tranmission", 0},
	{"RFC1213-MIB",	"SNMPv2-MIB",	"snmp",	4},
	{"RFC1271-MIB",	"RMON-MIB",	NULL,	0},
	{"RFC1286-MIB",	"SOURCE-ROUTING-MIB",	"dot1dSr", 7},
	{"RFC1286-MIB",	"BRIDGE-MIB",	NULL,	0},
	{"RFC1316-MIB",	"CHARACTER-MIB", NULL,	0},
};
#define MODULE_NOT_FOUND	0
#define MODULE_LOADED_OK	1
#define MODULE_ALREADY_LOADED	2
/* #define MODULE_LOAD_FAILED	3 	*/
#define MODULE_LOAD_FAILED	MODULE_NOT_FOUND


#define HASHSIZE        32
#define BUCKET(x)       (x & (HASHSIZE-1))

#define NHASHSIZE    128
#define NBUCKET(x)   (x & (NHASHSIZE-1))

struct tok      *buckets[HASHSIZE];

struct node *nbuckets[NHASHSIZE];
struct tree *tbuckets[NHASHSIZE];
struct node *orphan_nodes = NULL;
struct module *module_head = NULL;
struct tree   *tree_head = NULL;

#define	NUMBER_OF_ROOT_NODES	3
static struct module_import	root_imports[NUMBER_OF_ROOT_NODES];

static int current_module = 0;
static int     max_module = 0;

static void do_subtree __P((struct tree *, struct node **));
static int get_token __P((FILE *, char *,int));
static char last = ' ';
static void unget_token __P((int));
static int parseQuoteString __P((FILE *, char *, int));
static int tossObjectIdentifier __P((FILE *));
       void init_mib_internals __P((void));	/* called from 'mib.c' */
static int  name_hash __P((char *));
static void init_node_hash __P((struct node *));
static void print_rror __P((char *, char *, int));
static void *Malloc __P((unsigned));
static char *Strdup __P((char *));
static void Malloc_stats __P((FILE *));
static void free_tree __P((struct tree *));
static void free_node __P((struct node *));
#ifdef TEST
static void print_nodes __P((FILE *, struct node *));
#endif
static void build_translation_table __P((void));
static void init_tree_roots __P((void));
static void merge_anon_children __P((struct tree *, struct tree *));
static int getoid __P((FILE *, struct subid *, int));
static struct node *parse_objectid __P((FILE *, char *));
static int get_tc __P((char *, int, struct enum_list **, char **));
static int get_tc_index __P((char *, int));
static struct enum_list *parse_enumlist __P((FILE *));
static struct node *parse_asntype __P((FILE *, char *, int *, char *));
static struct node *parse_objecttype __P((FILE *, char *));
static struct node *parse_objectgroup __P((FILE *, char *));
static struct node *parse_notificationDefinition __P((FILE *, char *));
static struct node *parse_trapDefinition __P((FILE *, char *));
static struct node *parse_compliance __P((FILE *, char *));
static struct node *parse_moduleIdentity __P((FILE *, char *));
static        void  parse_imports __P((FILE *));
static struct node *parse __P((FILE *, struct node *));
struct tree *find_node __P((char *, struct tree*)); /* backwards compatability */
static int read_module_internal __P((char *));
static void read_module_replacements __P((char *));
static void read_import_replacements __P((char *, char *));

       int  which_module __P((char *));		/* used by 'mib.c' */
struct tree *find_tree_node __P((char *, int));	/* used by mib.c */
static char *module_name __P((int));
static void  new_module  __P((char *, char *));

extern void  set_function __P((struct tree *));	/* from 'mib.c' */
extern void init_mib __P((void));	/* from mib.c */

static int
name_hash( name )
    char *name;
{
    int hash = 0;
    char *cp;

    for(cp = name; *cp; cp++)
        hash += *cp;
    return(hash);
}
    
void
init_mib_internals __P((void))
{
    register struct tok *tp;
    register int        b, i;
    int			max_modc;

	/*
	 * Set up hash list of pre-defined tokens
	 */
    memset(buckets, 0, sizeof(buckets));
    for (tp = tokens; tp->name; tp++) {
        tp->hash = name_hash( tp->name );
        b = BUCKET(tp->hash);
        if (buckets[b])
            tp->next = buckets[b]; /* BUG ??? */
        buckets[b] = tp;
    }

	/*
	 * Initialise other internal structures
	 */

    max_modc = sizeof(module_map)/sizeof(struct module_compatability);
    for ( i=0 ; i < max_modc-1 ; ++i )
	module_map[i].next = &(module_map[i+1]);
    module_map[max_modc].next = NULL;
    module_map_head = module_map;

    memset(nbuckets, 0, sizeof(nbuckets));
    memset(tbuckets, 0, sizeof(tbuckets));
    memset(tclist, 0, MAXTC * sizeof(struct tc));
    build_translation_table();
    init_tree_roots();	/* Set up initial roots */
		/* Relies on 'add_mibdir' having set up the modules */

}


static void
init_node_hash(nodes)
     struct node *nodes;
{
     register struct node *np, *nextp;
     register int hash;

     for(np = nodes; np;){
         nextp = np->next;
         hash = NBUCKET(name_hash(np->parent));
         np->next = nbuckets[hash];
         nbuckets[hash] = np;
         np = nextp;
     }
}

static void
print_error(string, token, type)
    char *string;
    char *token;
    int type;
{
    DEBUGP("\n");
    if (type == ENDOFFILE)
        fprintf(stderr, "%s(EOF): At line %d in %s\n", string, Line,
                File);
    else if (token)
        fprintf(stderr, "%s(%s): At line %d in %s\n", string, token,
                Line, File);
    else
        fprintf(stderr, "%s: At line %d in %s\n", string, Line, File);
}

static long Malloc_calls = 0;
static long Malloc_bytes = 0;

static void *
Malloc(num)
    unsigned num;
{
    void *p;
    /* this is to fix (what seems to be) a problem with the IBM RT C
library malloc */
#if 0
    if (num < 16)
        num = 16;
#endif
    p = malloc(num);
    if (!p) {
        print_error("Out of memory", NULL, CONTINUE);
        exit (1);
    }
    memset (p, 0, num);
    Malloc_calls++;
    Malloc_bytes += num;
    return p;
}

static char *Strdup (s)
    char *s;
{
    char *ss = (char *) Malloc (strlen (s)+1);
    return strcpy (ss, s);
}

static void Malloc_stats(fp)
    FILE *fp;
{
    fprintf (fp, "Malloc: %ld calls, %ld bytes\n", Malloc_calls, Malloc_bytes);
}

static void
free_tree(Tree)
    struct tree *Tree;
{
    if (Tree == NULL)
    {
        return;
    }

    if (Tree->enums)
    {
        struct enum_list *ep, *tep;

        ep = Tree->enums;
        while(ep)
        {
            tep = ep;
            ep = ep->next;
            if (tep->label)
                free(tep->label);

            free(tep);
        }
    }

    if (Tree->description)
        free(Tree->description);
    if (Tree->label)
        free(Tree->label);

    if (Tree->number_modules > 1 )
        free(Tree->module_list);

    free_tree(Tree->child_list);
    free (Tree);
}

static void
free_node(np)
    struct node *np;
{
    struct enum_list *ep, *tep;

    if (np->tc_index == -1) ep = np->enums;
    else ep = NULL;
    while (ep) {
        tep = ep;
        ep = ep->next;
        if (tep->label)
            free(tep->label);
        free(tep);
    }
    if (np->description)
        free(np->description);
    if (np->label)
        free(np->label);
    if (np->parent)
        free(np->parent);

    free(np);
}

#ifdef TEST
static void
print_nodes(fp, root)
    FILE *fp;
    struct node *root;
{
    struct enum_list *ep;
    struct node *np;

    for(np = root; np; np = np->next){
        fprintf(fp, "%s ::= { %s %ld } (%d)\n", np->label, np->parent,
                np->subid, np->type);
        if (np->tc_index >= 0)
            fprintf(fp, "  TC = %s\n",tclist[np->tc_index].descriptor);
        if (np->enums){
            fprintf(fp, "  Enums: \n");
            for(ep = np->enums; ep; ep = ep->next){
                fprintf(fp, "    %s(%d)\n", ep->label, ep->value);
            }
        }
        if (np->hint)
            fprintf(fp, "  Hint: %s\n", np->hint);
        if (np->units)
            fprintf(fp, "  Units: %s\n", np->units);
    }
}
#endif

void
print_subtree(f, tree, count)
    FILE *f;
    struct tree *tree;
    int count;
{
    struct tree *tp;
    int i;

    for(i = 0; i < count; i++)
        fprintf(f, "  ");
    fprintf(f, "Children of %s(%ld):\n", tree->label, tree->subid);
    count++;
    for(tp = tree->child_list; tp; tp = tp->next_peer){
        for(i = 0; i < count; i++)
            fprintf(f, "  ");
        fprintf(f, "%s(%ld) type=%d",
                tp->label, tp->subid, tp->type);
        if (tp->tc_index != -1) fprintf(f, " tc=%d", tp->tc_index);
        if (tp->hint) fprintf(f, " hint=%s", tp->hint);
        if (tp->units) fprintf(f, " units=%s", tp->units);
	fprintf(f, "\n");
    }
    for(tp = tree->child_list; tp; tp = tp->next_peer){
        if (tp->child_list)
            print_subtree(f, tp, count);
    }
}

void
print_ascii_dump_tree(f, tree, count)
    FILE *f;
    struct tree *tree;
    int count;
{
    struct tree *tp;

/*    fprintf(f, "Children of %s(%ld):\n", tree->label, tree->subid); */
    count++;
    for(tp = tree->child_list; tp; tp = tp->next_peer){
/*        fprintf(f, "%s(%ld) type=%d",
                tp->label, tp->subid, tp->type); */
          fprintf(f, "%s ::= { %s %d }\n", tp->label, tree->label, tp->subid);
/*
        if (tp->tc_index != -1) fprintf(f, " tc=%d", tp->tc_index);
        if (tp->hint) fprintf(f, " hint=%s", tp->hint);
        if (tp->units) fprintf(f, " units=%s", tp->units);
	fprintf(f, "\n");
        */
    }
    for(tp = tree->child_list; tp; tp = tp->next_peer){
        if (tp->child_list)
            print_ascii_dump_tree(f, tp, count);
    }
}

int translation_table[256];

static void
build_translation_table(){
    int count;

    for(count = 0; count < 256; count++){
        switch(count){
            case OBJID:
                translation_table[count] = TYPE_OBJID;
                break;
            case OCTETSTR:
                translation_table[count] = TYPE_OCTETSTR;
                break;
            case INTEGER:
                translation_table[count] = TYPE_INTEGER;
                break;
            case NETADDR:
                translation_table[count] = TYPE_IPADDR;
                break;
            case IPADDR:
                translation_table[count] = TYPE_IPADDR;
                break;
            case COUNTER:
                translation_table[count] = TYPE_COUNTER;
                break;
            case GAUGE:
                translation_table[count] = TYPE_GAUGE;
                break;
            case TIMETICKS:
                translation_table[count] = TYPE_TIMETICKS;
                break;
            case KW_OPAQUE:
                translation_table[count] = TYPE_OPAQUE;
                break;
            case NUL:
                translation_table[count] = TYPE_NULL;
                break;
            case COUNTER64:
                translation_table[count] = TYPE_COUNTER64;
                break;
            case BITSTRING:
                translation_table[count] = TYPE_BITSTRING;
                break;
            case NSAPADDRESS:
                translation_table[count] = TYPE_NSAPADDRESS;
                break;
            case UINTEGER32:
                translation_table[count] = TYPE_UINTEGER;
                break;
            default:
                translation_table[count] = TYPE_OTHER;
                break;
        }
    }
}

static void
init_tree_roots()
{
    struct tree *tp, *lasttp;
    int  base_modid;
    int  hash;

    base_modid = which_module("SNMPv2-SMI");
    if (base_modid == -1 )
        base_modid = which_module("RFC1155-SMI");
    if (base_modid == -1 )
        base_modid = which_module("RFC1213-MIB");

    /* build root node */
    tp = (struct tree *) Malloc(sizeof(struct tree));
    tp->parent = NULL;
    tp->next_peer = NULL;
    tp->child_list = NULL;
    tp->enums = NULL;
    tp->hint = NULL;
    tp->label = Strdup("joint-iso-ccitt");
    tp->modid = base_modid;
    tp->number_modules = 1;
    tp->module_list = &(tp->modid);
    tp->subid = 2;
    tp->tc_index = -1;
    tp->type = 0;
    tp->description = NULL;
    set_function(tp);		/* from mib.c */
    hash = NBUCKET(name_hash(tp->label));
    tp->next = tbuckets[hash];
    tbuckets[hash] = tp;
    lasttp = tp;
    root_imports[0].label = Strdup( tp->label );
    root_imports[0].modid = base_modid;

    /* build root node */
    tp = (struct tree *) Malloc(sizeof(struct tree));
    tp->parent = NULL;
    tp->next_peer = lasttp;
    tp->child_list = NULL;
    tp->enums = NULL;
    tp->hint = NULL;
    tp->label = Strdup("ccitt");
    tp->modid = base_modid;
    tp->number_modules = 1;
    tp->module_list = &(tp->modid);
    tp->subid = 0;
    tp->tc_index = -1;
    tp->type = 0;
    tp->description = NULL;
    set_function(tp);		/* from mib.c */
    hash = NBUCKET(name_hash(tp->label));
    tp->next = tbuckets[hash];
    tbuckets[hash] = tp;
    lasttp = tp;
    root_imports[1].label = Strdup( tp->label );
    root_imports[1].modid = base_modid;

    /* build root node */
    tp = (struct tree *) Malloc(sizeof(struct tree));
    tp->parent = NULL;
    tp->next_peer = lasttp;
    tp->child_list = NULL;
    tp->enums = NULL;
    tp->hint = NULL;
    tp->modid = base_modid;
    tp->number_modules = 1;
    tp->module_list = &(tp->modid);
    tp->label = Strdup("iso");
    tp->subid = 1;
    tp->tc_index = -1;
    tp->type = 0;
    tp->description = NULL;
    set_function(tp);		/* from mib.c */
    hash = NBUCKET(name_hash(tp->label));
    tp->next = tbuckets[hash];
    tbuckets[hash] = tp;
    root_imports[2].label = Strdup( tp->label );
    root_imports[2].modid = base_modid;

    tree_head = tp;

}


struct tree *
find_tree_node( name, modid )
    char *name;
    int   modid;
{
    struct tree *tp, *headtp;
    int count, *int_p;

    headtp = tbuckets[NBUCKET(name_hash(name))];
    for ( tp = headtp ; tp ; tp=tp->next ) {
        if ( !strcmp(tp->label, name) ) {

            if ( modid == -1 )	/* Any module */
                return(tp);

            for (int_p = tp->module_list, count=0 ;
                       count < tp->number_modules ;
                       ++count, ++int_p )
                if ( *int_p == modid )
                    return(tp);
        }
    }

    return(NULL);
}

static void
merge_anon_children( tp1, tp2 )
    struct tree *tp1, *tp2;
		/* NB: tp1 is the 'anonymous' node */
{
    struct tree *child1, *child2, *previous;

    for ( child1 = tp1->child_list ; child1 ; ) {

        for ( child2 = tp2->child_list, previous = NULL ;
              child2 ; previous = child2, child2 = child2->next_peer ) {

            if ( child1->subid == child2->subid ) {
			/*
			 * Found 'matching' children,
			 *  so merge them
			 */
		if ( !strncmp( child1->label, ANON, ANON_LEN)) {
                    merge_anon_children( child1, child2 );

                    previous = child1;		/* Finished with 'child1' */
                    child1 = child1->next_peer;
                    free_tree( previous );
                    break;
                }

		else if ( !strncmp( child2->label, ANON, ANON_LEN)) {
                    merge_anon_children( child2, child1 );

                    if ( previous )
                         previous->next_peer = child2->next_peer;
                    else
                         tp2->child_list = child2->next_peer;
                    free_tree(child2);

                    previous = child1;		/* Move 'child1' to 'tp2' */
                    child1 = child1->next_peer;
                    previous->next_peer = tp2->child_list;
                    tp2->child_list = previous;
                    break;
                }
		else if ( strcmp( child1->label, child2->label) != 0 ) {
	            if (mib_warnings)
		        fprintf (stderr, "Warning: %s.%ld is both %s and %s\n",
			        tp2->label, child1->subid,
                                child1->label, child2->label);
                    continue;
                }
                else {
				/*
				 * Two copies of the same node.
				 * 'child2' adopts the children of 'child1'
				 */

                    if ( child2->child_list ) {
                        for ( previous = child2->child_list ;
                              previous->next_peer ;
                              previous = previous->next_peer )
                                  ;	/* Find the end of the list */
                        previous->next_peer = child1->child_list;
                    }
                    else
                        child2->child_list = child1->child_list;
                    child1->child_list = NULL;

                    previous = child1;		/* Finished with 'child1' */
                    child1 = child1->next_peer;
                    free_tree( previous );
                    break;
                }
            }
        }
		/*
		 * If no match, move 'child1' to 'tp2' child_list
		 */
        if ( child1 ) {
            previous = child1;
            child1 = child1->next_peer;
            previous->next_peer = tp2->child_list;
            tp2->child_list = previous;
        }
    }
}


/*
 * Find all the children of root in the list of nodes.  Link them into the
 * tree and out of the nodes list.
 */
static void
do_subtree(root, nodes)
    struct tree *root;
    struct node **nodes;
{
    register struct tree *tp, *anon_tp=NULL;
    register struct node *np, **headp;
    struct node *oldnp = NULL, *child_list = NULL, *childp = NULL;
    int hash;
    int *int_p;

    tp = root;
    headp = &nbuckets[NBUCKET(name_hash(tp->label))];
    /*
     * Search each of the nodes for one whose parent is root, and
     * move each into a separate list.
     */
    for(np = *headp; np; np = np->next){
        if ( !strcmp(tp->label, np->parent)){
            /* take this node out of the node list */
            if (oldnp == NULL){
                *headp = np->next;  /* fix root of node list */
            } else {
                oldnp->next = np->next; /* link around this node */
            }
            if (child_list) childp->next = np;
            else child_list = np;
            childp = np;
        }
        else {
	    oldnp = np;
        }

    }
    if (childp) childp->next = NULL;
    /*
     * Take each element in the child list and place it into the tree.
     */
    for(np = child_list; np; np = np->next){
        tp = root->child_list;
        while (tp)
            if (tp->subid == np->subid) break;
            else tp = tp->next_peer;
        if (tp) {
	    if (strcmp (tp->label, np->label) == 0) {
		    /* Update list of modules */
                int_p = (int *) Malloc((tp->number_modules+1) * sizeof(int));
                memcpy(int_p, tp->module_list, tp->number_modules*sizeof(int));
                int_p[tp->number_modules] = np->modid;
                if (tp->number_modules > 1 )
                   free(tp->module_list);
                ++tp->number_modules;
                tp->module_list = int_p;
		    /* Handle children */
		do_subtree(tp, nodes);
		continue;
            }
            if (!strncmp( np->label, ANON, ANON_LEN) ||
                !strncmp( tp->label, ANON, ANON_LEN)) {
                anon_tp = tp;	/* Need to merge these two trees later */
            }
	    else if (mib_warnings)
		fprintf (stderr, "Warning: %s.%ld is both %s and %s\n",
			root->label, np->subid, tp->label, np->label);
	}
        tp = (struct tree *) Malloc(sizeof(struct tree));
        tp->parent = root;
        tp->child_list = NULL;
        tp->label = np->label;
        np->label = NULL;
        tp->modid = np->modid;
        tp->number_modules = 1;
        tp->module_list = &(tp->modid);
        tp->subid = np->subid;
        tp->tc_index = np->tc_index;
        tp->type = translation_table[np->type];
        tp->enums = np->enums;
        np->enums = NULL;       /* so we don't free them later */
        tp->hint = np->hint;
	np->hint = NULL;
	tp->units = np->units;
	np->units = NULL;
        tp->description = np->description; /* steals memory from np */
        np->description = NULL; /* so we don't free it later */
	tp->access = np->access;
	tp->status = np->status;
        set_function(tp);	/* from mib.c */
        tp->next_peer = root->child_list;
        root->child_list = tp;
        hash = NBUCKET(name_hash(tp->label));
        tp->next = tbuckets[hash];
        tbuckets[hash] = tp;
/*      if (tp->type == TYPE_OTHER) */
            do_subtree(tp, nodes);      /* recurse on this child if it isn't
                                           an end node */
        if ( anon_tp ) {
            if (!strncmp( tp->label, ANON, ANON_LEN)) {
			/*
			 * The new node is anonymous,
			 *  so merge it with the existing one.
			 */
                merge_anon_children( tp, anon_tp );
            }
            else if (!strncmp( anon_tp->label, ANON, ANON_LEN)) {
			/*
			 * The old node was anonymous,
			 *  so merge it with the existing one,
			 *  and fill in the full information.
			 */
                merge_anon_children( anon_tp, tp );
                anon_tp->label = tp->label;  tp->label=NULL;
                anon_tp->child_list = tp->child_list;  tp->child_list=NULL;
                anon_tp->modid = tp->modid;
                anon_tp->tc_index = tp->tc_index;
                anon_tp->type = tp->type;
                anon_tp->enums = tp->enums;  tp->enums=NULL;
                anon_tp->hint = tp->hint;  tp->hint=NULL;
                anon_tp->description = tp->description;  tp->description=NULL;
                set_function(anon_tp);
            }
            else {
                /* Uh?  One of these two should have been anonymous! */
	        if (mib_warnings)
		    fprintf (stderr, "Warning: expected anonymous node (either %s or %s\n",
			tp->label, anon_tp->label);
            }
		/*
		 * The new node is no longer needed
		 *  so unlink and discard it.
		 */
            root->child_list = tp->next_peer;
            tbuckets[hash] = tp->next;
            free_tree( tp );
            anon_tp = NULL;
        }
    }
    /* free all nodes that were copied into tree */
    oldnp = NULL;
    for(np = child_list; np; np = np->next){
        if (oldnp)
            free_node(oldnp);
        oldnp = np;
    }
    if (oldnp)
        free_node(oldnp);
}


/*
 * Takes a list of the form:
 * { iso org(3) dod(6) 1 }
 * and creates several nodes, one for each parent-child pair.
 * Returns NULL on error.
 */
static int
getoid(fp, id,  length)
    register FILE *fp;
    register struct subid *id; /* an array of subids */
    int length;     /* the length of the array */
{
    register int count;
    int type;
    char token[MAXTOKEN];

    if ((type = get_token(fp, token,MAXTOKEN)) != LEFTBRACKET){
        print_error("Expected \"{\"", token, type);
        return 0;
    }
    type = get_token(fp, token,MAXTOKEN);
    for(count = 0; count < length; count++, id++){
        id->label = NULL;
        id->modid = current_module;
        id->subid = -1;
        if (type == RIGHTBRACKET){
            return count;
        } else if (type != LABEL && type != NUMBER){
            print_error("Not valid for object identifier", token, type);
            return 0;
        }
        if (type == LABEL){
            /* this entry has a label */
            id->label = Strdup(token);
            type = get_token(fp, token,MAXTOKEN);
            if (type == LEFTPAREN){
                type = get_token(fp, token,MAXTOKEN);
                if (type == NUMBER){
                    id->subid = atoi(token);
                    if ((type = get_token(fp, token, MAXTOKEN)) != RIGHTPAREN){
                        print_error("Expected a closing parenthesis",
                                    token, type);
                        return 0;
                    }
                } else {
                    print_error("Expected a number", token, type);
                    return 0;
                }
            } else {
                continue;
            }
        } else {
            /* this entry  has just an integer sub-identifier */
            id->subid = atoi(token);
        }
        type = get_token(fp, token,MAXTOKEN);
    }
    print_error ("Too long OID", token, type);
    return count;


}

/*
 * Parse an entry of the form:
 * label OBJECT IDENTIFIER ::= { parent 2 }
 * The "label OBJECT IDENTIFIER ::=" portion has already been parsed.
 * Returns 0 on error.
 */
static struct node *
parse_objectid(fp, name)
    FILE *fp;
    char *name;
{
    register int count;
    register struct subid *op, *nop;
    int length;
    struct subid oid[32];
    struct node *np, *root, *oldnp = NULL;
    struct tree *tp;

    if ((length = getoid(fp, oid, 32)) != 0){
        np = root = (struct node *) Malloc(sizeof(struct node));
        memset(np, 0, sizeof(struct node));

	/*
	 * Handle numeric-only object identifiers,
	 *  by labelling the first sub-identifier
	 */
        if ( !oid->label )
           for ( tp = tree_head ; tp ; tp=tp->next_peer )
               if ( (int)tp->subid == oid->subid ) {
                   oid->label = Strdup(tp->label);
                   break;
               }

        /*
         * For each parent-child subid pair in the subid array,
         * create a node and link it into the node list.
         */
        for(count = 0, op = oid, nop=oid+1; count < (length - 2); count++,
            op++, nop++){
            /* every node must have parent's name and child's name or number */
            if (op->label && (nop->label || (nop->subid != -1))){
                np->parent = Strdup (op->label);
                if (!nop->label) {
		    nop->label = (char *) Malloc(20);
 		    sprintf(nop->label, "%s%d", ANON, anonymous++);
                }
                np->label = Strdup (nop->label);
                np->modid = nop->modid;
                if (nop->subid != -1)
                    np->subid = nop->subid;
                np->tc_index = -1;
                np->type = 0;
                np->enums = NULL;
                /* set up next entry */
                np->next = (struct node *) Malloc(sizeof(*np->next));
                memset(np->next, 0, sizeof(struct node));
                oldnp = np;
                np = np->next;
            }
        }
        np->next = NULL;
        np->tc_index = -1;
        /*
         * The above loop took care of all but the last pair.  This pair is taken
         * care of here.  The name for this node is taken from the label for this
         * entry.
         * np still points to an unused entry.
         */
        if (count == (length - 2)){
            if (op->label){
                np->parent = Strdup (op->label);
                np->label = Strdup (name);
                np->modid = nop->modid;
                if (nop->subid != -1)
                    np->subid = nop->subid;
                else
                    print_error("Warning: This entry is pretty silly",
                                np->label, CONTINUE);
            } else {
                free_node(np);
                if (oldnp)
                    oldnp->next = NULL;
                else
                    return NULL;
            }
        } else {
            print_error("Missing end of OID", NULL, CONTINUE);
            free_node(np);   /* the last node allocated wasn't used */
            if (oldnp)
                oldnp->next = NULL;
            return NULL;
        }
        /* free the oid array */
        for(count = 0, op = oid; count < length; count++, op++){
            if (op->label)
                free(op->label);
        }
        return root;
    } else {
        print_error("Bad object identifier", NULL, CONTINUE);
        return NULL;
    }
}

static int
get_tc(descriptor, modid, ep, hint)
    char *descriptor;
    int modid;
    struct enum_list **ep;
    char **hint;
{
    int i;
    struct tc *tcp;
    struct module *mp;
    struct module_import *mip;

	/*
	 * Check that the descriptor isn't imported
	 *  by searching the import list
	 */

    for ( mp = module_head ; mp ; mp = mp->next )
         if ( mp->modid == modid )
             break;
    if ( mp )
         for ( i=0, mip=mp->imports ; i < mp->no_imports ; ++i, ++mip ) {
             if ( !strcmp( mip->label, descriptor )) {
				/* Found it - so amend the module ID */
                  modid = mip->modid;
                  break;
             }
         }


    for(i = 0, tcp = tclist; i < MAXTC; i++, tcp++){
        if (tcp->type == 0)
            break;
        if (!strcmp(descriptor, tcp->descriptor) &&
		((modid == tcp->modid) || (modid==-1))){
            *ep = tcp->enums;
	    *hint = tcp->hint;
            return tcp->type;
        }
    }
    return LABEL;
}

/* return index into tclist of given TC descriptor
   return -1 if not found
 */
static int
get_tc_index(descriptor, modid)
    char *descriptor;
    int modid;
{
    int i;
    struct module *mp;
    struct module_import *mip;

	/*
	 * Check that the descriptor isn't imported
	 *  by searching the import list
	 */

    for ( mp = module_head ; mp ; mp = mp->next )
         if ( mp->modid == modid )
             break;
    if ( mp )
         for ( i=0, mip=mp->imports ; i < mp->no_imports ; ++i, ++mip ) {
             if ( !strcmp( mip->label, descriptor )) {
				/* Found it - so amend the module ID */
                  modid = mip->modid;
                  break;
             }
         }


    for(i = 0; i < MAXTC; i++){
      if (tclist[i].type == 0)
          break;
      if (!strcmp(descriptor, tclist[i].descriptor) &&
		((modid == tclist[i].modid) || (modid==-1))){
          return i;
      }
    }
    return -1;
}


/*
 * Parses an enumeration list of the form:
 *        { label(value) label(value) ... }
 * The initial { has already been parsed.
 * Returns NULL on error.
 */

static struct enum_list *
parse_enumlist(fp)
    register FILE *fp;
{
    register int type;
    char token [MAXTOKEN];
    struct enum_list *ep = NULL, *rep;

    while((type = get_token(fp, token,MAXTOKEN)) != ENDOFFILE){
        if (type == RIGHTBRACKET)
            break;
        if (type == LABEL){
            /* this is an enumerated label */
            rep = (struct enum_list *) Malloc(sizeof(struct enum_list));
            rep->next = ep;
            ep = rep;
            /* a reasonable approximation for the length */
            ep->label = Strdup(token);
            type = get_token(fp, token,MAXTOKEN);
            if (type != LEFTPAREN) {
                print_error("Expected \"(\"", token, type);
                return NULL;
            }
            type = get_token(fp, token,MAXTOKEN);
            if (type != NUMBER) {
                print_error("Expected integer", token, type);
                return NULL;
            }
            ep->value = atoi(token);
            type = get_token(fp, token,MAXTOKEN);
            if (type != RIGHTPAREN) {
                print_error("Expected \")\"", token, type);
                return NULL;
            }
        }
    }
    if (type == ENDOFFILE){
        print_error("Expected \"}\"", token, type);
        return NULL;
    }
    return ep;
}

/*
 * Parses an asn type.  Structures are ignored by this parser.
 * Returns NULL on error.
 */
static struct node *
parse_asntype(fp, name, ntype, ntoken)
    FILE *fp;
    char *name;
    int *ntype;
    char *ntoken;
{
    int type, i;
    char token[MAXTOKEN];
    char *hint = NULL;
    char *tmp_hint;
    struct enum_list *ep;
    struct tc *tcp;
    int level;

    type = get_token(fp, token,MAXTOKEN);
    if (type == SEQUENCE){
        while((type = get_token(fp, token, MAXTOKEN)) != ENDOFFILE){
            if (type == RIGHTBRACKET){
                *ntype = get_token(fp, ntoken,MAXTOKEN);
                return NULL;
            }
        }
        print_error("Expected \"}\"", token, type);
        return NULL;
    } else if (type == LEFTBRACKET) {
        struct node *np;
        unget_token (type);
        np = parse_objectid (fp, name);
        if (np != NULL) {
            *ntype = get_token(fp, ntoken, MAXTOKEN);
            return np;
        }
        return NULL;
    } else {
        if (type == CONVENTION) {
            while (type != SYNTAX && type != ENDOFFILE) {
                if (type == DISPLAYHINT) {
                    type = get_token(fp, token, MAXTOKEN);
                    if (type != QUOTESTRING) print_error("DISPLAY-HINT must be string", token, type);
                    else hint = Strdup (token);
                }
                else
		    type = get_token(fp, token, MAXTOKEN);
            }
            type = get_token(fp, token, MAXTOKEN);
        }

        if (type == LABEL)
        {
            type = get_tc(token, current_module, &ep, &tmp_hint);
        }
        
        
        /* textual convention */
        for(i = 0; i < MAXTC; i++){
            if (tclist[i].type == 0)
                break;
        }

        if (i == MAXTC){
            print_error("Too many textual conventions", token, type);
            return NULL;
        }
        tcp = &tclist[i];
        tcp->modid = current_module;
        tcp->descriptor = Strdup(name);
        tcp->hint = hint;
        if (!(type & SYNTAX_MASK)){
            print_error("Textual convention doesn't map to real type", token,
                        type);
            return NULL;
        }
        tcp->type = type;
        *ntype = get_token(fp, ntoken, MAXTOKEN);
        if (*ntype == LEFTPAREN){
            level = 1;
            /* don't record any constraints for now */
            while(level > 0){
                *ntype = get_token(fp, ntoken, MAXTOKEN);
                if (*ntype == LEFTPAREN)
                    level++;
                else if (*ntype == RIGHTPAREN)
                    level--;
                else if (*ntype == ENDOFFILE)
                    break;
            }
            *ntype = get_token(fp, ntoken, MAXTOKEN);
        } else if (*ntype == LEFTBRACKET) {
            /* if there is an enumeration list, parse it */
            tcp->enums = parse_enumlist(fp);
            *ntype = get_token(fp, ntoken, MAXTOKEN);
        }
        return NULL;
    }
}


/*
 * Parses an OBJECT TYPE macro.
 * Returns 0 on error.
 */
static struct node *
parse_objecttype(fp, name)
    register FILE *fp;
    char *name;
{
    register int type;
    char token[MAXTOKEN];
    int nexttype, tctype;
    char nexttoken[MAXTOKEN];
    register struct node *np, *nnp;

    type = get_token(fp, token,MAXTOKEN);
    if (type != SYNTAX){
        print_error("Bad format for OBJECT-TYPE", token, type);
        return NULL;
    }
    np = (struct node *) Malloc(sizeof(struct node));
    np->next = NULL;
    np->tc_index = -1;
    np->enums = NULL;
    np->units = NULL;
    np->description = NULL;        /* default to an empty description */
    type = get_token(fp, token, MAXTOKEN);
    if (type == LABEL){
        tctype = get_tc(token, current_module, &np->enums, &np->hint);
        if (tctype == LABEL && mib_warnings > 1){
            print_error("Warning: No known translation for type", token, type);
        }
        type = tctype;
        np->tc_index = get_tc_index(token, current_module); /* store TC for later reference */
    }
    np->type = type;
    nexttype = get_token(fp, nexttoken,MAXTOKEN);
    switch(type){
        case SEQUENCE:
            if (nexttype == OF){
                nexttype = get_token(fp, nexttoken,MAXTOKEN);
                nexttype = get_token(fp, nexttoken,MAXTOKEN);
            }
            break;
        case INTEGER:
        case UINTEGER32:
        case COUNTER:
        case GAUGE:
            if (nexttype == LEFTBRACKET) {
                /* if there is an enumeration list, parse it */
                np->enums = parse_enumlist(fp);
                nexttype = get_token(fp, nexttoken,MAXTOKEN);
            } else if (nexttype == LEFTPAREN){
		do {
		    nexttype = get_token(fp, nexttoken, MAXTOKEN);
		    nexttype = get_token(fp, nexttoken, MAXTOKEN);
		    if (nexttype == RANGE) {
			nexttype = get_token(fp, nexttoken, MAXTOKEN);
			nexttype = get_token(fp, nexttoken, MAXTOKEN);
		    }
		} while (nexttype == BAR);
		if (nexttype != RIGHTPAREN)
		    print_error ("Expected \")\"", nexttoken, nexttype);
                nexttype = get_token(fp, nexttoken, MAXTOKEN);
            }
            break;
        case BITSTRING:
            if (nexttype == LEFTBRACKET) {
                /* if there is an enumeration list, parse it */
                np->enums = parse_enumlist(fp);
                nexttype = get_token(fp, nexttoken, MAXTOKEN);
            } else if (nexttype == LEFTPAREN){
                /* ignore the "constrained integer" for now */
		do {
		    nexttype = get_token(fp, nexttoken, MAXTOKEN);
		    nexttype = get_token(fp, nexttoken, MAXTOKEN);
		    if (nexttype == RANGE) {
			nexttype = get_token(fp, nexttoken, MAXTOKEN);
			nexttype = get_token(fp, nexttoken, MAXTOKEN);
		    }
		} while (nexttype == BAR);
		if (nexttype != RIGHTPAREN)
		    print_error ("Expected \")\"", nexttoken, nexttype);
		nexttype = get_token (fp, nexttoken, MAXTOKEN);
            }
            break;
        case LABEL:
        case OCTETSTR:
            /* ignore the "constrained octet string" for now */
            if (nexttype == LEFTPAREN) {
                nexttype = get_token(fp, nexttoken,MAXTOKEN);
                if (nexttype == SIZE) {
                    nexttype = get_token(fp, nexttoken,MAXTOKEN);
                    if (nexttype == LEFTPAREN) {
                        do {
                            nexttype = get_token(fp, nexttoken, MAXTOKEN);
                            nexttype = get_token(fp, nexttoken, MAXTOKEN);
                            if (nexttype == RANGE) {
                                nexttype = get_token(fp, nexttoken, MAXTOKEN);
                                nexttype = get_token(fp, nexttoken, MAXTOKEN);
                            }
                        } while (nexttype == BAR);
                        nexttype = get_token(fp, nexttoken,MAXTOKEN); /* ) */
                        if (nexttype == RIGHTPAREN)
                        {
                            nexttype = get_token(fp, nexttoken,MAXTOKEN);
                            break;
                        }
                    }
                }
                print_error("Bad syntax", token, type);
                free_node(np);
                return NULL;
            }
            break;
        case OBJID:
        case NETADDR:
        case IPADDR:
        case TIMETICKS:
        case KW_OPAQUE:
        case NUL:
        case NSAPADDRESS:
        case COUNTER64:
            break;
        default:
            print_error("Bad syntax", token, type);
            free_node(np);
            return NULL;
    }
    if (nexttype == UNITS){
        type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
        if (type != QUOTESTRING) {
            print_error("Bad UNITS", quoted_string_buffer, type);
            free_node(np);
            return NULL;
        }
	np->units = Strdup (quoted_string_buffer);
        nexttype = get_token(fp, nexttoken,MAXTOKEN);
    }
    if (nexttype != ACCESS){
        print_error("Should be ACCESS", nexttoken, nexttype);
        free_node(np);
        return NULL;
    }
    type = get_token(fp, token,MAXTOKEN);
    if (type != READONLY && type != READWRITE && type != WRITEONLY
        && type != NOACCESS && type != READCREATE && type != ACCNOTIFY){
        print_error("Bad ACCESS type", token, type);
        free_node(np);
        return NULL;
    }
    np->access = type;
    type = get_token(fp, token,MAXTOKEN);
    if (type != STATUS){
        print_error("Should be STATUS", token, type);
        free_node(np);
        return NULL;
    }
    type = get_token(fp, token,MAXTOKEN);
    if (type != MANDATORY && type != CURRENT && type != KW_OPTIONAL &&
        type != OBSOLETE && type != DEPRECATED){
        print_error("Bad STATUS", token, type);
        free_node(np);
        return NULL;
    }
    np->status = type;
    /*
     * Optional parts of the OBJECT-TYPE macro
     */
    type = get_token(fp, token,MAXTOKEN);
    while (type != EQUALS && type != ENDOFFILE) {
      switch (type) {
        case DESCRIPTION:
          type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
          if (type != QUOTESTRING) {
              print_error("Bad DESCRIPTION", quoted_string_buffer, type);
              free_node(np);
              return NULL;
          }
          if (save_mib_descriptions) {
              np->description = Strdup (quoted_string_buffer);
          }
          break;

        case REFERENCE:
          type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
          if (type != QUOTESTRING) {
              print_error("Bad REFERENCE", quoted_string_buffer, type);
              free_node(np);
              return NULL;
          }
          break;
        case INDEX:
        case DEFVAL:
        case AUGMENTS:
        case NUM_ENTRIES:
          if (tossObjectIdentifier(fp) != OBJID) {
              print_error("Bad Object Identifier", token, type);
              free_node(np);
              return NULL;
          }
          break;

        default:
          print_error("Bad format of optional clauses", token,type);
          free_node(np);
          return NULL;

      }
      type = get_token(fp, token,MAXTOKEN);
    }
    if (type != EQUALS){
        print_error("Bad format", token, type);
        free_node(np);
        return NULL;
    }
    nnp = parse_objectid (fp, name);
    if (nnp) {
        np->label = nnp->label;
        np->parent = nnp->parent;
        np->next = nnp->next;
        np->modid = nnp->modid;
        np->subid = nnp->subid;
        free(nnp);
    }
    else np = NULL;
    return np;
}


/*
 * Parses an OBJECT GROUP macro.
 * Returns 0 on error.
 *
 * Also parses object-identy, since they are similar (ignore STATUS).
 *   - WJH 10/96
 */
static struct node *
parse_objectgroup(fp, name)
    register FILE *fp;
    char *name;
{
    register int type;
    char token[MAXTOKEN];
    register struct node *np, *nnp;

    np = (struct node *) Malloc(sizeof(struct node));
    np->tc_index = -1;
    np->type = 0;
    np->next = NULL;
    np->enums = NULL;
    np->description = NULL;        /* default to an empty description */
    type = get_token(fp, token,MAXTOKEN);
    while (type != EQUALS && type != ENDOFFILE) {
      switch (type) {
        case DESCRIPTION:
          type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
          if (type != QUOTESTRING) {
              print_error("Bad DESCRIPTION", quoted_string_buffer, type);
              free_node(np);
              return NULL;
          }
#ifdef TEST2
printf("Description== \"%.50s\"\n", quoted_string_buffer);
#endif
          if (save_mib_descriptions) {
              np->description = Strdup (quoted_string_buffer);
          }
          break;

        default:
          /* NOTHING */
          break;
      }
      type = get_token(fp, token,MAXTOKEN);
    }
    nnp = parse_objectid (fp, name);
    if (nnp) {
	np->parent = nnp->parent;
	np->label = nnp->label;
	np->next = nnp->next;
	np->modid = nnp->modid;
	np->subid = nnp->subid;
	free(nnp);
    }
    else np = NULL;
    return np;
}

/*
 * Parses a NOTIFICATION-TYPE macro.
 * Returns 0 on error.
 */
static struct node *
parse_notificationDefinition(fp, name)
    register FILE *fp;
    char *name;
{
    register int type;
    char token[MAXTOKEN];
    register struct node *np, *nnp;

    np = (struct node *) Malloc(sizeof(struct node));
    np->tc_index = -1;
    np->type = 0;
    np->next = NULL;
    np->enums = NULL;
    np->description = NULL;        /* default to an empty description */
    type = get_token(fp, token,MAXTOKEN);
    while (type != EQUALS && type != ENDOFFILE) {
      switch (type) {
        case DESCRIPTION:
          type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
          if (type != QUOTESTRING) {
              print_error("Bad DESCRIPTION", quoted_string_buffer, type);
              free_node(np);
              return NULL;
          }
#ifdef TEST2
printf("Description== \"%.50s\"\n", quoted_string_buffer);
#endif
          if (save_mib_descriptions) {
              np->description = Strdup (quoted_string_buffer);
          }
          break;

        default:
          /* NOTHING */
          break;
      }
      type = get_token(fp, token,MAXTOKEN);
    }
    nnp = parse_objectid (fp, name);
    if (nnp) {
	np->parent = nnp->parent;
	np->label = nnp->label;
	np->next = nnp->next;
	np->modid = nnp->modid;
	np->subid = nnp->subid;
	free(nnp);
    }
    else np = NULL;
    return np;
}

/*
 * Parses a TRAP-TYPE macro.
 * Returns 0 on error.
 */
static struct node *
parse_trapDefinition(fp, name)
    register FILE *fp;
    char *name;
{
    register int type;
    char token[MAXTOKEN];
    register struct node *np;

    np = (struct node *) Malloc(sizeof(struct node));
    np->tc_index = -1;
    np->type = 0;
    np->next = NULL;
    np->enums = NULL;
    np->description = NULL;        /* default to an empty description */
    type = get_token(fp, token, MAXTOKEN);
    while (type != EQUALS && type != ENDOFFILE) {
        switch (type) {
            case DESCRIPTION:
                type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
                if (type != QUOTESTRING) {
                    print_error("Bad DESCRIPTION", quoted_string_buffer, type);
                    free_node(np);
                    return NULL;
                }

#ifdef TEST2
                printf("Description== \"%.50s\"\n", quoted_string_buffer);
#endif
                if (save_mib_descriptions) {
                    np->description = Strdup (quoted_string_buffer);
                }
                break;
            case ENTERPRISE:
                type = get_token(fp, token, MAXTOKEN);
                if (type == LEFTBRACKET) {
                    type = get_token(fp, token, MAXTOKEN);
                    if (type != LABEL) {
                        print_error("Bad Trap Format", token, type);
                        free_node(np);
                        return NULL;
                    }
                    np->parent = Strdup(token);
                    /* Get right bracket */
                    type = get_token(fp, token, MAXTOKEN);
                }
                else if (type == LABEL)
                    np->parent = Strdup(token);
                break;
            default:
                /* NOTHING */
                break;
        }
        type = get_token(fp, token, MAXTOKEN);
    }
    type = get_token(fp, token, MAXTOKEN);

    np->label = Strdup(name);
    
    if (type != NUMBER) {
        print_error("Expected a Number", token, type);
        free_node(np);
        return NULL;
    }
    np->subid = atoi(token);
    return np;
}


/*
 * Parses a compliance macro
 * Returns 0 on error.
 */
static struct node *
parse_compliance(fp, name)
    register FILE *fp;
    char *name;
{
    register int type;
    char token[MAXTOKEN];
    register struct node *np, *nnp;

    np = (struct node *) Malloc(sizeof(struct node));
    np->tc_index = -1;
    np->type = 0;
    np->next = NULL;
    np->enums = NULL;
    np->description = NULL;        /* default to an empty description */
    type = get_token(fp, token,MAXTOKEN);
    while (type != EQUALS && type != ENDOFFILE)
        type = get_token(fp, quoted_string_buffer,MAXQUOTESTR);
    nnp = parse_objectid (fp, name);
    if (nnp) {
	np->parent = nnp->parent;
	np->label = nnp->label;
	np->next = nnp->next;
	np->modid = nnp->modid;
	np->subid = nnp->subid;
	free(nnp);
    }
    else np = NULL;
    return np;
}



/*
 * Parses a module identity macro
 * Returns 0 on error.
 */
static struct node *
parse_moduleIdentity(fp, name)
    register FILE *fp;
    char *name;
{
    register int type;
    char token[MAXTOKEN];
    register struct node *np, *nnp;

    np = (struct node *) Malloc (sizeof (struct node));
    np->tc_index = -1;
    np->type = 0;
    np->next = NULL;
    np->enums = NULL;
    np->description = NULL;        /* default to an empty description */
    type = get_token(fp, token, MAXTOKEN);
    while (type != EQUALS && type != ENDOFFILE) {
        type = get_token(fp, token, MAXTOKEN);
    }
    nnp = parse_objectid(fp, name);
    if (nnp) {
	np->parent = nnp->parent;
	np->label = nnp->label;
	np->subid = nnp->subid;
	np->next = nnp->next;
	free (nnp);
    }
    else np = NULL;
    return np;
}


/*
 * Parses a module import clause
 *   loading any modules referenced
 */
static void
parse_imports(fp)
    register FILE *fp;
{
    register int type;
    char token[MAXTOKEN];
#define MAX_IMPORTS	32
    struct module_import import_list[MAX_IMPORTS];
    int this_module, old_current_module;
    char old_last;
    char *old_File;
    int old_line;
    struct module *mp;

    int import_count=0;		/* Total number of imported descriptors */
    int i=0, old_i;		/* index of first import from each module */

    type = get_token(fp, token, MAXTOKEN);

		/*
		 * Parse the IMPORTS clause
		 */
    while (type != SEMI && type != ENDOFFILE) {
	if (type == LABEL ) {
	    if (import_count == MAX_IMPORTS ) {
		print_error("Too many imported symbols", token, type);
		exit(1);
	    }
	    import_list[import_count++].label = Strdup(token);
	}
	else if ( type == FROM ) {
	    type = get_token(fp, token, MAXTOKEN);
            if ( import_count == i ) {	/* All imports are handled internally */
	       type = get_token(fp, token, MAXTOKEN);
               continue;
            }
	    this_module = which_module(token);

	    for ( old_i=i ; i<import_count ; ++i)
		import_list[i].modid = this_module;

	    old_current_module = current_module;	/* Save state */
	    old_last = last;
            old_File = Strdup( File );
	    old_line = Line;
	    current_module = this_module;
	    last = ' ';

		/*
		 * Recursively read any pre-requisite modules
		 */
	    if  (read_module_internal(token) == MODULE_NOT_FOUND ) {
		for ( ; old_i<import_count ; ++old_i ) {
		    read_import_replacements( token, import_list[old_i].label);
		}
	    }

	    current_module = old_current_module;	/* Restore state */
	    last = old_last;
	    strcpy (File, old_File);
            free( old_File );
	    Line = old_line;
	}
	type = get_token(fp, token, MAXTOKEN);
    }

		/*
		 * Save the import information
		 *   in the global module table
		 */
    for ( mp=module_head ; mp ; mp=mp->next )
	if ( mp->modid == current_module) {
            if ( import_count == 0)
              return;
            mp->imports = (struct module_import *)
              Malloc(import_count*sizeof(struct module_import));
	    for ( i=0 ; i<import_count ; ++i ) {
		mp->imports[i].label = import_list[i].label;
		mp->imports[i].modid = import_list[i].modid;
	    }
	    mp->no_imports = import_count;
	    return;
	}

	/*
	 * Shouldn't get this far
	 */
    print_error("Cannot find module", module_name(current_module), CONTINUE);
    exit(1);
}



/*
 * MIB module handling routines
 */
int
which_module(name)
    char *name;
{
    struct module *mp;

    for ( mp=module_head ; mp ; mp=mp->next )
	if ( !strcmp(mp->name, name))
	    return(mp->modid);

    DEBUGP1("Module %s not found\n", name);
    return(-1);
}

static char *
module_name ( modid )
    int modid;
{
    struct module *mp;
    char *cp;

    for ( mp=module_head ; mp ; mp=mp->next )
	if ( mp->modid == modid )
	    return(mp->name);

    DEBUGP1("Module %d not found\n", modid);
    cp = (char *) Malloc(10);	/* copes with 1e8 modules! */
    sprintf(cp, "#%d", modid);
    return(cp);
}

/*
 *  Backwards compatability
 *  Read newer modules that replace the one specified:-
 *	either all of them (read_module_replacements),
 *	or those relating to a specified identifier (read_import_replacements)
 *	plus an interface to add new replacement requirements
 */
void
add_module_replacement( old, new, tag, len)
    char *old;
    char *new;
    char *tag;
    int len;
{
    struct module_compatability *mcp;

    mcp =  (struct module_compatability *)
      Malloc(sizeof( struct module_compatability));

    mcp->old_module = Strdup( old );
    mcp->new_module = Strdup( new );
    mcp->tag	    = Strdup( tag );
    mcp->tag_len = len;

    mcp->next    = module_map_head;
    module_map_head = mcp;
}

static void
read_module_replacements( name )
    char *name;
{
    struct module_compatability *mcp;

    for ( mcp=module_map_head ; mcp; mcp=mcp->next ) {
      if ( !strcmp( mcp->old_module, name )) {
	if (mib_warnings)
	    fprintf (stderr, "Loading replacement module %s\n", mcp->new_module);
	(void)read_module( mcp->new_module );
      }
    }
}

static void
read_import_replacements( module_name, node_identifier )
    char *module_name;
    char *node_identifier;
{
    struct module_compatability *mcp;

	/*
	 * Look for matches first
	 */
    for ( mcp=module_map_head ; mcp; mcp=mcp->next ) {
      if ( !strcmp( mcp->old_module, module_name )) {

	if (	/* exact match */
	  	  ( mcp->tag_len==0 &&
		    (mcp->tag == NULL ||
                     !strcmp( mcp->tag, node_identifier ))) ||
		/* prefix match */
	          ( mcp->tag_len!=0 && 
		    !strncmp( mcp->tag, node_identifier, mcp->tag_len ))
	   ) {

	    if (mib_warnings)
	        fprintf (stderr, "Loading replacement module %s (for %s)\n",
			mcp->new_module, node_identifier);
	    (void)read_module( mcp->new_module );
	    return;	/* finished! */
        }
      }
    }

	/*
	 * If no exact match, load everything releant
	 */
    read_module_replacements( module_name );
}


/*
 *  Read in the named module
 *	Returns the root of the whole tree
 *	(by analogy with 'read_mib')
 */
static int
read_module_internal (name )
    char *name;
{
    struct module *mp;
    struct module_import *mip;
    FILE *fp;
    struct node *np;
    struct tree *tp;
    int i;

    if ( tree_head == NULL )
	init_mib();

    for ( mp=module_head ; mp ; mp=mp->next )
	if ( !strcmp(mp->name, name)) {
	    if ( mp->no_imports != -1 ) {
		DEBUGP1("Module %s already loaded\n", name);
		return MODULE_ALREADY_LOADED;
	    }
	    if ((fp = fopen(mp->file, "r")) == NULL) {
		perror(mp->file);
		return MODULE_LOAD_FAILED;
	    }
	    mp->no_imports=0;		/* Note that we've read the file */
	    strcpy(File, mp->file);
	    Line = 1;
		/*
		 * Parse the file
		 */
	    np = parse( fp, orphan_nodes );
	    fclose(fp);
#ifdef TEST
	    printf("\nNodes for Module %s:\n", name);
	    print_nodes( stdout, np );
#endif

		/*
		 * All modules implicitly import
		 *   the roots of the tree
		 */
	    if ( mp->no_imports == 0 ) {
		mp->no_imports = NUMBER_OF_ROOT_NODES;
		mp->imports = root_imports;
	    }

		/*
		 * Build the tree
		 */
	    init_node_hash( np );
	    for ( i=0, mip=mp->imports ; i < mp->no_imports ; ++i, ++mip ) {
		if (get_tc_index( mip->label, mip->modid ) != -1)
		    continue;
		tp = find_tree_node( mip->label, mip->modid );
		if (!tp) {
		    fprintf(stderr, "Did not find %s in module %s\n",
			mip->label, module_name(mip->modid));
		    continue;
		}
		do_subtree( tp, &np );
	    }

		/*
		 * If any nodes left over,
		 *   add them to the list of orphans
		 */
	    
	    if (!orphan_nodes) return MODULE_LOADED_OK;
	    for ( np = orphan_nodes ; np->next ; np = np->next )
		;	/* find the end of the orphan list */
	    for (i = 0; i < NHASHSIZE; i++)
		if ( nbuckets[i] ) {
		    if ( np )
			np->next = nbuckets[i];
		    else {
			orphan_nodes = nbuckets[i];
			np = orphan_nodes;
		    }
		    nbuckets[i] = 0;
		    for ( ; np->next ; np = np->next )
			;
		}

	    return MODULE_LOADED_OK;
	}

    fprintf(stderr, "Module %s not found\n", name);
    return MODULE_NOT_FOUND;
}

struct tree *
read_module(name )
    char *name;
{
    if ( read_module_internal(name) == MODULE_NOT_FOUND )
	read_module_replacements( name );
    return tree_head;
}


static void
new_module (name , file)
    char *name;
    char *file;
{
    struct module *mp;

    for ( mp=module_head ; mp ; mp=mp->next )
	if ( !strcmp(mp->name, name)) {
	    DEBUGP1("Module %s already noted\n",name);
			/* Not the same file */
	    if ( strcmp(mp->file, file)) {
                fprintf(stderr, "Warning: Module %s in both %s and %s\n",
			name, mp->file, file);

			/* Use the new one in preference */
		free(mp->file);
                mp->file = Strdup(file);
            }
	    return;
	}

	/* Add this module to the list */
    mp = (struct module *) Malloc(sizeof(struct module));
    mp->name = Strdup(name);
    mp->file = Strdup(file);
    mp->imports = NULL;
    mp->no_imports = -1;	/* Not yet loaded */
    mp->modid = max_module;
    ++max_module;

    mp->next = module_head;	/* Or add to the *end* of the list? */
    module_head = mp;
}




/*
 * Parses a mib file and returns a linked list of nodes found in the file.
 * Returns NULL on error.
 */
static struct node *
parse(fp, root)
    FILE *fp;
    struct node *root;
{
    char token[MAXTOKEN];
    char name[MAXTOKEN];
    int type = LABEL;
    int lasttype = LABEL;

#define BETWEEN_MIBS          1
#define IN_MIB                2
    int state = BETWEEN_MIBS;
    struct node *np, *nnp;

    if (mib_warnings) fprintf (stderr, "Parsing mib file:  %s...\n", File);

    np = root;
    if (np != NULL) {
        /* now find end of chain */
        while(np->next)
            np = np->next;
    }

    while (type != ENDOFFILE){
        if (lasttype == CONTINUE) lasttype = type;
        else type = lasttype = get_token(fp, token,MAXTOKEN);

        switch (type) {
        case END:
            if (state != IN_MIB){
                print_error("Error, END before start of MIB", NULL, type);
                return NULL;
            }
            state = BETWEEN_MIBS;
            if (mib_warnings) Malloc_stats (stderr);
            continue;
        case IMPORTS:
            parse_imports( fp );
            continue;
        case EXPORTS:
            while (type != SEMI && type != ENDOFFILE)
                type = get_token(fp, token, MAXTOKEN);
            continue;
        case LABEL:
            break;
        case ENDOFFILE:
            continue;
        default:
            print_error(token, "is a reserved word", type);
            return NULL;
        }
        strcpy(name, token);
        type = get_token(fp, token, MAXTOKEN);
        nnp = NULL;

	/* Handle obsolete method to assign an object identifier to a 
	   module*/
	if (lasttype == LABEL && type == LEFTBRACKET) {
	    while (type != RIGHTBRACKET && type != ENDOFFILE)
		type = get_token(fp, token, MAXTOKEN);
	    if (type == ENDOFFILE){
		print_error("Expected \"}\"", token, type);
		return NULL;
	    }
	    type = get_token(fp, token, MAXTOKEN);
	}

        switch (type) {
        case DEFINITIONS:
            if (state != BETWEEN_MIBS){
                print_error("Error, nested MIBS", NULL, type);
                return NULL;
            }
            state = IN_MIB;
            if (mib_warnings) fprintf (stderr, "Parsing MIB: %s\n", name);
            current_module = which_module( name );
            while ((type = get_token (fp, token, MAXTOKEN)) != ENDOFFILE)
                if (type == BEGIN) break;
            break;
        case OBJTYPE:
            nnp = parse_objecttype(fp, name);
            if (nnp == NULL){
                print_error("Bad parse of OBJECT-TYPE", NULL, type);
                return NULL;
            }
            break;
        case OBJGROUP:
            nnp = parse_objectgroup(fp, name);
            if (nnp == NULL){
                print_error("Bad parse of OBJECT-GROUP", NULL, type);
                return NULL;
            }
            break;
        case TRAPTYPE:
            nnp = parse_trapDefinition(fp, name);
            if (nnp == NULL){
                print_error("Bad parse of TRAP-TYPE", NULL, type);
                return NULL;
            }
            break;
        case NOTIFTYPE:
            nnp = parse_notificationDefinition(fp, name);
            if (nnp == NULL){
                print_error("Bad parse of NOTIFICATION-TYPE", NULL, type);
                return NULL;
            }
            break;
        case COMPLIANCE:
            nnp = parse_compliance(fp, name);
            if (nnp == NULL){
                print_error("Bad parse of MODULE-COMPLIANCE", NULL, type);
                return NULL;
            }
            break;
        case MODULEIDENTITY:
            nnp = parse_moduleIdentity(fp, name);
            if (nnp == NULL){
                print_error("Bad parse of NODULE-IDENTITY", NULL, type);
                return NULL;
            }
            break;
        case OBJID:
            type = get_token(fp, token, MAXTOKEN);
            if (type != EQUALS){
                print_error("Expected \"::=\"", token, type);
                return NULL;
            }
            nnp = parse_objectid(fp, name);
            if (nnp == NULL){
                print_error("Bad parse of OBJECT IDENTIFIER", NULL, type);
                return NULL;
            }
            break;
        case EQUALS:
            nnp = parse_asntype(fp, name, &type, token);
            lasttype = CONTINUE;
            break;
        case ENDOFFILE:
            break;
        default:
	    print_error("Bad operator", token, type);
	    return NULL;
        }
        if (nnp) {
            if (np) np->next = nnp;
            else np = root = nnp;
            while (np->next) np = np->next;
        }
    }
    return root;
}

/*
 * Parses a token from the file.  The type of the token parsed is returned,
 * and the text is placed in the string pointed to by token.
 */

static int ungotten_token = CONTINUE;

static void unget_token (token)
  int token;
{
    if (ungotten_token != CONTINUE) {
        fprintf (stderr, "Double unget\n");
        exit (1);
    }
    ungotten_token = token;
}

static int
get_token(fp, token,maxtlen)
    register FILE *fp;
    register char *token;
    int maxtlen;
{
    register int ch, ch_next;
    register char *cp = token;
    register int hash = 0;
    register struct tok *tp;
    int too_long = 0;

    if (ungotten_token != CONTINUE) {
        int tok = ungotten_token;
        ungotten_token = CONTINUE;
        return tok;
    }

    *cp = 0;
    ch = last;
    /* skip all white space */
    while(isspace(ch) && ch != EOF){
        ch = getc(fp);
        if (ch == '\n')
            Line++;
    }
    if (ch == EOF) {
        return ENDOFFILE;
    } else if (ch == '"') {
        return parseQuoteString(fp, token, maxtlen);
    }

    /*
     * Accumulate characters until end of token is found.  Then attempt to
     * match this token as a reserved word.  If a match is found, return the
     * type.  Else it is a label. Handle the RANGE token correctly.
     */
    do {
        if (ch == '\n')
            Line++;
	ch_next = getc(fp);
        if (isspace(ch) || ch == '(' || ch == ')' || ch == '{' || ch == '}' ||
            ch == ',' || ch == ';' || ch == '|' || (ch == '.' && ch_next == '.')){
	    if (ch == '.' && ch_next == '.' && *token == 0) {
                hash += ch + ch_next;
                if (cp-token < maxtlen-1)
                    *cp++ = ch;
                else too_long = 1;
                if (cp-token < maxtlen-1)
                    *cp++ = ch_next;
                else too_long = 1;
                last = ' ';
            }
	    else if (!isspace(ch) && *token == 0){
	        ungetc (ch_next, fp);
                hash += ch;
                if (cp-token < maxtlen-1)
                    *cp++ = ch;
                else too_long = 1;
                last = ' ';
            } else {
		ungetc (ch_next, fp);
                last = ch;
            }
            *cp = '\0';

            if (too_long)
                print_error("Warning: token too long", token, CONTINUE);
            for (tp = buckets[BUCKET(hash)]; tp; tp = tp->next) {
                if ((tp->hash == hash) && (strcmp(tp->name, token) == 0))
                        break;
            }
            if (tp){
                if (tp->token == CONTINUE)
                    continue;
                return (tp->token);
            }

            if (token[0] == '-' && token[1] == '-'){
                /* strip comment */
                if (ch != '\n'){
                    while ((ch = getc(fp)) != EOF)
                        if (ch == '\n'){
                            Line++;
                            break;
                        }
                }
                if (ch == EOF)
                    return ENDOFFILE;
                last = ch;
                return get_token(fp, token,maxtlen);
            }
            if ( token[0] == '-' ) {
               for(cp = token+1; *cp; cp++)
                  if (!isdigit(*cp))
                      return LABEL;
               return NUMBER;
            } 

            for(cp = token; *cp; cp++)
                if (!isdigit(*cp))
                    return LABEL;
            return NUMBER;
        }
	else {
	    ungetc (ch_next, fp);
            hash += ch;
            if (cp-token < maxtlen-1)
                *cp++ = ch;
            else too_long = 1;
            if (ch == '\n')
                Line++;
        }

    } while ((ch = getc(fp)) != EOF);
    return ENDOFFILE;
}

int
add_mibdir( dirname )
    char *dirname;
{
    FILE *fp;
    DIR *dir, *dir2;
    struct dirent *file;
    char token[MAXTOKEN];
    char tmpstr[300];
    int count = 0;

    if ((dir = opendir(dirname))) {
        while ((file = readdir(dir))) {
            /* Only parse file names not beginning with a '.' */
            if (file->d_name != NULL && file->d_name[0] != '.') {
                sprintf(tmpstr, "%s/%s", dirname, file->d_name);
                if ((dir2 = opendir(tmpstr))) {
                    /* file is a directory, don't read it */
                    closedir(dir2);
                } else {
                    /* which module is this */
                    if ((fp = fopen(tmpstr, "r")) == NULL) {
                        perror(tmpstr);
			continue;
                    }
                    DEBUGP1("Adding %s...",tmpstr);
                    Line = 1;
                    strcpy(File,tmpstr);
                    get_token( fp, token, MAXTOKEN);
                    new_module(token, tmpstr);
                    count++;
                    DEBUGP("done\n");
                    fclose (fp);
                }
            }
        }
        closedir(dir);
        return(count);
    }
    return(-1);
}


/*
 * Returns the root of the whole tree
 *   (for backwards compatability)
 */
struct tree *
read_mib(filename)
    char *filename;
{
    FILE *fp;
    char token[MAXTOKEN];

    fp = fopen(filename, "r");
    if (fp == NULL)
        return NULL;
    Line = 1;
    strcpy(File,filename);
    DEBUGP1("Parsing %s...",filename);
    get_token( fp, token, MAXTOKEN);
    fclose(fp);
    new_module(token, filename);
    (void) read_module(token);
    DEBUGP("Done\n");

    return tree_head;
}


struct tree *
read_all_mibs()
{
    struct module *mp;

    for ( mp=module_head ; mp ; mp=mp->next )
	if ( mp->no_imports == -1 )
            read_module( mp->name );

    return tree_head;
}


#ifdef TEST
main(argc, argv)
    int argc;
    char *argv[];
{
    int i;
    struct tree *tp;
    mib_warnings = 2;

    init_mib();

    if ( argc == 1 )
	(void) read_all_mibs();
    else
	for ( i=1 ; i<argc ; i++ )
	    read_mib( argv[i] );

    for ( tp = tree_head ; tp ; tp=tp->next_peer )
        print_subtree( stdout, tp, 0 );
    free_tree( tree_head );

    return 0;
}
#endif /* TEST */

static int
parseQuoteString(fp, token,maxtlen)
    register FILE *fp;
    register char *token;
    int maxtlen;
{
    register int ch;
    int count = 0;
    int too_long = 0;
    char *token_start = token;

    ch = getc(fp);
    while(ch != EOF) {
        if (ch == '\n') {
            Line++;
        }
        else if (ch == '"') {
            *token = '\0';
            if (too_long && mib_warnings > 1)
                print_error ("Warning: string too long",
                             token_start, QUOTESTRING);
            return QUOTESTRING;
        }
        /* maximum description length check.  If greater, keep parsing
           but truncate the string */
        if (++count < maxtlen)
            *token++ = ch;
        else too_long = 1;
        ch = getc(fp);
    }

    return 0;
}

/*
 * This routine parses a string like  { blah blah blah } and returns OBJID if
 * it is well formed, and NULL if not.
 */
static int
tossObjectIdentifier(fp)
    register FILE *fp;
{
    int type;
    char token[MAXTOKEN];
    int bracketcount = 1;
    
    type = get_token(fp, token, MAXTOKEN);
    
    if (type != LEFTBRACKET)
        return 0;
    while ((type != RIGHTBRACKET || bracketcount > 0) && type != ENDOFFILE )
    {
        type = get_token(fp, token, MAXTOKEN);
        if (type == LEFTBRACKET)
          bracketcount++;
        else if (type == RIGHTBRACKET)
          bracketcount--;
    }
    
    if (type == RIGHTBRACKET)
        return OBJID;
    else
        return 0;
}

struct tree *
find_node(name, subtree)
  char *name;
  struct tree *subtree;    /* Unused */
{
  return( find_tree_node( name, -1 ));
}
