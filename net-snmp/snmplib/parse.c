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

#include "parse.h"

/* A quoted string value-- too long for a general "token" */
char *quoted_string_buffer;

/*
 * This is one element of an object identifier with either an integer
 * subidentifier, or a textual string label, or both.
 * The subid is -1 if not present, and label is NULL if not present.
 */
struct subid {
    int subid;
    char *label;
};

#define MAXTC   256
struct tc {     /* textual conventions */
    int type;
    char descriptor[MAXTOKEN];
    struct enum_list *enums;
} tclist[MAXTC];



int Line = 1;
char File[300];
int save_mib_descriptions = 0;
int mib_warnings = 0;

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
#define OPAQUE      (12 | SYNTAX_MASK)
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
#define OPTIONAL    24
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

struct tok {
    char *name;                 /* token name */
    int len;                    /* length not counting nul */
    int token;                  /* value */
    int hash;                   /* hash of name */
    struct tok *next;           /* pointer to next in hash table */
};


struct tok tokens[] = {
    { "obsolete", sizeof ("obsolete")-1, OBSOLETE },
    { "Opaque", sizeof ("Opaque")-1, OPAQUE },
    { "optional", sizeof ("optional")-1, OPTIONAL },
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
    { "BITSTRING", sizeof("BitString")-1, BITSTRING},
    { "BIT", sizeof("BIT")-1, CONTINUE},
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
    { "EXPORTS", sizeof ("EXPORTS")-1, IMPORTS },
    { "accessible-for-notify", sizeof ("accessible-for-notify")-1, ACCNOTIFY },
    { "|", sizeof ("|")-1, BAR },
    { "..", sizeof ("..")-1, RANGE },
    { "TEXTUAL-CONVENTION", sizeof ("TEXTUAL-CONVENTION")-1, CONVENTION },
    { NULL }
};

#define HASHSIZE        32
#define BUCKET(x)       (x & 0x01F)

struct tok      *buckets[HASHSIZE];

static void do_subtree();
static int get_token();
static void unget_token();
static int parseQuoteString();
static int tossObjectIdentifier();

static void
hash_init()
{
    register struct tok *tp;
    register char       *cp;
    register int        h;
    register int        b;

    memset(buckets, 0, sizeof(buckets));
    for (tp = tokens; tp->name; tp++) {
        for (h = 0, cp = tp->name; *cp; cp++)
            h += *cp;
        tp->hash = h;
        b = BUCKET(h);
        if (buckets[b])
            tp->next = buckets[b]; /* BUG ??? */
        buckets[b] = tp;
    }
}

#define NHASHSIZE    128
#define NBUCKET(x)   (x & 0x7F)
struct node *nbuckets[NHASHSIZE];

static void
init_node_hash(nodes)
     struct node *nodes;
{
     register struct node *np, *nextp;
     register char *cp;
     register int hash;

     memset(nbuckets, 0, sizeof(nbuckets));
     for(np = nodes; np;){
         nextp = np->next;
         hash = 0;
         for(cp = np->parent; *cp; cp++)
             hash += *cp;
         np->next = nbuckets[NBUCKET(hash)];
         nbuckets[NBUCKET(hash)] = np;
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
    char *ss = Malloc (strlen (s)+1);
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

            free((char *)tep);
        }
    }

    if (Tree->description)
        free(Tree->description);
    if (Tree->label)
        free(Tree->label);

    free_tree(Tree->child_list);
    free (Tree);
}

static void
free_node(np)
    struct node *np;
{
    struct enum_list *ep, *tep;

    ep = np->enums;
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
    }
}
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
        fprintf(f, "%s(%ld) type=%d tc=%d\n",
                tp->label, tp->subid, tp->type, tp->tc_index);
    }
    for(tp = tree->child_list; tp; tp = tp->next_peer){
        if (tp->child_list)
            print_subtree(f, tp, count);
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
            case OPAQUE:
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

static struct tree *
build_tree(nodes)
    struct node *nodes;
{
    struct node *np;
    struct tree *tp, *lasttp;
    int bucket, nodes_left = 0;

    build_translation_table();
    /* grow tree from this root node */
    init_node_hash(nodes);

    /* build root node */
    tp = Malloc(sizeof(struct tree));
    tp->parent = NULL;
    tp->next_peer = NULL;
    tp->child_list = NULL;
    tp->enums = NULL;
    tp->label = "joint-iso-ccitt";
    tp->subid = 2;
    tp->tc_index = -1;
    tp->type = 0;
    tp->description = NULL;
    /* XXX nodes isn't needed in do_subtree() ??? */
    do_subtree(tp, &nodes);
    lasttp = tp;

    /* build root node */
    tp = Malloc(sizeof(struct tree));
    tp->parent = NULL;
    tp->next_peer = lasttp;
    tp->child_list = NULL;
    tp->enums = NULL;
    tp->label = "ccitt";
    tp->subid = 0;
    tp->tc_index = -1;
    tp->type = 0;
    tp->description = NULL;
    /* XXX nodes isn't needed in do_subtree() ??? */
    do_subtree(tp, &nodes);
    lasttp = tp;

    /* build root node */
    tp = Malloc(sizeof(struct tree));
    tp->parent = NULL;
    tp->next_peer = lasttp;
    tp->child_list = NULL;
    tp->enums = NULL;
    tp->label = "iso";
    tp->subid = 1;
    tp->tc_index = -1;
    tp->type = 0;
    tp->description = NULL;
    /* XXX nodes isn't needed in do_subtree() ??? */
    do_subtree(tp, &nodes);

    if (mib_warnings) Malloc_stats (stderr);

    /* If any nodes are left, the tree is probably inconsistent */
    for(bucket = 0; bucket < NHASHSIZE; bucket++){
        if (nbuckets[bucket]){
            nodes_left = 1;
            break;
        }
    }
    if (nodes_left){
        fprintf(stderr, "The mib description doesn't seem to be consistent.\n");
        fprintf(stderr, "Some nodes couldn't be linked under the \"iso\" tree.\n");
        fprintf(stderr, "these nodes are left:\n");
        for(bucket = 0; bucket < NHASHSIZE; bucket++){
            for(np = nbuckets[bucket]; np; np = np->next)
                fprintf(stderr, "%s ::= { %s %ld } (%d)\n", np->label,
                        np->parent, np->subid, np->type);
        }
    }
    return tp;
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
    register struct tree *tp;
    register struct node *np, **headp;
    struct node *oldnp = NULL, *child_list = NULL, *childp = NULL;
    char *cp;
    int hash;

    tp = root;
    hash = 0;
    for(cp = tp->label; *cp; cp++)
        hash += *cp;
    headp = &nbuckets[NBUCKET(hash)];
    /*
     * Search each of the nodes for one whose parent is root, and
     * move each into a separate list.
     */
    for(np = *headp; np; np = np->next){
        if ((*tp->label != *np->parent) || strcmp(tp->label, np->parent)){
            if ((*tp->label == *np->label) && !strcmp(tp->label, np->label)){
                /* if there is another node with the same label, assume that
                 * any children after this point in the list belong to the other node.
                 * This adds some scoping to the table and allows vendors to
                 * reuse names such as "ip".
                 */
                if (mib_warnings)
                    fprintf(stderr, "Warning: duplicate label: %s.%s¹n",
                            np->parent, np->label);
                break;
            }
            oldnp = np;
        } else {
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
        if (tp && mib_warnings)
            fprintf (stderr, "Warning: %s.%ld is both %s and %s\n",
                    root->label, np->subid, tp->label, np->label);
        tp = Malloc(sizeof(struct tree));
        tp->parent = root;
        tp->child_list = NULL;
        tp->label = np->label;
        np->label = NULL;
        tp->subid = np->subid;
        tp->tc_index = np->tc_index;
        tp->type = translation_table[np->type];
        tp->enums = np->enums;
        np->enums = NULL;       /* so we don't free them later */
        tp->description = np->description; /* steals memory from np */
        np->description = NULL; /* so we don't free it later */
        tp->next_peer = root->child_list;
        root->child_list = tp;
/*      if (tp->type == TYPE_OTHER) */
            do_subtree(tp, nodes);      /* recurse on this child if it isn't
                                           an end node */
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
getoid(fp, oid,  length)
    register FILE *fp;
    register struct subid *oid; /* an array of subids */
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
    for(count = 0; count < length; count++, oid++){
        oid->label = NULL;
        oid->subid = -1;
        if (type == RIGHTBRACKET){
            return count;
        } else if (type != LABEL && type != NUMBER){
            print_error("Not valid for object identifier", token, type);
            return 0;
        }
        if (type == LABEL){
            /* this entry has a label */
            oid->label = Strdup(token);
            type = get_token(fp, token,MAXTOKEN);
            if (type == LEFTPAREN){
                type = get_token(fp, token,MAXTOKEN);
                if (type == NUMBER){
                    oid->subid = atoi(token);
                    if ((type = get_token(fp, token,MAXTOKEN)) != RIGHTPAREN){
                        print_error("Expected a closing bracket", token, type);
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
            oid->subid = atoi(token);
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

    if ((length = getoid(fp, oid, 32)) != 0){
        np = root = Malloc(sizeof(struct node));
        memset(np, 0, sizeof(struct node));
        /*
         * For each parent-child subid pair in the subid array,
         * create a node and link it into the node list.
         */
        for(count = 0, op = oid, nop=oid+1; count < (length - 2); count++,
            op++, nop++){
            /* every node must have parent's name and child's name or number */
            if (op->label && (nop->label || (nop->subid != -1))){
                np->parent = Strdup (op->label);
                if (nop->label)
                    np->label = Strdup (nop->label);
                if (nop->subid != -1)
                    np->subid = nop->subid;
                np->tc_index = -1;
                np->type = 0;
                np->enums = NULL;
                /* set up next entry */
                np->next = Malloc(sizeof(*np->next));
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
get_tc(descriptor, ep)
    char *descriptor;
    struct enum_list **ep;
{
    int i;

    for(i = 0; i < MAXTC; i++){
        if (tclist[i].type == 0)
            break;
        if (!strcmp(descriptor, tclist[i].descriptor)){
            *ep = tclist[i].enums;
            return tclist[i].type;
        }
    }
    return LABEL;
}

/* return index into tclist of given TC descriptor
   return -1 if not found
 */
static int
get_tc_index(descriptor)
    char *descriptor;
{
    int i;

    for(i = 0; i < MAXTC; i++){
      if (tclist[i].type == 0)
          break;
      if (!strcmp(descriptor, tclist[i].descriptor)){
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
            rep = Malloc(sizeof(struct enum_list));
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
            while (type != SYNTAX && type != ENDOFFILE)
                type = get_token(fp, token, MAXTOKEN);
            type = get_token(fp, token, MAXTOKEN);
        }

        if (type == LABEL)
        {
            type = get_tc(token, &ep);
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
        strncpy(tcp->descriptor, name, MAXTOKEN);
        if (!(type & SYNTAX_MASK)){
            print_error("Textual convention doesn't map to real type", token,
                        type);
            return NULL;
        }
        tcp->type = type;
        *ntype = get_token(fp, ntoken,MAXTOKEN);
        if (*ntype == LEFTPAREN){
            level = 1;
            /* don't record any constraints for now */
            while(level > 0){
                *ntype = get_token(fp, ntoken,MAXTOKEN);
                if (*ntype == LEFTPAREN)
                    level++;
                else if (*ntype == RIGHTPAREN)
                    level--;
                else if (*ntype == ENDOFFILE)
                    break;
            }
            *ntype = get_token(fp, ntoken,MAXTOKEN);
        } else if (*ntype == LEFTBRACKET) {
            /* if there is an enumeration list, parse it */
            tcp->enums = parse_enumlist(fp);
            *ntype = get_token(fp, ntoken,MAXTOKEN);
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
    np = Malloc(sizeof(struct node));
    np->next = NULL;
    np->tc_index = -1;
    np->enums = NULL;
    np->description = NULL;        /* default to an empty description */
    type = get_token(fp, token, MAXTOKEN);
    if (type == LABEL){
        tctype = get_tc(token, &(np->enums));
        if (tctype == LABEL && mib_warnings > 1){
            print_error("Warning: No known translation for type", token, type);
        }
        type = tctype;
        np->tc_index = get_tc_index(token); /* store TC for later reference */
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
                /* ignore the "constrained integer" for now */
                nexttype = get_token(fp, nexttoken,MAXTOKEN);
                if (nexttype == SIZE)
                {
                    /* LEFTPAREN */
                    nexttype = get_token(fp, nexttoken, MAXTOKEN);
                    /* Range */
                    nexttype = get_token(fp, nexttoken, MAXTOKEN);
                    nexttype = get_token(fp, nexttoken, MAXTOKEN);
                    if (nexttype == RANGE) {
                        nexttype = get_token(fp, nexttoken, MAXTOKEN);
                        nexttype = get_token(fp, nexttoken, MAXTOKEN);
                    }
                    nexttype = get_token(fp, nexttoken,MAXTOKEN);
                }
                else {
                    nexttype = get_token(fp, nexttoken,MAXTOKEN);
                    while (nexttype == BAR) {
                        nexttype = get_token(fp, nexttoken,MAXTOKEN);
                        nexttype = get_token(fp, nexttoken,MAXTOKEN);
                    }
                }
                nexttype = get_token(fp, nexttoken,MAXTOKEN);
            }
            break;
        case BITSTRING:
            if (nexttype == LEFTBRACKET) {
                /* if there is an enumeration list, parse it */
                np->enums = parse_enumlist(fp);
                nexttype = get_token(fp, nexttoken,MAXTOKEN);
            } else if (nexttype == LEFTPAREN){
                /* ignore the "constrained integer" for now */
                nexttype = get_token(fp, nexttoken,MAXTOKEN);
                nexttype = get_token(fp, nexttoken,MAXTOKEN);
                nexttype = get_token(fp, nexttoken,MAXTOKEN);
            }
            break;
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
        case OPAQUE:
        case NUL:
        case LABEL:
        case NSAPADDRESS:
        case COUNTER64:
            break;
        default:
            print_error("Bad syntax", token, type);
            free_node(np);
            return NULL;
    }
    if (nexttype == UNITS){
        type = get_token(fp, quoted_string_buffer,MAXQUOTESTR);
        if (type != QUOTESTRING) {
            print_error("Bad UNITS", quoted_string_buffer, type);
            free_node(np);
            return NULL;
        }
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
    type = get_token(fp, token,MAXTOKEN);
    if (type != STATUS){
        print_error("Should be STATUS", token, type);
        free_node(np);
        return NULL;
    }
    type = get_token(fp, token,MAXTOKEN);
    if (type != MANDATORY && type != CURRENT && type != OPTIONAL &&
        type != OBSOLETE && type != DEPRECATED){
        print_error("Bad STATUS", token, type);
        free_node(np);
        return NULL;
    }
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

    np = Malloc(sizeof(struct node));
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
    np->parent = nnp->parent;
    np->label = nnp->label;
    np->next = nnp->next;
    np->subid = nnp->subid;
    free(nnp);
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

    np = Malloc(sizeof(struct node));
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
    np->parent = nnp->parent;
    np->label = nnp->label;
    np->next = nnp->next;
    np->subid = nnp->subid;
    free(nnp);
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

    np = Malloc(sizeof(struct node));
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

    np = Malloc(sizeof(struct node));
    np->tc_index = -1;
    np->type = 0;
    np->next = NULL;
    np->enums = NULL;
    np->description = NULL;        /* default to an empty description */
    type = get_token(fp, token,MAXTOKEN);
    while (type != EQUALS && type != ENDOFFILE)
        type = get_token(fp, quoted_string_buffer,MAXQUOTESTR);
    nnp = parse_objectid (fp, name);
    np->parent = nnp->parent;
    np->label = nnp->label;
    np->next = nnp->next;
    np->subid = nnp->subid;
    free(nnp);
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

    np = Malloc (sizeof (struct node));
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
    np->parent = nnp->parent;
    np->label = nnp->label;
    np->subid = nnp->subid;
    np->next = nnp->next;
    free (nnp);
    return np;
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
    } else {
        hash_init();
        memset(tclist, 0, MAXTC * sizeof(struct tc));
    }
    quoted_string_buffer = Malloc(MAXQUOTESTR);  /* free this later */
    if (quoted_string_buffer == NULL) {
        print_error ("Out of memory", NULL, CONTINUE);
        return NULL;
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
            while (type != SEMI && type != ENDOFFILE)
                type = get_token(fp, token, MAXTOKEN);
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
        switch (type) {
        case DEFINITIONS:
            if (state != BETWEEN_MIBS){
                print_error("Error, nested MIBS", NULL, type);
                return NULL;
            }
            state = IN_MIB;
            if (mib_warnings) fprintf (stderr, "Parsing MIB: %s\n", name);
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
                print_error("Bad format", token, type);
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
    free (quoted_string_buffer);
    quoted_string_buffer = NULL;
    return root;
}

/*
 * Parses a token from the file.  The type of the token parsed is returned,
 * and the text is placed in the string pointed to by token.
 */

static int ungotten_token = CONTINUE;

static void unget_token (token)
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
    static char last = ' ';
    register int ch;
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
     * type.  Else it is a label.
     */
    do {
        if (ch == '\n')
            Line++;
        if (isspace(ch) || ch == '(' || ch == ')' || ch == '{' || ch == '}' ||
            ch == ',' || ch == ';' || ch == '|' || ch == '.' && *token == 0){
            if (!isspace(ch) && *token == 0){
                hash += ch;
                if (cp-token < maxtlen-1)
                    *cp++ = ch;
                else too_long = 1;
                last = ' ';
            } else {
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
            for(cp = token; *cp; cp++)
                if (!isdigit(*cp))
                    return LABEL;
            return NUMBER;
        } else {
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

#ifndef TEST
struct tree *
read_mib(filename)
    char *filename;
{
    FILE *fp;
    struct node *nodes = NULL;
    struct tree *tree;
    DIR *dir, *dir2;
    struct dirent *file;
    char tmpstr[300];
    char *libpath;

    fp = fopen(filename, "r");
    if (fp == NULL)
        return NULL;
    strcpy(File,filename);
    nodes = parse(fp, nodes);
    if (!nodes){
        fprintf(stderr, "Mib table is bad.  Exiting\n");
        exit(1);
    }
    fclose(fp);
    DEBUGP("Done\n");

    libpath = getenv("SNMPLIBPATH");
    if (!libpath) libpath = SNMPLIBPATH;
    sprintf(tmpstr,"%s/mibs", libpath);
    if (nodes != NULL && (dir = opendir(tmpstr))) {
        while (nodes != NULL && (file = readdir(dir))) {
            /* Only parse file names not beginning with a '.' */
            if (file->d_name != NULL && file->d_name[0] != '.') {
                sprintf(tmpstr, "%s/mibs/%s", libpath, file->d_name);
                if (dir2 = opendir(tmpstr)) {
                    /* file is a directory, don't read it */
                    closedir(dir2);
                } else {
                    /* parse it */
                    if ((fp = fopen(tmpstr, "r")) == NULL) {
                        perror(tmpstr);
                        exit(1);
                    }
                    Line = 1;
                    strcpy(File,tmpstr);
                    nodes = parse(fp, nodes);
                    if (nodes == NULL) {
                        fprintf(stderr, "Mib table is bad.  Exiting\n");
                        exit(1);
                    }
                    DEBUGP("done\n");
                    fclose (fp);
                }
            }
        }
        closedir(dir);
    }
    tree = build_tree(nodes);
    return tree;
}
#endif


#ifdef TEST
main(argc, argv)
    int argc;
    char *argv[];
{
    FILE *fp;
    struct node *nodes;
    struct tree *tp = NULL;

    if (argc == 2) strcpy (File, argv [1]);
    else strcpy (File, "mib.txt");

    fp = fopen(File, "r");
    if (fp == NULL){
        perror(File);
        return 1;
    }
    nodes = parse(fp, NULL);

    if (nodes != NULL)
    {
        print_nodes(stdout, nodes);
        tp = build_tree(nodes);
        print_subtree(stdout, tp, 0);
    }

    free_tree(tp);

    fclose(fp);

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
