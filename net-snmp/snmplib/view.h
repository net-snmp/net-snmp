/*
          viewIndex        INTEGER,                     -- first INDEX
          viewSubtree      OBJECT IDENTIFIER,           -- second INDEX
          viewMask         OCTET STRING
          viewType         INTEGER,
          viewStorageType  StorageType,
          viewStatus       RowStatus,
 */

#define VIEWINDEX	1
#define VIEWSUBTREE	2
#define VIEWMASK	3
#define VIEWTYPE	4
#define VIEWSTORAGETYPE	5
#define VIEWSTATUS	6

#define VIEWNONEXISTENT        0
#define VIEWACTIVE             1
#define VIEWNOTINSERVICE       2
#define VIEWNOTREADY           3
#define VIEWCREATEANDGO        4
#define VIEWCREATEANDWAIT      5
#define VIEWDESTROY            6

#define VIEWINCLUDED	1
#define VIEWEXCLUDED	2

struct viewEntry {
    int		viewIndex;
    char	viewName[64];
    int		viewNameLen;
    oid		viewSubtree[32];
    int		viewSubtreeLen;
    u_char	viewMask[32];
    int		viewMaskLen;
    int		viewType;
    int		viewStorageType;
    int		viewStatus;

    u_long	viewBitMask;

    struct viewEntry *reserved;
    struct viewEntry *next;
};

u_char *var_view();
int write_view();

struct viewEntry *
view_getEntry(/* int viewIndex */ );
/*
 * Returns a pointer to the viewEntry with the
 * same viewParty and viewSubtree
 * Returns NULL if that entry does not exist.
 */

int
view_scanInit();
/*
 * Initialized the scan routines so that they will begin at the
 * beginning of the list of viewEntries.
 *
 */


struct viewEntry *
view_scanNext();
/*
 * Returns a pointer to the next viewEntry.
 * These entries are returned in no particular order,
 * but if N entries exist, N calls to view_scanNext() will
 * return all N entries once.
 * Returns NULL if all entries have been returned.
 * view_scanInit() starts the scan over.
 */

struct viewEntry *
view_createEntry(/* int viewIndex */);
/*
 * Creates a viewEntry with the given index
 * and returns a pointer to it.
 * The status of this entry is created as invalid.
 */



