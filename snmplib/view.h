#ifndef VIEW_H
#define VIEW_H

#ifdef __cplusplus
extern "C" {
#endif
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
    size_t	viewNameLen;
    oid		viewSubtree[MAX_OID_LEN];
    size_t	viewSubtreeLen;
    u_char	viewMask[32];
    size_t	viewMaskLen;
    int		viewType;
    int		viewStorageType;
    int		viewStatus;

    u_long	viewBitMask;

    struct viewEntry *reserved;
    struct viewEntry *next;
};

int read_view_database (char *);

void view_destroyEntry (int, oid *, size_t);

struct viewEntry *
view_getEntry (int, oid*, int);
/*
 * Returns a pointer to the viewEntry with the
 * same viewParty and viewSubtree
 * Returns NULL if that entry does not exist.
 */

void
view_scanInit (void);
/*
 * Initialized the scan routines so that they will begin at the
 * beginning of the list of viewEntries.
 *
 */


struct viewEntry *
view_scanNext (void);
/*
 * Returns a pointer to the next viewEntry.
 * These entries are returned in no particular order,
 * but if N entries exist, N calls to view_scanNext() will
 * return all N entries once.
 * Returns NULL if all entries have been returned.
 * view_scanInit() starts the scan over.
 */

struct viewEntry *
view_createEntry (int, oid *, size_t);
/*
 * Creates a viewEntry with the given index
 * and returns a pointer to it.
 * The status of this entry is created as invalid.
 */

#ifdef __cplusplus
}
#endif

#endif /* VIEW_H */
