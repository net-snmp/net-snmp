#ifndef IN_CONTEXT_H
#define IN_CONTEXT_H

#ifdef __cplusplus
extern "C" {
#endif
/*
    contextIdentity         Context,
    contextIndex            INTEGER,
    contextViewIndex        INTEGER,
    contextLocalEntity      OCTET STRING,
    contextLocalTime        OBJECT IDENTIFIER,
    contextDstPartyIndex    INTEGER,
    contextSrcPartyIndex    INTEGER,
    contextProxyContext     OBJECT IDENTIFIER
    contextStorageType      StorageType,
    contextStatus           RowStatus
 */

#define CONTEXTIDENTITY         1
#define CONTEXTINDEX            2
#define CONTEXTLOCAL		3
#define CONTEXTVIEWINDEX        4
#define CONTEXTLOCALENTITY      5
#define CONTEXTLOCALTIME        6
#define CONTEXTDSTPARTYINDEX    7
#define CONTEXTSRCPARTYINDEX    8
#define CONTEXTPROXYCONTEXT     9
#define CONTEXTSTORAGETYPE      10
#define CONTEXTSTATUS           11

#define CURRENTTIME	1
#define RESTARTTIME	2
#define CACHETIME	3	/* not implemented */

struct contextEntry {
    oid		contextIdentity[MAX_OID_LEN];
    size_t	contextIdentityLen;
    int		contextIndex;
    char	contextName[64];	/* friendly name */
    int		contextLocal;
    int		contextViewIndex;
    u_char	contextLocalEntity[64];
    size_t	contextLocalEntityLen;
    int		contextLocalTime;
    int		contextDstPartyIndex;
    int		contextSrcPartyIndex;
    oid		contextProxyContext[MAX_OID_LEN];
    size_t	contextProxyContextLen;
    int		contextStorageType;
    int		contextStatus;
    
    u_long	contextBitMask;

    struct contextEntry *reserved;
    struct contextEntry *next;
    struct timeval tv;
};

void context_destroyEntry (oid *, size_t);

struct contextEntry *
context_getEntry (oid *contextID, size_t contextIDLen);
/*
 * Returns a pointer to the contextEntry with the
 * same identity as contextID.
 * Returns NULL if that entry does not exist.
 */

void
context_scanInit (void);
/*
 * Initialized the scan routines so that they will begin at the
 * beginning of the list of contextEntries.
 *
 */


struct contextEntry *
context_scanNext (void);
/*
 * Returns a pointer to the next contextEntry.
 * These entries are returned in no particular order,
 * but if N entries exist, N calls to context_scanNext() will
 * return all N entries once.
 * Returns NULL if all entries have been returned.
 * context_scanInit() starts the scan over.
 */

struct contextEntry *
context_createEntry (oid *contextID, size_t contextIDLen);
/*
 * Creates a contextEntry with the given index
 * and returns a pointer to it.
 * The status of this entry is created as invalid.
 */

int read_context_database (char *);

#ifdef __cplusplus
}
#endif

#endif
