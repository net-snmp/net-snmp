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

#define CONTEXTNONEXISTENT 	0
#define CONTEXTACTIVE		1
#define CONTEXTNOTINSERVICE	2
#define CONTEXTNOTREADY		3
#define CONTEXTCREATEANDGO	4
#define CONTEXTCREATEANDWAIT	5
#define CONTEXTDESTROY		6


#define CURRENTTIME	1
#define RESTARTTIME	2
#define CACHETIME	3	/* not implemented */

struct contextEntry {
    oid		contextIdentity[32];
    int		contextIdentityLen;
    int		contextIndex;
    char	contextName[64];	/* friendly name */
    int		contextLocal;
    int		contextViewIndex;
    u_char	contextLocalEntity[64];
    int		contextLocalEntityLen;
    int		contextLocalTime;
    int		contextDstPartyIndex;
    int		contextSrcPartyIndex;
    oid		contextProxyContext[32];
    int		contextProxyContextLen;
    int		contextStorageType;
    int		contextStatus;
    
    u_long	contextBitMask;

    struct contextEntry *reserved;
    struct contextEntry *next;
    struct timeval tv;
};

u_char *var_context();
int write_context();

struct contextEntry *
context_getEntry(/* oid *contextID, int contextIDLen */);
/*
 * Returns a pointer to the contextEntry with the
 * same identity as contextID.
 * Returns NULL if that entry does not exist.
 */

int
context_scanInit();
/*
 * Initialized the scan routines so that they will begin at the
 * beginning of the list of contextEntries.
 *
 */


struct contextEntry *
context_scanNext();
/*
 * Returns a pointer to the next contextEntry.
 * These entries are returned in no particular order,
 * but if N entries exist, N calls to context_scanNext() will
 * return all N entries once.
 * Returns NULL if all entries have been returned.
 * context_scanInit() starts the scan over.
 */

struct contextEntry *
context_createEntry(/* oid *contextID, int contextIDLen */);
/*
 * Creates a contextEntry with the given index
 * and returns a pointer to it.
 * The status of this entry is created as invalid.
 */


