/*
              historyControlIndex             INTEGER (1..65535),
              historyControlDataSource        OBJECT IDENTIFIER,
              historyControlBucketsRequested  INTEGER (1..65535),
              historyControlBucketsGranted    INTEGER (1..65535),
              historyControlInterval          INTEGER (1..3600),
              historyControlOwner             DisplayString (SIZE (0..127)),
              historyControlStatus            INTEGER
*/

#define HISTORYCONTROLINDEX               1
#define HISTORYCONTROLDATASOURCE          2
#define HISTORYCONTROLBUCKETSREQUESTED    3
#define HISTORYCONTROLBUCKETSGRANTED      4
#define HISTORYCONTROLINTERVAL            5
#define HISTORYCONTROLOWNER               6
#define HISTORYCONTROLSTATUS              7

#define HCNONEXISTENT	0
#define HCVALID		1
#define HCCREATEREQUEST 2
#define HCUNDERCREATION	3
#define HCINVALID	4

struct bucket {
    int value;
};

struct bucketList {
    struct bucket *buckets;
    int size;
};

struct historyControlEntry {
  int    historyControlIndex;
  int    historyControlIfIndex;  /* computed from DataSource */
  oid    historyControlDataSource[32];
  int    historyControlDataSourceLength;
  int    historyControlBucketsRequested;
  int    historyControlBucketsGranted;
  struct bucketList *buckets;
  int    historyControlInterval;
  u_char historyControlOwner[128];
  int    historyControlOwnerLength;
  int    historyControlStatus;

  int    historyControlBitMask;

/* Reserved area */
  int    RhistoryControlIfIndex;  /* computed from DataSource */
  oid    RhistoryControlDataSource[32];
  int    RhistoryControlDataSourceLength;
  int    RhistoryControlBucketsRequested;
  int    RhistoryControlBucketsGranted;
  struct bucketList *Rbuckets;
  int    RhistoryControlInterval;
  u_char RhistoryControlOwner[128];
  int    RhistoryControlOwnerLength;
  int    RhistoryControlStatus;

  /* Reserved bitmask must equal real bitmask before every PDU starts.
   * This means it must be reset after each PDU is over.
   * The only time they can be different is between the RESERVE and COMMIT or
   * FREE phases.
   */
  int    RhistoryControlBitMask;
  struct historyControlEntry *next;
};

u_char *var_historyControlEntry();
int write_historyControl();

struct historyControlEntry *
hc_getEntry(/* int historyControlIndex */);
/*
 * Returns a pointer to the historyControlEntry with the
 * same index as historyControlIndex.
 * Returns NULL if that entry does not exist.
 */

hc_scanInit();
/*
 * Initialized the scan routines so that they will begin at the
 * beginning of the list of historyControlEntries.
 *
 */


struct historyControlEntry *
hc_scanNext();
/*
 * Returns a pointer to the next historyControlEntry.
 * These entries are returned in no particular order,
 * but if N entries exist, N calls to hc_scanNext() will
 * return all N entries once.
 * Returns NULL if all entries have been returned.
 * hc_scanInit() starts the scan over.
 */

struct historyControlEntry *
hc_createEntry(/* int historyControlIndex */);
/*
 * Creates a historyControlEntry with the given index
 * and returns a pointer to it.
 * The status of this entry is created as invalid.
 */

struct bucketList * hc_granted(/* int * requested */);
/*
 * Modifies the input number of buckets with the value that
 * can be granted.
 * Returns a pointer to a bucket list.
 * These buckets should be reserved until they are freed.
 */

hc_freeBuckets(/* struct bucketList * freeList */);
/*
 * Frees a list of buckets
 * Care should be taken to free any reserved buckets when
 * the entry times out.
 */

