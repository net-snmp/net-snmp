/*
  aclTarget        INTEGER,
  aclSubject       INTEGER,
  aclResources     INTEGER,
  aclPrivileges    INTEGER,
  aclStorageType   StorageType,
  aclStatus        RowStatus
 */

#define ACLTARGET	1
#define ACLSUBJECT	2
#define ACLRESOURCES	3
#define ACLPRIVELEGES	4
#define ACLSTORAGETYPE	5
#define ACLSTATUS	6

#define ACLNONEXISTENT        0
#define ACLACTIVE             1
#define ACLNOTINSERVICE       2
#define ACLNOTREADY           3
#define ACLCREATEANDGO        4
#define ACLCREATEANDWAIT      5
#define ACLDESTROY            6

#define ACLPRIVELEGESGET		1
#define ACLPRIVELEGESGETNEXT		2
#define ACLPRIVELEGESGETRESPONSE	4
#define ACLPRIVELEGESSET		8
#define ACLPRIVELEGESBULK		32
#define ACLPRIVELEGESINFORM		64
#define ACLPRIVELEGESTRAP2		128

struct aclEntry {
    int		aclTarget;
    int		aclSubject;
    int		aclResources;
    int		aclPriveleges;
    int		aclStorageType;
    int		aclStatus;
    
    u_long	aclBitMask;

    struct aclEntry *reserved;
    struct aclEntry *next;
};

u_char *var_acl();
int write_acl();

struct aclEntry *
acl_getEntry(/* int target, int subject, int resources */);
/*
 * Returns a pointer to the aclEntry with the
 * same target and subject and resources.
 * Returns NULL if that entry does not exist.
 */

acl_scanInit();
/*
 * Initialized the scan routines so that they will begin at the
 * beginning of the list of aclEntries.
 *
 */


struct aclEntry *
acl_scanNext();
/*
 * Returns a pointer to the next aclEntry.
 * These entries are returned in no particular order,
 * but if N entries exist, N calls to acl_scanNext() will
 * return all N entries once.
 * Returns NULL if all entries have been returned.
 * acl_scanInit() starts the scan over.
 */

struct aclEntry *
acl_createEntry(/* int target, int subject, int resources */);
/*
 * Creates a aclEntry with the given index
 * and returns a pointer to it.
 * The status of this entry is created as invalid.
 */

