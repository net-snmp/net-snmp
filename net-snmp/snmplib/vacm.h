#ifndef VACM_H
#define VACM_H
/*
 * SNMPv3 View-based Access Control Model
 */

#define SECURITYMODEL	1
#define SECURITYNAME	2
#define SECURITYGROUP	3
#define SECURITYSTORAGE	4
#define SECURITYSTATUS	5

#define ACCESSPREFIX	1
#define ACCESSMODEL	2
#define ACCESSLEVEL	3
#define ACCESSMATCH	4
#define ACCESSREAD	5
#define ACCESSWRITE	6
#define ACCESSNOTIFY	7
#define ACCESSSTORAGE	8
#define ACCESSSTATUS	9

#define VIEWNAME	1
#define VIEWSUBTREE	2
#define VIEWMASK	3
#define VIEWTYPE	4
#define VIEWSTORAGE	5
#define VIEWSTATUS	6

struct vacm_securityEntry {
    char	securityName[32];
    snmp_ipaddr	sourceIp;
    snmp_ipaddr	sourceMask;
    char	community[32];
    struct vacm_securityEntry *next;
};

struct vacm_groupEntry {
    int		securityModel;
    char	securityName[32];
    char	groupName[32];
    int		storageType;
    int		status;

    u_long	bitMask;
    struct vacm_groupEntry *reserved;
    struct vacm_groupEntry *next;
};

struct vacm_accessEntry {
    char	groupName[32];
    char	contextPrefix[32];
    int		securityModel;
    int		securityLevel;
    int 	contextMatch;
    char	readView[32];
    char	writeView[32];
    char	notifyView[32];
    int		storageType;
    int		status;

    u_long	bitMask;
    struct vacm_accessEntry *reserved;
    struct vacm_accessEntry *next;
};

struct vacm_viewEntry {
    char	viewName[32];
    oid		viewSubtree[32];
    int		viewSubtreeLen;
    u_char	viewMask[32];
    int		viewMaskLen;
    int		viewType;
    int		viewStorageType;
    int		viewStatus;

    u_long	bitMask;

    struct vacm_viewEntry *reserved;
    struct vacm_viewEntry *next;
};

void vacm_destroyViewEntry __P((char *, oid *, int));
void vacm_destroyAllViewEntries __P((void));

struct vacm_viewEntry *
vacm_getViewEntry __P((char *, oid*, int));
/*
 * Returns a pointer to the viewEntry with the
 * same viewName and viewSubtree
 * Returns NULL if that entry does not exist.
 */

void
vacm_scanViewInit __P((void));
/*
 * Initialized the scan routines so that they will begin at the
 * beginning of the list of viewEntries.
 *
 */


struct vacm_viewEntry *
vacm_scanViewNext __P((void));
/*
 * Returns a pointer to the next viewEntry.
 * These entries are returned in no particular order,
 * but if N entries exist, N calls to view_scanNext() will
 * return all N entries once.
 * Returns NULL if all entries have been returned.
 * view_scanInit() starts the scan over.
 */

struct vacm_viewEntry *
vacm_createViewEntry __P((char *, oid *, int));
/*
 * Creates a viewEntry with the given index
 * and returns a pointer to it.
 * The status of this entry is created as invalid.
 */

void vacm_destroyGroupEntry __P((int, char *));
void vacm_destroyAllGroupEntries __P((void));
struct vacm_groupEntry * vacm_createGroupEntry __P((int, char *));
struct vacm_groupEntry *vacm_getGroupEntry __P((int, char *));
void vacm_scanGroupInit __P((void));
struct vacm_groupEntry *vacm_scanGroupNext __P((void));

void vacm_destroyAccessEntry __P((char *, char *, int, int));
void vacm_destroyAllAccessEntries __P((void));
struct vacm_accessEntry * vacm_createAccessEntry __P((char *, char *, int, int));
struct vacm_accessEntry *vacm_getAccessEntry __P((char *, char *, int, int));
void vacm_scanAccessInit __P((void));
struct vacm_accessEntry *vacm_scanAccessNext __P((void));

void vacm_destroySecurityEntry __P((char *));
void vacm_destroyAllSecurityEntries __P((void));
struct vacm_securityEntry * vacm_createSecurityEntry __P((char *));
struct vacm_securityEntry *vacm_getSecurityEntry __P((char *));
void vacm_scanSecurityInit __P((void));
struct vacm_securityEntry *vacm_scanSecurityEntry __P((void));
#endif /* VACM_H */
