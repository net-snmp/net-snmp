/* include file for event module */

extern int eventFreeSpace();
extern u_char *var_eventnextindex();
extern u_char *var_eventtab();
extern u_char *var_eventnotifyvars();
extern u_char *var_eventnotifytab();
extern void eventGenerate();
extern void eventTimer();

#define MAX_COMMUNITY_LEN 128

struct eventEntry {
	struct eventEntry *next;
	int index;				/* 1..65535 */
	oid id[MAX_NAME_LEN];
	int idLen;
	char description[MAX_DESCRIPTION_LEN];		/* 0..127 */
	int descriptionLen;
	int numEvents;
	u_long lastTimeSent;	/* timeticks */
	u_long minInterval;
	u_long maxRetransmissions;
	int status;
	struct eventEntry *shadow;	/* copy for row creates and changes */
	u_long bitmask;			/* mask of valid variables */
};

struct eventNotifyEntry {
    struct eventNotifyEntry *next;
    int index;
    oid srcParty[MAX_NAME_LEN];
    int srcPartyLen;
    oid dstParty[MAX_NAME_LEN];
    int dstPartyLen;
    oid context[MAX_NAME_LEN];
    int contextLen;
    int interval;
    int retransmissions;
    int lifetime;
    int status;
    struct snmp_session *ss;
    struct get_req_state *magic;
    struct eventNotifyEntry *shadow;
    u_long bitmask;
};


/* defines passed to eventGenerate() to tell it what type of event occured */
#define EVENT_TYPE_STARTUP_RISING 1
#define EVENT_TYPE_STARTUP_FALLING 2
#define EVENT_TYPE_RISING 3
#define EVENT_TYPE_FALLING 4
#define EVENT_TYPE_UNAVAILABLE 5

/* does this mean anything? */
#define TRAP_RISING_ALARM 1
#define TRAP_FALLING_ALARM 2
#define TRAP_UNAVAILABLE_ALARM 3

/* masks for the bitmask field in struct eventEntry */
#define EVENTTABINDEXMASK			0x00000001
#define EVENTTABIDMASK				0x00000002
#define EVENTTABDESCRIPTIONMASK			0x00000004
#define EVENTTABEVENTSMASK			0x00000008
#define EVENTTABLASTTIMESENTMASK		0x00000010
#define EVENTTABSTATUSMASK			0x00000020

#define EVENTTABCOMPLETEMASK			0x0000003F

#define EVENTNOTIFYTABINTERVALMASK	    	0x00000001
#define EVENTNOTIFYTABRETRANSMISSIONSMASK 	0x00000002
#define EVENTNOTIFYTABLIFETIMEMASK	    	0x00000004
#define EVENTNOTIFYTABSTATUSMASK	    	0x00000008

#define EVENTNOTIFYTABCOMPLETEMASK		0x0000000F
