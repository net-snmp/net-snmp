/* include file for alarm module */

extern u_char *var_alarmtab();
extern u_char *var_alarmnextindex();
extern void alarmTimer();
extern int alarmGetResponse();

/* defines for values of alarmEntry.sampleType */
#define ALARM_ABSOLUTE_VALUE 1
#define ALARM_DELTA_VALUE 2

/* defines for values of alarmEntry.startupAlarm */
#define ALARM_STARTUP_RISING 1
#define ALARM_STARTUP_FALLING 2
#define ALARM_STARTUP_RISING_OR_FALLING 3

struct alarmEntry {
    struct alarmEntry *next;
    int index;			/* 1..65535 */
    oid dstPartyID[MAX_OID_LEN];
    int dstPartyLength;
    oid srcPartyID[MAX_OID_LEN];
    int srcPartyLength;
    oid contextID[MAX_OID_LEN];
    int contextLength;
    long interval;
    oid variable[MAX_OID_LEN];
    int variableLen;		/* number of subids in "variable" */
    int sampleType;
    long value;
    int startupAlarm;
    long risingThresh;
    long fallingThresh;
    int risingEventIndex;		/* same as an eventIndex */
    int fallingEventIndex;		/* same as an eventIndex */
    int unavailableEventIndex;		/* same as an eventIndex */
    char owner[MAX_OWNER_STR_LEN];
    int status;
    struct timeval update;	/* time that next update should occur */
    struct timeval intervalAdd;	/* amount to add to get to next update */
    char cantSendRising;	/* boolean: may a rising event be sent? */
    char cantSendFalling;	/* boolean: may a falling event be sent? */
    char cantSendUnavailable; /* boolean: may an unavailable event be sent? */
    long lastRealValue;		/* used for delta samples */
    long lastDeltaValue;	/* used for delta samples */
    struct snmp_session *ss;
    int reqid;
    struct get_req_state *magic;	/* for snmp api */
    struct alarmEntry *shadow;	/* copy for row creates and changes */
    u_long bitmask;			/* mask of valid variables */
};

/* masks for the bitmask field in struct alarmEntry */
#define ALARMTABINDEXMASK			0x00000001
#define ALARMTABVARIABLEMASK			0x00000002
#define ALARMTABINTERVALMASK			0x00000004
#define ALARMTABSAMPLETYPEMASK			0x00000008
#define ALARMTABVALUEMASK			0x00000010
#define ALARMTABSTARTUPALARMMASK		0x00000020
#define ALARMTABRISINGTHRESHMASK		0x00000040
#define ALARMTABFALLINGTHRESHMASK		0x00000080
#define ALARMTABRISINGINDEXMASK			0x00000100
#define ALARMTABFALLINGINDEXMASK		0x00000200
#define ALARMTABUNAVAILABLEINDEXMASK		0x00000400
#define ALARMTABSTATUSMASK			0x00000800

#define ALARMTABCOMPLETEMASK			0x00000FFF

/* this define has nothing to do with the protocol, just the
** implementation.  It's here because it's convenient.
*/
#define ALARMTABREALVALUEMASK			0x10000000
