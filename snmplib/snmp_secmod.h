#ifndef SNMPSECMOD_H
#define SNMPSECMOD_H

struct snmp_secmod_def;

/*
 * parameter information passed to security model routines
 */
struct snmp_secmod_outgoing_params {
   int      msgProcModel;
   u_char  *globalData;
   size_t   globalDataLen;
   int      maxMsgSize;
   int      secModel;
   u_char  *secEngineID;
   size_t   secEngineIDLen;
   char    *secName;
   size_t   secNameLen;
   int      secLevel;
   u_char  *scopedPdu;
   size_t   scopedPduLen;
   void    *secStateRef;
   u_char  *secParams;
   size_t  *secParamsLen;
   u_char **wholeMsg;
   size_t  *wholeMsgLen;
   struct snmp_session *pdu;       /* IN - the pdu getting encoded            */
   struct snmp_session *session;   /* IN - session sending the message        */
};

struct snmp_secmod_incoming_params {
   int      msgProcModel;	   /* IN */
   size_t   maxMsgSize;	           /* IN     - Used to calc maxSizeResponse.  */

   u_char  *secParams;	           /* IN     - BER encoded securityParameters.*/
   int      secModel;	           /* IN */
   int      secLevel;	           /* IN     - AuthNoPriv; authPriv etc.      */

   u_char  *wholeMsg;	           /* IN     - Original v3 message.           */
   size_t   wholeMsgLen;	   /* IN     - Msg length.                    */

   u_char  *secEngineID;	   /* OUT    - Pointer snmpEngineID.          */
   size_t  *secEngineIDLen;        /* IN/OUT - Len available; len returned.   */
                                   /*   NOTE: Memory provided by caller.      */

   char *secName;                  /* OUT    - Pointer to securityName.       */
   size_t  *secNameLen;	           /* IN/OUT - Len available; len returned.   */

   u_char **scopedPdu;             /* OUT    - Pointer to plaintext scopedPdu.*/
   size_t  *scopedPduLen;	   /* IN/OUT - Len available; len returned.   */

   size_t  *maxSizeResponse;       /* OUT    - Max size of Response PDU.      */
   void   **secStateRef;           /* OUT    - Ref to security state.         */
   struct snmp_session *sess;      /* IN     - session which got the message  */
   struct snmp_session *pdu;       /* IN     - the pdu getting parsed         */
   u_char msg_flags;	           /* IN     - v3 Message flags.              */
};


/*
 * function pointers:
 */

/* free's a given security module's data; called at unregistration time */
typedef int (SecmodInitSess)(struct snmp_session *);
typedef int (SecmodOutMsg)(struct snmp_secmod_outgoing_params *);
typedef int (SecmodInMsg)(struct snmp_secmod_incoming_params *);
typedef void (SecmodFreeState) (void *);
typedef void (FreePdu) (struct snmp_pdu *);
typedef void (FreeSession) (struct snmp_session *);

/*
 * definition of a security module
 */
struct snmp_secmod_def {
   /* maniplation functions */
   SecmodInitSess  *init_sess_secmod;

   /* encoding routines */
   SecmodOutMsg    *reverse_encode_out; /* encode packet back to front */
   SecmodOutMsg    *forward_encode_out; /* encode packet forward */
   SecmodInMsg     *decode_in;          /* decode & validate incoming */

   /* clean up routines */
   SecmodFreeState *free_state_ref;     /* frees pdu->securityStateRef */
   FreePdu         *free_pdu;           /* called during free_pdu() */
   FreeSession     *free_session;       /* called during snmp_sess_close() */
};


/*
 * internal list
 */
struct snmp_secmod_list {
   int                      securityModel;
   struct snmp_secmod_def  *secDef;
   struct snmp_secmod_list *next;
};


/* register a security service */
int register_sec_mod(int, const char *, struct snmp_secmod_def *);
/* find a security service definition */
struct snmp_secmod_def *find_sec_mod(int);
/* register a security service */
int unregister_sec_mod(int); /* register a security service */
SNMPCallback set_default_secmod;
void init_secmod(void);

#endif /* SNMPSECMOD_H */
