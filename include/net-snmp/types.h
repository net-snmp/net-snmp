/*
 * Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 *
 * Portions of this file are copyrighted by:
 * Copyright (c) 2016 VMware, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */

#ifndef NET_SNMP_TYPES_H
#define NET_SNMP_TYPES_H

    /**
     *  Definitions of data structures, used within the library API.
     */

#include <stdio.h>

#ifndef NET_SNMP_CONFIG_H
#error "Please include <net-snmp/net-snmp-config.h> before this file"
#endif

#include <sys/types.h>

#if defined(WIN32) && !defined(cygwin)
typedef HANDLE netsnmp_pid_t;
#define NETSNMP_NO_SUCH_PROCESS INVALID_HANDLE_VALUE
#else
/*
 * Note: on POSIX-compliant systems, pid_t is defined in <sys/types.h>.
 * And if pid_t has not been defined in <sys/types.h>, AC_TYPE_PID_T ensures
 * that a pid_t definition is present in net-snmp-config.h.
 */
typedef pid_t netsnmp_pid_t;
#define NETSNMP_NO_SUCH_PROCESS -1
#endif

#include <net-snmp/library/oid.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HAVE_SOCKLEN_T
#ifdef WIN32
typedef int socklen_t;
#else
typedef u_int socklen_t;
#endif
#endif

#ifndef HAVE_SSIZE_T
#if defined(__INT_MAX__) && __INT_MAX__ == 2147483647
typedef int ssize_t;
#else
typedef long ssize_t;
#endif
#endif

#ifndef HAVE_NFDS_T
typedef unsigned long int nfds_t;
#endif

#if defined(HAVE_PCRE2_H) || defined(HAVE_PCRE_H)
/*
 * Abstract the pcre typedef such that not all *.c files have to include
 * <pcre.h>.
 */
typedef struct {
    void *regex_ptr;
} netsnmp_regex_ptr;
#endif
 
    /*
     *  For the initial release, this will just refer to the
     *  relevant UCD header files.
     *    In due course, the types and structures relevant to the
     *  Net-SNMP API will be identified, and defined here directly.
     *
     *  But for the time being, this header file is primarily a placeholder,
     *  to allow application writers to adopt the new header file names.
     */

typedef union {
   long           *integer;
   u_char         *string;
   oid            *objid;
   u_char         *bitstring;
   struct counter64 *counter64;
#ifdef NETSNMP_WITH_OPAQUE_SPECIAL_TYPES
   float          *floatVal;
   double         *doubleVal;
   /*
    * t_union *unionVal; 
    */
#endif                          /* NETSNMP_WITH_OPAQUE_SPECIAL_TYPES */
} netsnmp_vardata;


#define MIN_OID_LEN	    2
#define MAX_OID_LEN	    128 /* max subid's in an oid */

/** @typedef struct variable_list netsnmp_variable_list
 * Typedefs the variable_list struct into netsnmp_variable_list */
/** @struct variable_list
 * The netsnmp variable list binding structure, it's typedef'd to
 * netsnmp_variable_list.
 */
typedef struct variable_list {
   /** NULL for last variable */
   struct variable_list *next_variable;    
   /** Object identifier of variable */
   oid            *name;   
   /** number of subid's in name */
   size_t          name_length;    
   /** ASN type of variable */
   u_char          type;   
   /** value of variable */
    netsnmp_vardata val;
   /** the length of the value to be copied into buf */
   size_t          val_len;
   /** buffer to hold the OID */
   oid             name_loc[MAX_OID_LEN];  
   /** 90 percentile < 40. */
   u_char          buf[40];
   /** (Opaque) hook for additional data */
   void           *data;
   /** callback to free above */
   void            (*dataFreeHook)(void *);    
   int             index;
} netsnmp_variable_list;


/** @typedef struct snmp_pdu to netsnmp_pdu
 * Typedefs the snmp_pdu struct into netsnmp_pdu */
/** @struct snmp_pdu
 * The snmp protocol data unit.
 */	
typedef struct snmp_pdu {

#define non_repeaters	errstat
#define max_repetitions errindex

    /*
     * Protocol-version independent fields
     */
    /** snmp version */
    long            version;
    /** Type of this PDU */	
    int             command;
    /** Request id - note: incremented for each retry */
    long            reqid;  
    /** Message id for V3 messages note: incremented for each retry */
    long            msgid;
    /** Unique ID for incoming transactions */
    long            transid;
    /** Session id for AgentX messages */
    long            sessid;
    /** Error status (non_repeaters in GetBulk) */
    long            errstat;
    /** Error index (max_repetitions in GetBulk) */
    long            errindex;       
    /** Uptime */
    u_long          time;   
    u_long          flags;

    int             securityModel;
    /** noAuthNoPriv, authNoPriv, authPriv */
    int             securityLevel;  
    int             msgParseModel;

    /** smallest of max for transport, v3 msgMaxSize and local cfg. */
    long            msgMaxSize;

    /**
     * Transport-specific opaque data.  This replaces the IP-centric address
     * field.  
     */
    
    void           *transport_data;
    int             transport_data_length;

    /**
     * The actual transport domain.  This SHOULD NOT BE FREE()D.  
     */

    const oid      *tDomain;
    size_t          tDomainLen;

    netsnmp_variable_list *variables;


    /*
     * SNMPv1 & SNMPv2c fields
     */
    /** community for outgoing requests. */
    u_char         *community;
    /** length of community name. */
    size_t          community_len;  

    /*
     * Trap information
     */
    /** System OID */
    oid            *enterprise;     
    size_t          enterprise_length;
    /** trap type */
    long            trap_type;
    /** specific type */
    long            specific_type;
    /** This is ONLY used for v1 TRAPs  */
    unsigned char   agent_addr[4];  

    /*
     *  SNMPv3 fields
     */
    /** context snmpEngineID */
    u_char         *contextEngineID;
    /** Length of contextEngineID */
    size_t          contextEngineIDLen;     
    /** authoritative contextName */
    char           *contextName;
    /** Length of contextName */
    size_t          contextNameLen;
    /** authoritative snmpEngineID for security */
    u_char         *securityEngineID;
    /** Length of securityEngineID */
    size_t          securityEngineIDLen;    
    /** on behalf of this principal */
    char           *securityName;
    /** Length of securityName. */
    size_t          securityNameLen;        
    
    /*
     * AgentX fields
     *      (also uses SNMPv1 community field)
     */
    int             priority;
    int             range_subid;
    
    void           *securityStateRef;
} netsnmp_pdu;


/**
 * @typedef struct snmp_session netsnmp_session
 * Typedefs the snmp_session struct into netsnmp_session.
 */
typedef struct snmp_session netsnmp_session;

/** for openssl this should match up with EVP_MAX_MD_SIZE */
#define USM_AUTH_KU_LEN     64
#define USM_PRIV_KU_LEN     64

typedef int        (*snmp_callback) (int, netsnmp_session *, int,
                                          netsnmp_pdu *, void *);
typedef int     (*netsnmp_callback) (int, netsnmp_session *, int,
                                          netsnmp_pdu *, void *);

struct netsnmp_container_s;

#ifndef NETSNMP_NO_TRAP_STATS
    /*
     * trap/inform statistics.
     *
     * all times are sysuptime
     */
typedef struct netsnmp_trap_stats_s {
    u_long   sent_count;
    u_long   sent_last_sent;

    u_long   sent_fail_count;
    u_long   sent_last_fail;

    u_long   ack_count;
    u_long   ack_last_rcvd;

    u_long   sec_err_count;
    u_long   sec_err_last;

    u_long   timeouts;
    u_long   sent_last_timeout;
} netsnmp_trap_stats;
#endif /* NETSNMP_NO_TRAP_STATS */

/** @struct snmp_session
 * The snmp session structure.
 */
struct snmp_session {
    /*
     * Protocol-version independent fields
     */
    /** snmp version */
    long            version;
    /** Number of retries before timeout. */
    int             retries;
    /** Number of uS until first timeout, then exponential backoff */
    long            timeout;        
    u_long          flags;
    struct snmp_session *subsession;
    struct snmp_session *next;

    /** name or address of default peer (may include transport specifier and/or port number) */
    char           *peername;
    /** UDP port number of peer. (NO LONGER USED - USE peername INSTEAD) */
    u_short         remote_port NETSNMP_ATTRIBUTE_DEPRECATED;
    /** My Domain name or dotted IP address, 0 for default */
    char           *localname;
    /** My UDP port number, 0 for default, picked randomly */
    u_short         local_port;     
    /**
     * Authentication function or NULL if null authentication is used 
     */
    u_char         *(*authenticator) (u_char *, size_t *, u_char *, size_t);
    /** Function to interpret incoming data */
    netsnmp_callback callback;      
    /**
     * Pointer to data that the callback function may consider important 
     */
    void           *callback_magic;
    /** copy of system errno */
    int             s_errno;
    /** copy of library errno */
    int             s_snmp_errno;   
    /** Session id - AgentX only */
    long            sessid; 

    /*
     * SNMPv1 & SNMPv2c fields
     */
    /** community for outgoing requests. */
    u_char         *community;
    /** Length of community name. */
    size_t          community_len;  
    /**  Largest message to try to receive.  */
    size_t          rcvMsgMaxSize;
    /**  Largest message to try to send.  */
    size_t          sndMsgMaxSize;  

    /*
     * SNMPv3 fields
     */
    /** are we the authoritative engine? */
    u_char          isAuthoritative;
    /** authoritative snmpEngineID */
    u_char         *contextEngineID;
    /** Length of contextEngineID */
    size_t          contextEngineIDLen;     
    /** initial engineBoots for remote engine */
    u_int           engineBoots;
    /** initial engineTime for remote engine */
    u_int           engineTime;
    /** authoritative contextName */
    char           *contextName;
    /** Length of contextName */
    size_t          contextNameLen;
    /** authoritative snmpEngineID */
    u_char         *securityEngineID;
    /** Length of contextEngineID */
    size_t          securityEngineIDLen;    
    /** on behalf of this principal */
    char           *securityName;
    /** Length of securityName. */
    size_t          securityNameLen;

    /** auth protocol oid */
    oid            *securityAuthProto;
    /** Length of auth protocol oid */
    size_t          securityAuthProtoLen;
    /** Ku for auth protocol XXX */
    u_char          securityAuthKey[USM_AUTH_KU_LEN];       
    /** Length of Ku for auth protocol */
    size_t          securityAuthKeyLen;
    /** Kul for auth protocol */
    u_char          *securityAuthLocalKey;       
    /** Length of Kul for auth protocol XXX */
    size_t          securityAuthLocalKeyLen;       

    /** priv protocol oid */
    oid            *securityPrivProto;
    /** Length of priv protocol oid */
    size_t          securityPrivProtoLen;
    /** Ku for privacy protocol XXX */
    u_char          securityPrivKey[USM_PRIV_KU_LEN];       
    /** Length of Ku for priv protocol */
    size_t          securityPrivKeyLen;
    /** Kul for priv protocol */
    u_char          *securityPrivLocalKey;       
    /** Length of Kul for priv protocol XXX */
    size_t          securityPrivLocalKeyLen;       

    /** snmp security model, v1, v2c, usm */
    int             securityModel;
    /** noAuthNoPriv, authNoPriv, authPriv */
    int             securityLevel;  
    /** target param name */
    char           *paramName;
#ifndef NETSNMP_NO_TRAP_STATS
    netsnmp_trap_stats *trap_stats;
#endif /* NETSNMP_NO_TRAP_STATS */

    /**
     * security module specific 
     */
    void           *securityInfo;

    /**
     * transport specific configuration 
     */
   struct netsnmp_container_s *transport_configuration;

    /**
     * use as you want data 
     *
     *     used by 'SNMP_FLAGS_RESP_CALLBACK' handling in the agent
     * XXX: or should we add a new field into this structure?
     */
    void           *myvoid;

    /**
     * session specific user
     */
    struct usmUser *sessUser;
};

typedef struct netsnmp_index_s {
    size_t          len;
    oid            *oids;
} netsnmp_index;

typedef struct netsnmp_void_array_s {
    size_t          size;
    void          **array;
} netsnmp_void_array;

/*
 * references to various types
 */
typedef struct netsnmp_ref_void_s {
    void           *val;
} netsnmp_ref_void;

typedef union {
    u_long          ul;
    u_int           ui;
    u_short         us;
    u_char          uc;
    long            sl;
    int             si;
    short           ss;
    char            sc;
    char           *cp;
    void           *vp;
} netsnmp_cvalue;

/*
 * Structure for holding a set of file descriptors, similar to fd_set.
 *
 * This structure however can hold so-called large file descriptors
 * (>= FD_SETSIZE or 1024) on Unix systems or more than FD_SETSIZE (64)
 * sockets on Windows systems.
 *
 * It is safe to allocate this structure on the stack.
 *
 * This structure must be initialized by calling netsnmp_large_fd_set_init()
 * and must be cleaned up via netsnmp_large_fd_set_cleanup(). If this last
 * function is not called this may result in a memory leak.
 *
 * The members of this structure are:
 * lfs_setsize: maximum set size.
 * lsf_setptr:  points to lfs_set if lfs_setsize <= FD_SETSIZE, and otherwise
 *              to dynamically allocated memory.
 * lfs_set:     file descriptor / socket set data if lfs_setsize <= FD_SETSIZE.
 */
typedef struct netsnmp_large_fd_set_s {
    unsigned        lfs_setsize;
    fd_set         *lfs_setptr;
    fd_set          lfs_set;
} netsnmp_large_fd_set;

#ifdef __cplusplus
}
#endif

#endif                          /* NET_SNMP_TYPES_H */
