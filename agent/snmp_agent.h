/*
 * snmp_agent.h
 *
 * External definitions for functions and variables in snmp_agent.c.
 */

#ifndef SNMP_AGENT_H
#define SNMP_AGENT_H

#ifdef __cplusplus
extern "C" {
#endif

#define SNMP_MAX_PDU_SIZE 64000 /* local constraint on PDU size sent by agent
                                  (see also SNMP_MAX_MSG_SIZE in snmp_api.h) */

/*  If non-zero, causes the addresses of peers to be logged when receptions
    occur.  */

extern int	log_addresses;

/*  How many ticks since we last aged the address cache entries.  */

extern int	lastAddrAge;



struct agent_snmp_session {
    int		mode;
    struct variable_list *start, *end;
    struct snmp_session  *session;
    struct snmp_pdu      *pdu;
    struct snmp_pdu      *orig_pdu;
    int		rw;
    int		exact;
    int		status;
    int		index;
    int		inclusive;
    
    struct request_list *outstanding_requests;
    struct agent_snmp_session *next;
};


/*  Address cache handling functions.  */

void 		snmp_addrcache_initialise	(void);
void		snmp_addrcache_age		(void);


/* config file parsing routines */
int handle_snmp_packet(int, struct snmp_session *, int, struct snmp_pdu *, void *);
int handle_next_pass( struct agent_snmp_session *);
int handle_var_list( struct agent_snmp_session *);
int handle_one_var( struct agent_snmp_session *, struct variable_list *varbind_ptr);
void snmp_agent_parse_config (char *, char *);
struct agent_snmp_session  *init_agent_snmp_session( struct snmp_session *, struct snmp_pdu *);
void free_agent_snmp_session( struct agent_snmp_session * );
void remove_and_free_agent_snmp_session(struct agent_snmp_session *asp);
void free_agent_snmp_session_by_session(struct snmp_session *sess,
				  void (*free_request)(struct request_list *));
int getNextSessID(void);
void dump_sess_list(void);
int init_master_agent(void);
int agent_check_and_process(int block);
struct agent_snmp_session  *get_current_agent_session(void);

/*  Register and de-register agent NSAPs.  */
 
struct _snmp_transport;
 
int	register_agent_nsap	(struct _snmp_transport *t);
void	deregister_agent_nsap	(int handle);

#ifdef __cplusplus
}
#endif

#endif
