/*
 * Header file for Kerberos Security Model support
 */

#ifndef SNMPKSM_H
#define SNMPKSM_H

#ifdef __cplusplus
extern "C" {
#endif

int		ksm_rgenerate_out_msg(struct snmp_secmod_outgoing_params *);
int		ksm_process_in_msg(struct snmp_secmod_incoming_params *);
void		init_usm(void);

#ifdef __cplusplus
}
#endif

#endif /* SNMPKSM_H */
