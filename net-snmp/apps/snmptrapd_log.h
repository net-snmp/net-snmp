#ifndef  _SNMPTRAPD_LOG_H
#define  _SNMPTRAPD_LOG_H

int realloc_format_trap      (u_char **buf, size_t *buf_len, size_t *out_len,
                              int allow_realloc,
                              const char *format_str, 
                              struct snmp_pdu *pdu);

int realloc_format_plain_trap(u_char **buf, size_t *buf_len, size_t *out_len,
                              int allow_realloc,
                              struct snmp_pdu *pdu);

#endif/* _SNMPTRAPD_LOG_H */
