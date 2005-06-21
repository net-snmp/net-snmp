#ifndef IQUERY_H
#define IQUERY_H

void init_iquery(void);

netsnmp_session *netsnmp_iquery_user_session(      char* secName);
netsnmp_session *netsnmp_iquery_community_session( char* community, int version );
netsnmp_session *netsnmp_iquery_pdu_session(netsnmp_pdu* pdu);
netsnmp_session *netsnmp_iquery_session( char* secName,  int   version,
                                        int   secModel,  int   secLevel,
                                      u_char* engineID, size_t engIDLen);

int netsnmp_iquery_get(     netsnmp_variable_list *list);
int netsnmp_iquery_getnext( netsnmp_variable_list *list);
int netsnmp_iquery_walk(    netsnmp_variable_list *list);
int netsnmp_iquery_set(     netsnmp_variable_list *list);

#endif                          /* IQUERY_H */
