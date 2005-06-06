#ifndef IQUERY_H
#define IQUERY_H

void init_iquery(void);

netsnmp_session *iquery_user_session(      char* secName);
netsnmp_session *iquery_community_session( char* community, int version );
netsnmp_session *iquery_pdu_session(       netsnmp_pdu* pdu);
netsnmp_session *iquery_session( char* secName,   int   mpModel,
                                 int   secModel,  int   secLevel,
                               u_char* engineID, size_t engIDLen);


int iquery_get(        netsnmp_variable_list *list);
int iquery_get_session(netsnmp_variable_list *list,
                       netsnmp_session       *session);

int iquery_getnext(        netsnmp_variable_list *list);
int iquery_getnext_session(netsnmp_variable_list *list,
                           netsnmp_session       *session);

int iquery_walk(        netsnmp_variable_list *list);
int iquery_walk_session(netsnmp_variable_list *list,
                        netsnmp_session       *session);

int iquery_set(        netsnmp_variable_list *list);
int iquery_set_session(netsnmp_variable_list *list,
                       netsnmp_session       *session);

#endif                          /* IQUERY_H */
