
#ifdef WIN32
#ifndef _WINSTUB_H_
#define _WINSTUB_H_

/* database access functions for host, services, protocols, networks */

/* sets can open. ends must close. */
void sethostent (int stay_open);
void setservent (int stay_open);
void setprotoent (int stay_open);
void setnetent (int stay_open);
void endhostent (void);
void endservent (void);
void endprotoent (void);
void endnetent (void);

/* get next entry from data base file, or from NIS if possible. */
/* returns 0 if there are no more entries to read. */
struct hostent *gethostent (void);
struct servent *getservent (void);
struct protoent *getprotoent (void);
struct netent *getnetent (void);

struct netent * getnetbyaddr (unsigned long net, int type);

/* Return the network number from an internet address */
u_long inet_netof(struct in_addr in);

/* Return the host number from an internet address */
u_long inet_lnaof(struct in_addr in);

#endif /*_WINSTUB_H_ */
#endif /* WIN32 */

