extern int aflag, nflag;
extern int print_errors;
extern char *interface;
extern struct snmp_session *Session;

char *routename __P((struct in_addr));
char *netname __P((struct in_addr, u_long));
char *plural __P((int));
struct variable_list *getvarbyname __P((struct snmp_session *, oid *, int));

void intpr __P((int));
void intpro __P((int));
void protopr __P((char *));
void routepr __P((void));
void ip_stats __P((void));
void icmp_stats __P((void));
void tcp_stats __P((void));
void udp_stats __P((void));

void inetprint __P((struct in_addr *,u_short, char *));
void rt_stats __P((void));

struct protox *name2protox __P((char *));
struct protox *knownname __P((char *));

void get_ifname __P((char *, int));
