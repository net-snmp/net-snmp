extern int aflag, nflag;
extern int print_errors;
extern char *interface;
extern struct snmp_session *Session;

char *routename __UCD_P((struct in_addr));
char *netname __UCD_P((struct in_addr, u_long));
char *plural __UCD_P((int));
struct variable_list *getvarbyname __UCD_P((struct snmp_session *, oid *, int));

void intpr __UCD_P((int));
void intpro __UCD_P((int));
void protopr __UCD_P((void));
void routepr __UCD_P((void));
void ip_stats __UCD_P((void));
void icmp_stats __UCD_P((void));
void tcp_stats __UCD_P((void));
void udp_stats __UCD_P((void));

void inetprint __UCD_P((struct in_addr *,u_short, char *));
void rt_stats __UCD_P((void));

struct protox *name2protox __UCD_P((char *));
struct protox *knownname __UCD_P((char *));

void get_ifname __UCD_P((char *, int));
