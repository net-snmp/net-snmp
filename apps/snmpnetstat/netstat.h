extern int aflag, nflag;
extern int print_errors;
extern char *intrface;
extern struct snmp_session *Session;

char *routename (struct in_addr);
char *netname (struct in_addr, u_long);
const char *plural (int);
struct variable_list *getvarbyname (struct snmp_session *, oid *, size_t);

void intpr (int);
void intpro (int);
void protopr (const char *);
void routepr (void);
void ip_stats (void);
void icmp_stats (void);
void tcp_stats (void);
void udp_stats (void);

void inetprint (struct in_addr *,u_short, const char *);
void rt_stats (void);

struct protox *name2protox (const char *);
struct protox *knownname (const char *);

void get_ifname (char *, int);
