/* $Id$ */

/*
 * Smux module authored by Rohit Dube.
 */

#define NOTINIT  0
#define INIT     1

#define SMUXOK      0
#define SMUXNOTOK   -1

#define RTMIB    0
#define FTMIB    1
#define RIPMIB   2
#define BGPMIB   3
#define OSPFMIB  4
#define SMUXMIBS 5 /* one greater */

#define SMUXPORT 167

#define SMUXMAXPKTSIZE 1500
#define SMUXMAXSTRLEN  256

#define SMUX_OPEN 	(ASN_APPLICATION | ASN_CONSTRUCTOR | 0)
#define SMUX_CLOSE      (ASN_APPLICATION | ASN_PRIMITIVE | 1)
#define SMUX_RREQ       (ASN_APPLICATION | ASN_CONSTRUCTOR | 2)
#define SMUX_RRSP       (ASN_APPLICATION | ASN_PRIMITIVE | 3)
#define SMUX_SOUT       (ASN_APPLICATION | ASN_PRIMITIVE | 4)

#define SMUX_GET        (ASN_CONTEXT | ASN_CONSTRUCTOR | 0)
#define SMUX_GETNEXT    (ASN_CONTEXT | ASN_CONSTRUCTOR | 1)
#define SMUX_GETRSP     (ASN_CONTEXT | ASN_CONSTRUCTOR | 2)

extern int init_smux __P((void));
extern void smux_accept __P((int));
extern u_char *smux_snmp_process __P((int, oid *, int *, int *));
extern int smux_process __P((int));

static u_int rt_mib[] = {1, 3, 6, 1, 2, 1, 4, 21};
static u_int ft_mib[] = {1, 3, 6, 1, 2, 1, 4, 24};
static u_int ospf_mib[] = {1, 3, 6, 1, 2, 1, 14};
static u_int bgp_mib[] = {1, 3, 6, 1, 2, 1, 15};
static u_int rip_mib[] = {1, 3, 6, 1, 2, 1, 23};
