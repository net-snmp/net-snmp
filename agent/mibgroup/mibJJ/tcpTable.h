/*
 *  TCP MIB group interface - tcp.h
 *
 */
#ifndef _MIBGROUP_TCPTABLE_H
#define _MIBGROUP_TCPTABLE_H

#ifdef linux
struct inpcb {
        struct  inpcb *inp_next;        /* pointers to other pcb's */
        struct  in_addr inp_faddr;      /* foreign host table entry */
        u_short inp_fport;              /* foreign port */
        struct  in_addr inp_laddr;      /* local host table entry */
        u_short inp_lport;              /* local port */
	int     inp_state;
	int     uid;			/* owner of the connection */
};
#endif

#define TCPCONNSTATE	    13
#define TCPCONNLOCALADDRESS 14
#define TCPCONNLOCALPORT    15
#define TCPCONNREMADDRESS   16
#define TCPCONNREMPORT	    17

#if !(defined(solaris2) || defined(linux))
extern int TCP_Count_Connections (void);
#endif

config_arch_require(solaris2, kernel_sunos5)
config_require(mibJJ/tcp util_funcs)

extern FindVarMethod var_tcpEntry;
void init_tcpTable( void );

#endif /* _MIBGROUP_TCPTABLE_H */
