/*
 *  IPFWCHAINS-MIB group implementation - ipfwchains.c 
 *	This module reads the firewalling rules from the new (kernel 2.2)
 * 	ipchains firewalling code for Linux.
 *      Author : Didier.Dhaenens@rug.ac.be  from Atlantis, University of Ghent, Belgium.
 */

#include "../mib_module_config.h"
#include <config.h>
#include <sys/types.h>
#include <netdb.h>
#include <string.h>

/* mibincl.h contains all the snmp specific headers to define the
   return types and various defines and structures. */

#include "../mibincl.h"
#include "ipfwchains.h"
#include "libipfwc.h"
#include "../util_funcs.h"

struct icmp_names {
        const char *name;
        __u16 type;
        __u16 code_min, code_max;
        int use_code_min_for_testing;
};

const struct icmp_names icmp_codes[] = {
        { "echo-reply", 0, 0, 0xFFFF, TRUE },
        /* Alias */ { "pong", 0, 0, 0xFFFF, TRUE },

        { "destination-unreachable", 3, 0, 0xFFFF, FALSE },
        {   "network-unreachable", 3, 0, 0, TRUE },
        {   "host-unreachable", 3, 1, 1, TRUE },
        {   "protocol-unreachable", 3, 2, 2, TRUE },
        {   "port-unreachable", 3, 3, 3, TRUE },
        {   "fragmentation-needed", 3, 4, 4, TRUE },
        {   "source-route-failed", 3, 5, 5, TRUE },
        {   "network-unknown", 3, 6, 6, TRUE },
        {   "host-unknown", 3, 7, 7, TRUE },
        {   "network-prohibited", 3, 9, 9, TRUE },
        {   "host-prohibited", 3, 10, 10, TRUE },
        {   "TOS-network-unreachable", 3, 11, 11, TRUE },
        {   "TOS-host-unreachable", 3, 12, 12, TRUE },
        {   "communication-prohibited", 3, 13, 13, TRUE },
        {   "host-precedence-violation", 3, 14, 14, TRUE },
        {   "precedence-cutoff", 3, 15, 15, TRUE },

        { "source-quench", 4, 0, 0xFFFF, TRUE },

        { "redirect", 5, 0, 0xFFFF, FALSE },
        {   "network-redirect", 5, 0, 0, TRUE },
        {   "host-redirect", 5, 1, 1, TRUE },
        {   "TOS-network-redirect", 5, 2, 2, TRUE },
        {   "TOS-host-redirect", 5, 3, 3, TRUE },

        { "echo-request", 8, 0, 0xFFFF, TRUE },
        /* Alias */ { "ping", 8, 0, 0xFFFF, TRUE },

        { "router-advertisement", 9, 0, 0xFFFF, TRUE },

        { "router-solicitation", 10, 0, 0xFFFF, TRUE },

        { "time-exceeded", 11, 0, 0xFFFF, FALSE },
        /* Alias */ { "ttl-exceeded", 11, 0, 0xFFFF, FALSE },
        {   "ttl-zero-during-transit", 11, 0, 0, TRUE },
        {   "ttl-zero-during-reassembly", 11, 1, 1, TRUE },

        { "parameter-problem", 12, 0, 0xFFFF, FALSE },
        {   "ip-header-bad", 12, 0, 0, TRUE },
        {   "required-option-missing", 12, 1, 1, TRUE },

        { "timestamp-request", 13, 0, 0xFFFF, TRUE },

        { "timestamp-reply", 14, 0, 0xFFFF, TRUE },

        { "address-mask-request", 17, 0, 0xFFFF, TRUE },

        { "address-mask-reply", 18, 0, 0xFFFF, TRUE }
};   

static char *addr_to_host(struct in_addr *); 
static char *addr_to_dotted(struct in_addr *);
static char *addr_to_network(struct in_addr *); 
static char *addr_to_anyname(struct in_addr *);
static char *mask_to_dotted(struct in_addr *);
static char *port_to_service(int, unsigned short);
static char *service_to_string(__u16, __u16);   

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/


	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/


	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/

u_char * var_ipfwchains(
    struct variable *vp,
    oid     *name,
    int     *length,
    int     exact,
    int     *var_len,
    WriteMethod **write_method)
{
    static char string_value[256];
    static struct ipfwc_fwchain *chainnames;
    static int chainnames_initialized = 0;
    static unsigned int num_chains;
    __u64 cnt, cntkb, cntmb, cntgb;         

    if ( (!chainnames_initialized) || (name[*length-1]==1) ){
	printf("Initialising chaintable...\n");
	chainnames = ipfwc_get_chainnames(&num_chains);
	if (chainnames==NULL) return NULL;
	chainnames_initialized = 1;
    }

    if (!checkmib(vp,name,length,exact,var_len,write_method,num_chains)){
        printf("Match failed...\n");
   	return NULL;
    }

    switch (vp->magic){
	case IPFWCCHAININDEX:
	        long_return = name[*length-1];
	    	return (u_char *)&long_return;
	case IPFWCCHAINLABEL:
		*var_len = strlen(chainnames[name[*length-1]-1].label);
		return (u_char *) chainnames[name[*length-1]-1].label;
	case IPFWCPOLICY:
                *var_len = strlen(chainnames[name[*length-1]-1].policy);
                return (u_char *) chainnames[name[*length-1]-1].policy;  
	case IPFWCREFCNT:
		*var_len = sizeof(long int);
		long_return = chainnames[name[*length-1]-1].refcnt;
		return (u_char *)&long_return;	
	case IPFWCPKTS:
                cnt = chainnames[name[*length-1]-1].packets;
                        if (cnt > 99999) {
                                cntkb = (cnt + 500) / 1000;
                                if (cntkb > 9999) {
                                        cntmb = (cnt + 500000) / 1000000;
                                        if (cntmb > 9999) {
                                                cntgb = (cntmb + 500) / 1000;
                                                sprintf(string_value, "%lluG", cntgb);
                                        }
                                        else
                                                sprintf(string_value, "%lluM", cntmb);
                                } else
                                        sprintf(string_value, "%lluK", cntkb);
                        } else
                                sprintf(string_value, "%llu", cnt);   
		*var_len = strlen (string_value);
		return (u_char *)string_value; 
	case IPFWCBYTES:
                cnt = chainnames[name[*length-1]-1].bytes;
                        if (cnt > 99999) {
                                cntkb = (cnt + 500) / 1000;
                                if (cntkb > 9999) {
                                        cntmb = (cnt + 500000) / 1000000;
                                        if (cntmb > 9999) {
                                                cntgb = (cntmb + 500) / 1000;
                                                sprintf(string_value, "%lluG", cntgb);
                                        }
                                        else
                                                sprintf(string_value, "%lluM", cntmb);
                                } else
                                        sprintf(string_value, "%lluK", cntkb);
                        } else
                                sprintf(string_value, "%llu", cnt);    
                *var_len = strlen (string_value);
                return (u_char *)string_value;
	default:
	    ERROR_MSG("Oops...\n");
    }
    return NULL;
}

u_char * var_ipfwrules(
    struct variable *vp,
    oid     *name,
    int     *length,
    int     exact,
    int     *var_len,
    WriteMethod **write_method)
{
    static char string_value[256];
    static char buf[256];
    static struct ipfwc_fwrule *rules;
    static int rules_initialized = 0;
    static unsigned int num_rules;
    static struct protoent *protocol;
    unsigned short flags;
    __u64 cnt, cntkb, cntmb, cntgb;

/*    if ( (!rules_initialized) ||( (name[*length-1]==1)&&(name[*length-2]==1)) ){ */
    if (  (name[*length-1]==1)&&(name[*length-2]==1) ) { 
	printf("Initialising ruletable...\n");
        rules = ipfwc_get_rules(&num_rules,0);
        if (rules==NULL) return NULL;
        rules_initialized = 1;
    }

    if (!checkmib(vp,name,length,exact,var_len,write_method,num_rules)){
        printf("Match failed...\n");
        return NULL;
    }

    switch (vp->magic){
        case IPFWRRULEINDEX:
		long_return = name[*length-1];
		return (u_char *)&long_return;     
        case IPFWRCHAIN:
                *var_len = strlen(rules[name[*length-1]-1].chain[0].label);
                return (u_char *) rules[name[*length-1]-1].chain[0].label; 
        case IPFWRPKTS:
		printf ("case IPFWRPKTS\n");
                cnt = rules[name[*length-1]-1].packets;
                        if (cnt > 99999) {
                                cntkb = (cnt + 500) / 1000;
                                if (cntkb > 9999) {
                                        cntmb = (cnt + 500000) / 1000000;
                                        if (cntmb > 9999) {
                                                cntgb = (cntmb + 500) / 1000;
                                                sprintf(string_value, "%lluG", cntgb);
                                        }
                                        else
                                                sprintf(string_value, "%lluM", cntmb);
                                } else
                                        sprintf(string_value, "%lluK", cntkb);
                        } else 
                                sprintf(string_value, "%llu", cnt);   
                *var_len = strlen (string_value);
                return (u_char *) string_value;   


        case IPFWRBYTES:
                cnt = rules[name[*length-1]-1].bytes;
                        if (cnt > 99999) {
                                cntkb = (cnt + 500) / 1000;
                                if (cntkb > 9999) {
                                        cntmb = (cnt + 500000) / 1000000;
                                        if (cntmb > 9999) {
                                                cntgb = (cntmb + 500) / 1000;
                                                sprintf(string_value, "%lluG", cntgb);
                                        }
                                        else
                                                sprintf(string_value, "%lluM", cntmb);
                                } else
                                        sprintf(string_value, "%lluK", cntkb);
                        } else  
                                sprintf(string_value, "%llu", cnt);  
                *var_len = strlen (string_value);
                return (u_char *)string_value;  
        case IPFWRTARGET:
                *var_len = strlen(rules[name[*length-1]-1].ipfw.label);
                return (u_char *) rules[name[*length-1]-1].ipfw.label;   
        case IPFWRPROT:
		protocol = getprotobynumber( (int) rules[name[*length-1]-1].ipfw.ipfw.fw_proto);
		if (!strcmp(protocol->p_name,"ip" )) strcpy (protocol->p_name,"all");
		*var_len = strlen (protocol->p_name);
		return (u_char *) protocol->p_name;
        case IPFWRSOURCE:
        	if (rules[name[*length-1]-1].ipfw.ipfw.fw_invflg & IP_FW_INV_SRCIP)  sprintf(string_value,"!");
		else strcpy(string_value,"");   
        	if (rules[name[*length-1]-1].ipfw.ipfw.fw_smsk.s_addr == 0L)
                	strcat(string_value,"anywhere");
        	else {
                        sprintf(buf, "%s", addr_to_anyname(&(rules[name[*length-1]-1].ipfw.ipfw.fw_src)));
               	 	strcat(buf, mask_to_dotted(&(rules[name[*length-1]-1].ipfw.ipfw.fw_smsk)));
                	strcat(string_value,buf);
        		}
		printf("%s\n",string_value);
		*var_len = strlen(string_value);
		return (u_char *) string_value;  
        case IPFWRDESTINATION:
                if (rules[name[*length-1]-1].ipfw.ipfw.fw_invflg & IP_FW_INV_DSTIP)  sprintf(string_value,"!");
                else strcpy(string_value,"");
                if (rules[name[*length-1]-1].ipfw.ipfw.fw_dmsk.s_addr == 0L)
                        strcat(string_value,"anywhere");
                else {
                        sprintf(buf, "%s", addr_to_anyname(&(rules[name[*length-1]-1].ipfw.ipfw.fw_dst)));
                        strcat(buf, mask_to_dotted(&(rules[name[*length-1]-1].ipfw.ipfw.fw_dmsk)));
                        strcat(string_value,buf);
                        }
                printf("%s\n",string_value);
                *var_len = strlen(string_value);
                return (u_char *) string_value;      
        case IPFWRPORTS:
        	if (rules[name[*length-1]-1].ipfw.ipfw.fw_proto != IPPROTO_TCP
            		&& rules[name[*length-1]-1].ipfw.ipfw.fw_proto != IPPROTO_UDP
            		&& rules[name[*length-1]-1].ipfw.ipfw.fw_proto != IPPROTO_ICMP) {
                		sprintf(string_value,"n/a");
				*var_len = strlen(string_value);
                		return (u_char *) string_value;
        	}
 
        	/* ICMP handled specially. */
        	if (rules[name[*length-1]-1].ipfw.ipfw.fw_proto == IPPROTO_ICMP
            	   && !(rules[name[*length-1]-1].ipfw.ipfw.fw_invflg & IP_FW_INV_SRCPT)
            	   && !(rules[name[*length-1]-1].ipfw.ipfw.fw_invflg & IP_FW_INV_DSTPT)) {
                      unsigned int i;
                      for (i = 0; i < sizeof(icmp_codes)/sizeof(struct icmp_names); i++) {
                            if (icmp_codes[i].type == rules[name[*length-1]-1].ipfw.ipfw.fw_spts[0]
                               && icmp_codes[i].type == rules[name[*length-1]-1].ipfw.ipfw.fw_spts[1]
                               && icmp_codes[i].code_min == rules[name[*length-1]-1].ipfw.ipfw.fw_dpts[0]
                               && icmp_codes[i].code_max == rules[name[*length-1]-1].ipfw.ipfw.fw_dpts[1]) {
                                   sprintf(string_value, "%s", icmp_codes[i].name);
				   *var_len = strlen(string_value);  
				   return (u_char *) string_value;
                               }
                      }
        	}

        	sprintf(string_value, rules[name[*length-1]-1].ipfw.ipfw.fw_invflg & IP_FW_INV_SRCPT ? "!" : "");
        	if (rules[name[*length-1]-1].ipfw.ipfw.fw_spts[0] == 0 && rules[name[*length-1]-1].ipfw.ipfw.fw_spts[1] == 0xFFFF)
                   strcat(string_value, "any");
        	else if (rules[name[*length-1]-1].ipfw.ipfw.fw_spts[0] == rules[name[*length-1]-1].ipfw.ipfw.fw_spts[1]) {
		   strcat(string_value, service_to_string(rules[name[*length-1]-1].ipfw.ipfw.fw_spts[0], rules[name[*length-1]-1].ipfw.ipfw.fw_proto));
        	}
        	else {
                   strcat(string_value, service_to_string(rules[name[*length-1]-1].ipfw.ipfw.fw_spts[0], rules[name[*length-1]-1].ipfw.ipfw.fw_proto));   
		   strcat(string_value,":");
                   strcat(string_value, service_to_string(rules[name[*length-1]-1].ipfw.ipfw.fw_spts[1], rules[name[*length-1]-1].ipfw.ipfw.fw_proto));  
        	}
		strcat (string_value," -> ");
                strcat(string_value, rules[name[*length-1]-1].ipfw.ipfw.fw_invflg & IP_FW_INV_DSTPT ? "!" : "");
                if (rules[name[*length-1]-1].ipfw.ipfw.fw_dpts[0] == 0 && rules[name[*length-1]-1].ipfw.ipfw.fw_dpts[1] == 0xFFFF)
                   strcat(string_value, "any");
                else if (rules[name[*length-1]-1].ipfw.ipfw.fw_dpts[0] == rules[name[*length-1]-1].ipfw.ipfw.fw_dpts[1]) {
                   strcat(string_value, service_to_string(rules[name[*length-1]-1].ipfw.ipfw.fw_dpts[0], rules[name[*length-1]-1].ipfw.ipfw.fw_proto));
                }
                else {
                   strcat(string_value, service_to_string(rules[name[*length-1]-1].ipfw.ipfw.fw_dpts[0], rules[name[*length-1]-1].ipfw.ipfw.fw_proto));
                   strcat(string_value,":");
                   strcat(string_value, service_to_string(rules[name[*length-1]-1].ipfw.ipfw.fw_dpts[1], rules[name[*length-1]-1].ipfw.ipfw.fw_proto));
                }    
                *var_len = strlen(string_value);
                return (u_char *) string_value;  
        case IPFWROPT:
		flags = rules[name[*length-1]-1].ipfw.ipfw.fw_flg;
                sprintf(string_value, (rules[name[*length-1]-1].ipfw.ipfw.fw_invflg & IP_FW_INV_SYN) ? "!" : "-");
                strcat(string_value, (flags & IP_FW_F_TCPSYN) ? "y" : "-");
                strcat(string_value, (rules[name[*length-1]-1].ipfw.ipfw.fw_invflg & IP_FW_INV_FRAG) ? "!" : "-");
                strcat(string_value, (flags & IP_FW_F_FRAG) ? "f" : "-");
                strcat(string_value, (flags & IP_FW_F_PRN) ? "l" : "-");
                strcat(string_value, (flags & IP_FW_F_NETLINK) ? "o" : "-");
                *var_len = strlen(string_value);
                return (u_char *) string_value;    
        case IPFWRIFNAME:
                sprintf(string_value, rules[name[*length-1]-1].ipfw.ipfw.fw_invflg & IP_FW_INV_VIA ? "!" : "");
                if (rules[name[*length-1]-1].ipfw.ipfw.fw_flg & IP_FW_F_WILDIF && (rules[name[*length-1]-1].ipfw.ipfw.fw_vianame)[0]) {
                        rules[name[*length-1]-1].ipfw.ipfw.fw_vianame[strlen(rules[name[*length-1]-1].ipfw.ipfw.fw_vianame)+1]='\0';
                        rules[name[*length-1]-1].ipfw.ipfw.fw_vianame[strlen(rules[name[*length-1]-1].ipfw.ipfw.fw_vianame)]='+';
                }
                strcat(string_value, (rules[name[*length-1]-1].ipfw.ipfw.fw_vianame)[0] ? rules[name[*length-1]-1].ipfw.ipfw.fw_vianame : "any");
                *var_len = strlen(string_value);
                return (u_char *) string_value;    
        case IPFWRTOSA:
                sprintf(string_value, "0x%02hX", (unsigned short) rules[name[*length-1]-1].ipfw.ipfw.fw_tosand);
                *var_len = strlen(string_value);
                return (u_char *) string_value;
        case IPFWRTOSX:
                sprintf(string_value, "0x%02hX", (unsigned short) rules[name[*length-1]-1].ipfw.ipfw.fw_tosxor);
                *var_len = strlen(string_value);
                return (u_char *) string_value;   
        case IPFWRMARK:
                if (rules[name[*length-1]-1].ipfw.ipfw.fw_flg & IP_FW_F_MARKABS)
                        sprintf(string_value, "0x%x",rules[name[*length-1]-1].ipfw.ipfw.fw_mark);
                else if (rules[name[*length-1]-1].ipfw.ipfw.fw_mark == 0)
                        strcpy(string_value,"");
                else
                        sprintf(string_value, "0x%x", (int)rules[name[*length-1]-1].ipfw.ipfw.fw_mark);
                *var_len = strlen(string_value);
                return (u_char *) string_value;     
        case IPFWROUTSIZE:
                if ((rules[name[*length-1]-1].ipfw.ipfw.fw_flg & IP_FW_F_NETLINK) && (rules[name[*length-1]-1].ipfw.ipfw.fw_outputsize != 0xFFFF))
                        sprintf(string_value, "%hu", rules[name[*length-1]-1].ipfw.ipfw.fw_outputsize);
                else
                        strcpy(string_value,"");
                *var_len = strlen(string_value);
                return (u_char *)string_value;
        default:
            ERROR_MSG("Oops...\n");
    }
    return NULL;
}             

	/*********************
	 *
	 *  Internal implementation functions
	 *
	 *********************/

static char* addr_to_host(struct in_addr *addr)
{
        struct hostent *host;
        if ((host = gethostbyaddr((char *) addr, sizeof(struct in_addr), AF_INET)) != NULL)
                return (char *) host->h_name;
        else
                return (char *) NULL;
}
 
static char* addr_to_network(struct in_addr *addr)
{
        struct netent *net;
        if ((net = getnetbyaddr((long) ntohl(addr->s_addr), AF_INET)) != NULL)
                return (char *) net->n_name;
        else
                return (char *) NULL;
}

static char* addr_to_anyname(struct in_addr *addr)
{
        char *name;
        if ((name = addr_to_host(addr)) != NULL)
                return name;
        else if ((name = addr_to_network(addr)) != NULL)
                return name;
        else
                return addr_to_dotted(addr);
}
 
static char* addr_to_dotted(struct in_addr *addrp)
{
        static char buf[20];
        unsigned char *bytep;
        bytep = (unsigned char *) &(addrp->s_addr);
        sprintf(buf, "%d.%d.%d.%d", bytep[0], bytep[1], bytep[2], bytep[3]);
        return buf;
}
 
static char* mask_to_dotted(struct in_addr *mask)
{
        int i;
        static char buf[20];
        __u32 maskaddr, bits;

        maskaddr = ntohl(mask->s_addr);
        if (maskaddr == 0xFFFFFFFFL)
                /* we don't want to see "/32" */
                return "";
        else {
                i = 32;
                bits = 0xFFFFFFFEL;
                while (--i >= 0 && maskaddr != bits)
                        bits <<= 1;
                if (i >= 0)
                        sprintf(buf, "/%d", i);
                else
                        /* mask was not a decent combination of 1's and 0's */
                        sprintf(buf, "/%s", addr_to_dotted(mask));
                return buf;
        }
}
 
static char* port_to_service(int port, unsigned short proto)
{
        struct servent *service;

        if (proto == IPPROTO_TCP && (service = getservbyport(htons(port), "tcp")) != NULL)
                return service->s_name;
        else if (proto == IPPROTO_UDP &&
                        (service = getservbyport(htons(port), "udp")) != NULL)
                return service->s_name;
        else
                return (char *) NULL;
}
 
static char* service_to_string(__u16 port, __u16 proto)
{
	static char *service;
	char buf[30];
	if ( (service=port_to_service(port,proto))==NULL){ 
		sprintf(buf,"%u",port);
		return buf;
	}
	return service;
}
