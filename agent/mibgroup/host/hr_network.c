/*
 *  Host Resources MIB - network device group implementation - hr_network.c
 *
 */

#include <config.h>


#include "host_res.h"
#include "mibII/interfaces.h"
#include "hr_network.h"


	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

void  Init_HR_Network __P((void));
int   Get_Next_HR_Network __P((void));
void  Save_HR_Network_Info __P((void));

char *describe_networkIF __P((int));
int   network_status __P((int));
int   network_errors __P((int));
int header_hrnet __P((struct variable *,oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *,oid *,int)) ));

#define HRN_MONOTONICALLY_INCREASING

	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/


void	init_hr_network( )
{
    init_device[ HRDEV_NETWORK ] = &Init_HR_Network;	
    next_device[ HRDEV_NETWORK ] = &Get_Next_HR_Network;
    save_device[ HRDEV_NETWORK ] = &Save_HR_Network_Info;	
#ifdef HRN_MONOTONICALLY_INCREASING
    dev_idx_inc[ HRDEV_NETWORK ] = 1;
#endif

    device_descr[ HRDEV_NETWORK ] = &describe_networkIF;
    device_status[ HRDEV_NETWORK ] = &network_status;
    device_errors[ HRDEV_NETWORK ] = &network_errors;
}

#define MATCH_FAILED	-1
#define MATCH_SUCCEEDED	0

int
header_hrnet(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method) __P((int, u_char *,u_char, int, u_char *,oid*, int));
{
#define HRNET_ENTRY_NAME_LENGTH	11
    oid newname[MAX_NAME_LEN];
    int net_idx;
    int result;
    int LowIndex = -1;
    char c_oid[MAX_NAME_LEN];

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP("var_hrnet: %s %d\n", c_oid, exact);
    }

    memcpy( (char *)newname,(char *)vp->name, (int)vp->namelen * sizeof(oid));
	/* Find "next" net entry */

    Init_HR_Network();
    for ( ;; ) {
        net_idx = Get_Next_HR_Network();
        if ( net_idx == -1 )
	    break;
	newname[HRNET_ENTRY_NAME_LENGTH] = net_idx;
        result = compare(name, *length, newname, (int)vp->namelen + 1);
        if (exact && (result == 0)) {
	    LowIndex = net_idx;
            break;
	}
	if (!exact && (result < 0) &&
		(LowIndex == -1 || net_idx < LowIndex )) {
	    LowIndex = net_idx;
#ifdef HRN_MONOTONICALLY_INCREASING
	    break;
#endif
	}
    }

    if ( LowIndex == -1 ) {
        DEBUGP("... index out of range\n");
        return(MATCH_FAILED);
    }

    newname[HRNET_ENTRY_NAME_LENGTH] = LowIndex;
    memcpy( (char *)name,(char *)newname, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP("... get net stats %s\n", c_oid);
    }
    return LowIndex;
}


	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/


u_char	*
var_hrnet(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, u_char *,u_char, int, u_char *,oid*, int));
{
    int  net_idx;

    net_idx = header_hrnet(vp, name, length, exact, var_len, write_method);
    if ( net_idx == MATCH_FAILED )
	return NULL;
        

    switch (vp->magic){
	case HRNET_IFINDEX:
	    long_return = net_idx & ((1<<HRDEV_TYPE_SHIFT)-1);
	    return (u_char *)&long_return;
	default:
	    ERROR_MSG("");
    }
    return NULL;
}


	/*********************
	 *
	 *  Internal implementation functions
	 *
	 *********************/


static short		HRN_index;
static char		HRN_name[16];
static struct ifnet	HRN_ifnet;
static struct in_ifaddr	HRN_ifaddr;	/* Not used */

static char		HRN_savedName[16];
static u_short		HRN_savedFlags;;
static int		HRN_savedErrors;;


void
Init_HR_Network __P((void))
{
#ifndef solaris2
   Interface_Scan_Init();
#endif
}

int
Get_Next_HR_Network __P((void))
{
#ifndef solaris2
    if (Interface_Scan_Next( &HRN_index, HRN_name, &HRN_ifnet, &HRN_ifaddr))
        return ( HRDEV_NETWORK << HRDEV_TYPE_SHIFT ) + HRN_index;
    else
#endif
        return -1;
}

void
Save_HR_Network_Info __P((void))
{
   strcpy( HRN_savedName, HRN_name);
   HRN_savedFlags  = HRN_ifnet.if_flags;
   HRN_savedErrors = HRN_ifnet.if_ierrors + HRN_ifnet.if_oerrors;
}


char *
describe_networkIF( idx )
    int idx;
{
    static char string[100];

    sprintf( string, "network interface %s", HRN_savedName );
    return string;
}


int
network_status( idx )
    int idx;
{
    if ( HRN_savedFlags & IFF_UP )
	return 2;		/* running */
    else
	return 5;		/* down */
}

int
network_errors( idx )
    int idx;
{
    return HRN_savedErrors;
}
