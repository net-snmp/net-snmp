/* HEADER Testing include_ifmib_iface_prefix (issue 1081) */

#ifndef USING_IF_MIB_DATA_ACCESS_INTERFACE_MODULE
printf("1..0 # skip if-mib/data_access/interface not enabled\n");
__did_plan = 1;
return 0;
#else
#include <net-snmp/data_access/interface.h>

SOCK_STARTUP;

init_agent("snmpd");
init_snmp("snmpd");
init_interface();

/* When no include_ifmib_iface_prefix is configured, all interfaces are included */
OK(netsnmp_access_interface_include("eth0") == TRUE, "eth0 included by default");
OK(netsnmp_access_interface_include("veth1234") == TRUE, "veth1234 included by default");
OK(netsnmp_access_interface_include("docker0") == TRUE, "docker0 included by default");

/* Configure include_ifmib_iface_prefix as described in issue #1081 */
netsnmp_config("include_ifmib_iface_prefix eno ens enp lo tun ppp eth");

/* Interfaces matching prefix should be included */
OK(netsnmp_access_interface_include("eth0") == TRUE, "eth0 included");
OK(netsnmp_access_interface_include("eth1") == TRUE, "eth1 included");
OK(netsnmp_access_interface_include("eno1") == TRUE, "eno1 included");
OK(netsnmp_access_interface_include("ens3") == TRUE, "ens3 included");
OK(netsnmp_access_interface_include("enp0s3") == TRUE, "enp0s3 included");
OK(netsnmp_access_interface_include("lo") == TRUE, "lo included");
OK(netsnmp_access_interface_include("tun0") == TRUE, "tun0 included");
OK(netsnmp_access_interface_include("ppp0") == TRUE, "ppp0 included");

/* Interfaces NOT starting with any of those prefixes should be excluded */
OK(netsnmp_access_interface_include("veth1234") == FALSE, "veth1234 excluded");
OK(netsnmp_access_interface_include("vethabcdef") == FALSE, "vethabcdef excluded");
OK(netsnmp_access_interface_include("docker0") == FALSE, "docker0 excluded");
OK(netsnmp_access_interface_include("br-1234") == FALSE, "br-1234 excluded");
OK(netsnmp_access_interface_include("wlan0") == FALSE, "wlan0 excluded");
OK(netsnmp_access_interface_include("dummy0") == FALSE, "dummy0 excluded");

/* Free config and re-test with duplicate prefix tokens */
free_config();
netsnmp_config("include_ifmib_iface_prefix eth eth wlan");
OK(netsnmp_access_interface_include("eth0") == TRUE, "eth0 included with duplicate config");
OK(netsnmp_access_interface_include("wlan0") == TRUE, "wlan0 included after duplicate config");
OK(netsnmp_access_interface_include("veth0") == FALSE, "veth0 excluded with duplicate config");

snmp_shutdown("snmpd");
shutdown_agent();

SOCK_CLEANUP;
#endif
