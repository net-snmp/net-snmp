/*
 * ioctl interface data access header
 *
 * $Id$
 */
#ifndef NETSNMP_ACCESS_INTERFACE_IOCTL_H
#define NETSNMP_ACCESS_INTERFACE_IOCTL_H

#ifdef __cplusplus
extern          "C" {
#endif

/**---------------------------------------------------------------------*/
/**/

int
netsnmp_access_interface_ioctl_physaddr_get(int fd,
                                            netsnmp_interface_entry *ifentry);

int
netsnmp_access_interface_ioctl_flags_get(int fd,
                                         netsnmp_interface_entry *ifentry);

int
netsnmp_access_interface_ioctl_flags_set(int fd,
                                         netsnmp_interface_entry *ifentry,
                                         unsigned int flags,
                                         int and_complement);

int
netsnmp_access_interface_ioctl_mtu_get(int fd,
                                       netsnmp_interface_entry *ifentry);

oid
netsnmp_access_interface_ioctl_ifindex_get(const char *name);

/**---------------------------------------------------------------------*/

# ifdef __cplusplus
}
#endif

#endif /* NETSNMP_ACCESS_INTERFACE_IOCTL_H */
