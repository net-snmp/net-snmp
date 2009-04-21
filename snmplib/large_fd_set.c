#include <net-snmp/net-snmp-config.h>
#include <net-snmp/library/large_fd_set.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif

#if defined(_WIN32) || defined(_WIN64)

netsnmp_fd_set* netsnmp_fd_set_allocate(int setsize)
{
  return malloc(sizeof(netsnmp_fd_set)
                + (setsize > FD_SETSIZE ? setsize - FD_SETSIZE : 0) * sizeof(SOCKET));
}

int netsnmp_fd_clr(SOCKET fd, const netsnmp_fd_set* fdsetp)
{
  unsigned int i;

  for (i = 0; i < fdsetp->lfs_set.fd_count; i++)
  {
    if (fdsetp->lfs_set.fd_array[i] == fd)
      return 1;
  }
  return 0;
}

int netsnmp_fd_is_set(SOCKET fd, const netsnmp_fd_set* fdsetp)
{
  unsigned int i;

  for (i = 0; i < fdsetp->lfs_set.fd_count; i++)
  {
    if (fdsetp->lfs_set.fd_array[i] == fd)
      return 1;
  }
  return 0;
}

#else

netsnmp_fd_set* netsnmp_fd_set_allocate(int setsize)
{
  
  return malloc(sizeof(netsnmp_fd_set)
                + (setsize > FD_SETSIZE
                   ? (setsize + 8 * sizeof(long) - FD_SETSIZE - 1) / (8 * sizeof(long))
                   : 0)
                * sizeof(long));
}

#endif

void netsnmp_fd_set_free(netsnmp_fd_set* fdsetp)
{
  free(fdsetp);
}
