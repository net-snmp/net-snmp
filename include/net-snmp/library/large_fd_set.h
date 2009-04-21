#ifndef LARGE_FD_SET_H
#define LARGE_FD_SET_H


#include <net-snmp/net-snmp-config.h>
#include <net-snmp/types.h>

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#if HAVE_WINSOCK_H
#include <winsock2.h>
#endif


#if defined(_WIN32) || defined(_WIN64)
#define NETSNMP_FD_SET(fd, fdsetp)                                \
  do {                                                          \
    unsigned __i;                                               \
    for (__i = 0; __i < (fdsetp)->lfs_set.fd_count; __i++)      \
    {                                                           \
      if ((fdsetp)->lfs_set.fd_array[__i] == (SOCKET)(fd))      \
        break;                                                  \
    }                                                           \
    if (__i == (fdsetp)->lfs_set.fd_count                       \
        && (fdsetp)->lfs_set.fd_count < (fdsetp)->lfs_setsize)  \
    {                                                           \
      (fdsetp)->lfs_set.fd_count++;                             \
      (fdsetp)->lfs_set.fd_array[__i] = (fd);                   \
    }                                                           \
  } while(0)
#define NETSNMP_FD_CLR(fd, fdsetp)                                \
  do {                                                          \
    int __i;                                           \
    for (__i = 0; __i < (fdsetp)->lfs_set.fd_count ; __i++)     \
    {                                                           \
      if ((fdsetp)->lfs_set.fd_array[__i] == (fd))              \
      {                                                         \
        while (__i < (fdsetp)->lfs_set.fd_count - 1)            \
        {                                                       \
          (fdsetp)->lfs_set.fd_array[__i] =                     \
            (fdsetp)->lfs_set.fd_array[__i+1];                  \
          __i++;                                                \
        }                                                       \
        (fdsetp)->lfs_set.fd_count--;                           \
        break;                                                  \
      }                                                         \
    }                                                           \
  } while(0)
#define NETSNMP_FD_ISSET(fd, fdsetp) large_fd_is_set(fd, fdsetp)
#define NETSNMP_FD_ZERO(fdsetp)      do { (fdsetp)->fd_count = 0; } while(0)
#else
#define NETSNMP_FD_SET(fd, fdsetp)   FD_SET(fd, &(fdsetp)->lfs_set)
#define NETSNMP_FD_CLR(fd, fdsetp)   FD_CLR(fd, &(fdsetp)->lfs_set)
#define NETSNMP_FD_ISSET(fd, fdsetp) FD_ISSET(fd, &(fdsetp)->lfs_set)
#define NETSNMP_FD_ZERO(fdsetp)                                           \
  do {                                                                  \
    int __i;                                                   \
    fd_set *__arr = &(fdsetp)->lfs_set;                                 \
    __i = (fdsetp)->lfs_setsize / (8 * sizeof((fdsetp)->lfs_set.fds_bits)); \
    for ( ; __i > 0; __i--)                                             \
      __arr->fds_bits[__i - 1] = 0;                                     \
  } while (0)
#endif


#ifdef __cplusplus
extern "C" {
#endif

netsnmp_fd_set* netsnmp_fd_set_allocate(int setsize);
           void netsnmp_fd_set_free(netsnmp_fd_set* fdsetp);
#if defined(_WIN32) || defined(_WIN64)
int netsnmp_fd_clr(   SOCKET fd, const netsnmp_fd_set* fdsetp);
int netsnmp_fd_is_set(SOCKET fd, const netsnmp_fd_set* fdsetp);
#endif

#ifdef __cplusplus
}
#endif

#endif /* LARGE_FD_SET_H */
