
#ifdef NETSNMP_CAN_USE_NLIST
extern void     init_kmem(const char *);
extern int      klookup(unsigned long, char *, int);
#define NETSNMP_KLOOKUP(x) klookup((unsigned long) x )
#endif

#if HAVE_KVM_H
#include <kvm.h>
extern kvm_t   *kd;
#endif
