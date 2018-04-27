#include <sys/types.h>

void     ARP_Scan_Init(void);
int      ARP_Scan_Next(in_addr_t *, char *, int *, u_long *, u_short *);
