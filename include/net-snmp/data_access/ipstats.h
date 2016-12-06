/*
 * ipstats data access header
 *
 * $Id$
 */
#ifndef NETSNMP_ACCESS_IPSTATS_H
#define NETSNMP_ACCESS_IPSTATS_H

# ifdef __cplusplus
extern          "C" {
#endif

/**---------------------------------------------------------------------*/
/*
 * structure definitions
 */

/*
 * netsnmp_ipstats_entry
 */
typedef struct netsnmp_ipstats_s {

   struct counter64 HCInReceives;
   struct counter64 HCInOctets;
   u_long          InHdrErrors;
   u_long          InNoRoutes;
   u_long          InAddrErrors;
   u_long          InUnknownProtos;
   u_long          InTruncatedPkts;
   struct counter64 HCInForwDatagrams;
   u_long          ReasmReqds;
   u_long          ReasmOKs;
   u_long          ReasmFails;
   u_long          InDiscards;
   struct counter64 HCInDelivers;
   struct counter64 HCOutRequests;
   u_long          OutNoRoutes;
   struct counter64 HCOutForwDatagrams;
   u_long          OutDiscards;
   u_long          OutFragReqds;
   u_long          OutFragOKs;
   u_long          OutFragFails;
   u_long          OutFragCreates;
   struct counter64 HCOutTransmits;
   struct counter64 HCOutOctets;
   struct counter64 HCInMcastPkts;
   struct counter64 HCInMcastOctets;
   struct counter64 HCOutMcastPkts;
   struct counter64 HCOutMcastOctets;
   struct counter64 HCInBcastPkts;
   struct counter64 HCOutBcastPkts;

} netsnmp_ipstats;


# ifdef __cplusplus
}
#endif

#endif /* NETSNMP_ACCESS_IPSTATS_H */
