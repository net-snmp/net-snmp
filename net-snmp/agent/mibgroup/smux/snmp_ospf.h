/*
 *  snmp_ospf.h
 *
 */
#ifndef _MIBGROUP_SNMP_OSPF_H
#define _MIBGROUP_SNMP_OSPF_H

config_require(smux/smux)

u_char  *var_ospf __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));


#define ospfRouterId		0
#define ospfAdminStat		1
#define ospfVersionNumber		2
#define ospfAreaBdrRtrStatus		3
#define ospfASBdrRtrStatus		4
#define ospfExternLsaCount		5
#define ospfExternLsaCksumSum		6
#define ospfTOSSupport		7
#define ospfOriginateNewLsas		8
#define ospfRxNewLsas		9
#define ospfExtLsdbLimit		10
#define ospfMulticastExtensions		11
#define ospfAreaId		12
#define ospfAuthType		13
#define ospfImportAsExtern		14
#define ospfSpfRuns		15
#define ospfAreaBdrRtrCount		16
#define ospfAsBdrRtrCount		17
#define ospfAreaLsaCount		18
#define ospfAreaLsaCksumSum		19
#define ospfAreaSummary		20
#define ospfAreaStatus		21
#define ospfStubAreaId		22
#define ospfStubTOS		23
#define ospfStubMetric		24
#define ospfStubStatus		25
#define ospfStubMetricType		26
#define ospfLsdbAreaId		27
#define ospfLsdbType		28
#define ospfLsdbLsid		29
#define ospfLsdbRouterId		30
#define ospfLsdbSequence		31
#define ospfLsdbAge		32
#define ospfLsdbChecksum		33
#define ospfLsdbAdvertisement		34
#define ospfAreaRangeAreaId		35
#define ospfAreaRangeNet		36
#define ospfAreaRangeMask		37
#define ospfAreaRangeStatus		38
#define ospfAreaRangeEffect		39
#define ospfHostIpAddress		40
#define ospfHostTOS		41
#define ospfHostMetric		42
#define ospfHostStatus		43
#define ospfHostAreaID		44
#define ospfIfIpAddress		45
#define ospfAddressLessIf		46
#define ospfIfAreaId		47
#define ospfIfType		48
#define ospfIfAdminStat		49
#define ospfIfRtrPriority		50
#define ospfIfTransitDelay		51
#define ospfIfRetransInterval		52
#define ospfIfHelloInterval		53
#define ospfIfRtrDeadInterval		54
#define ospfIfPollInterval		55
#define ospfIfState		56
#define ospfIfDesignatedRouter		57
#define ospfIfBackupDesignatedRouter		58
#define ospfIfEvents		59
#define ospfIfAuthKey		60
#define ospfIfStatus		61
#define ospfIfMulticastForwarding		62
#define ospfIfMetricIpAddress		63
#define ospfIfMetricAddressLessIf		64
#define ospfIfMetricTOS		65
#define ospfIfMetricValue		66
#define ospfIfMetricStatus		67
#define ospfVirtIfAreaId		68
#define ospfVirtIfNeighbor		69
#define ospfVirtIfTransitDelay		70
#define ospfVirtIfRetransInterval		71
#define ospfVirtIfHelloInterval		72
#define ospfVirtIfRtrDeadInterval		73
#define ospfVirtIfState		74
#define ospfVirtIfEvents		75
#define ospfVirtIfAuthKey		76
#define ospfVirtIfStatus		77
#define ospfNbrIpAddr		78
#define ospfNbrAddressLessIndex		79
#define ospfNbrRtrId		80
#define ospfNbrOptions		81
#define ospfNbrPriority		82
#define ospfNbrState		83
#define ospfNbrEvents		84
#define ospfNbrLsRetransQLen		85
#define ospfNbmaNbrStatus		86
#define ospfNbmaNbrPermanence		87
#define ospfVirtNbrArea		88
#define ospfVirtNbrRtrId		89
#define ospfVirtNbrIpAddr		90
#define ospfVirtNbrOptions		91
#define ospfVirtNbrState		92
#define ospfVirtNbrEvents		93
#define ospfVirtNbrLsRetransQLen		94
#define ospfExtLsdbType		95
#define ospfExtLsdbLsid		96
#define ospfExtLsdbRouterId		97
#define ospfExtLsdbSequence		98
#define ospfExtLsdbAge		99
#define ospfExtLsdbChecksum		100
#define ospfExtLsdbAdvertisement		101
#define ospfAreaAggregateAreaID		102
#define ospfAreaAggregateLsdbType		103
#define ospfAreaAggregateNet		104
#define ospfAreaAggregateMask		105
#define ospfAreaAggregateStatus		106
#define ospfAreaAggregateEffect		107

#ifdef IN_SNMP_VARS_C

struct variable13 ospf_variables[108] = {
{ospfRouterId, ASN_IPADDRESS, RWRITE, var_ospf, 3, {1, 1, 1}},
{ospfAdminStat, ASN_INTEGER, RWRITE, var_ospf, 3, {1, 1, 2}},
{ospfVersionNumber, ASN_INTEGER, RONLY, var_ospf, 3, {1, 1, 3}},
{ospfAreaBdrRtrStatus, ASN_INTEGER, RONLY, var_ospf, 3, {1, 1, 4}},
{ospfASBdrRtrStatus, ASN_INTEGER, RWRITE, var_ospf, 3, {1, 1, 5}},
{ospfExternLsaCount, ASN_GAUGE, RONLY, var_ospf, 3, {1, 1, 6}},
{ospfExternLsaCksumSum, ASN_INTEGER, RONLY, var_ospf, 3, {1, 1, 7}},
{ospfTOSSupport, ASN_INTEGER, RWRITE, var_ospf, 3, {1, 1, 8}},
{ospfOriginateNewLsas, ASN_COUNTER, RONLY, var_ospf, 3, {1, 1, 9}},
{ospfRxNewLsas, ASN_COUNTER, RONLY, var_ospf, 3, {1, 1, 10, 0}},
{ospfExtLsdbLimit, ASN_INTEGER, RWRITE, var_ospf, 3, {1, 1, 11}},
{ospfMulticastExtensions, ASN_INTEGER, RWRITE, var_ospf, 3, {1, 1, 12}},
{ospfAreaId, ASN_IPADDRESS, RONLY, var_ospf, 3, {2, 1, 1}},
{ospfAuthType, ASN_INTEGER, RWRITE, var_ospf, 3, {2, 1, 2}},
{ospfImportAsExtern, ASN_INTEGER, RWRITE, var_ospf, 3, {2, 1, 3}},
{ospfSpfRuns, ASN_COUNTER, RONLY, var_ospf, 3, {2, 1, 4}},
{ospfAreaBdrRtrCount, ASN_GAUGE, RONLY, var_ospf, 3, {2, 1, 5}},
{ospfAsBdrRtrCount, ASN_GAUGE, RONLY, var_ospf, 3, {2, 1, 6}},
{ospfAreaLsaCount, ASN_GAUGE, RONLY, var_ospf, 3, {2, 1, 7}},
{ospfAreaLsaCksumSum, ASN_INTEGER, RONLY, var_ospf, 3, {2, 1, 8}},
{ospfAreaSummary, ASN_INTEGER, RWRITE, var_ospf, 3, {2, 1, 9}},
{ospfAreaStatus, ASN_INTEGER, RWRITE, var_ospf, 3, {2, 1, 10}},
{ospfStubAreaId, ASN_IPADDRESS, RONLY, var_ospf, 3, {3, 1, 1}},
{ospfStubTOS, ASN_INTEGER, RONLY, var_ospf, 3, {3, 1, 2}},
{ospfStubMetric, ASN_INTEGER, RWRITE, var_ospf, 3, {3, 1, 3}},
{ospfStubStatus, ASN_INTEGER, RWRITE, var_ospf, 3, {3, 1, 4}},
{ospfStubMetricType, ASN_INTEGER, RWRITE, var_ospf, 3, {3, 1, 5}},
{ospfLsdbAreaId, ASN_IPADDRESS, RONLY, var_ospf, 3, {4, 1, 1}},
{ospfLsdbType, ASN_INTEGER, RONLY, var_ospf, 3, {4, 1, 2}},
{ospfLsdbLsid, ASN_IPADDRESS, RONLY, var_ospf, 3, {4, 1, 3}},
{ospfLsdbRouterId, ASN_IPADDRESS, RONLY, var_ospf, 3, {4, 1, 4}},
{ospfLsdbSequence, ASN_INTEGER, RONLY, var_ospf, 3, {4, 1, 5}},
{ospfLsdbAge, ASN_INTEGER, RONLY, var_ospf, 3, {4, 1, 6}},
{ospfLsdbChecksum, ASN_INTEGER, RONLY, var_ospf, 3, {4, 1, 7}},
{ospfLsdbAdvertisement, ASN_OCTET_STR, RONLY, var_ospf, 3, {4, 1, 8}},
{ospfAreaRangeAreaId, ASN_IPADDRESS, RONLY, var_ospf, 3, {5, 1, 1}},
{ospfAreaRangeNet, ASN_IPADDRESS, RONLY, var_ospf, 3, {5, 1, 2}},
{ospfAreaRangeMask, ASN_IPADDRESS, RWRITE, var_ospf, 3, {5, 1, 3}},
{ospfAreaRangeStatus, ASN_INTEGER, RWRITE, var_ospf, 3, {5, 1, 4}},
{ospfAreaRangeEffect, ASN_INTEGER, RWRITE, var_ospf, 3, {5, 1, 5}},
{ospfHostIpAddress, ASN_IPADDRESS, RONLY, var_ospf, 3, {6, 1, 1}},
{ospfHostTOS, ASN_INTEGER, RONLY, var_ospf, 3, {6, 1, 2}},
{ospfHostMetric, ASN_INTEGER, RWRITE, var_ospf, 3, {6, 1, 3}},
{ospfHostStatus, ASN_INTEGER, RWRITE, var_ospf, 3, {6, 1, 4}},
{ospfHostAreaID, ASN_IPADDRESS, RONLY, var_ospf, 3, {6, 1, 5}},
{ospfIfIpAddress, ASN_IPADDRESS, RONLY, var_ospf, 3, {7, 1, 1}},
{ospfAddressLessIf, ASN_INTEGER, RONLY, var_ospf, 3, {7, 1, 2}},
{ospfIfAreaId, ASN_IPADDRESS, RWRITE, var_ospf, 3, {7, 1, 3}},
{ospfIfType, ASN_INTEGER, RWRITE, var_ospf, 3, {7, 1, 4}},
{ospfIfAdminStat, ASN_INTEGER, RWRITE, var_ospf, 3, {7, 1, 5}},
{ospfIfRtrPriority, ASN_INTEGER, RWRITE, var_ospf, 3, {7, 1, 6}},
{ospfIfTransitDelay, ASN_INTEGER, RWRITE, var_ospf, 3, {7, 1, 7}},
{ospfIfRetransInterval, ASN_INTEGER, RWRITE, var_ospf, 3, {7, 1, 8}},
{ospfIfHelloInterval, ASN_INTEGER, RWRITE, var_ospf, 3, {7, 1, 9}},
{ospfIfRtrDeadInterval, ASN_INTEGER, RWRITE, var_ospf, 3, {7, 1, 10}},
{ospfIfPollInterval, ASN_INTEGER, RWRITE, var_ospf, 3, {7, 1, 11}},
{ospfIfState, ASN_INTEGER, RONLY, var_ospf, 3, {7, 1, 12}},
{ospfIfDesignatedRouter, ASN_IPADDRESS, RONLY, var_ospf, 3, {7, 1, 13}},
{ospfIfBackupDesignatedRouter, ASN_IPADDRESS, RONLY, var_ospf, 3, {7, 1, 14}},
{ospfIfEvents, ASN_COUNTER, RONLY, var_ospf, 3, {7, 1, 15}},
{ospfIfAuthKey, ASN_OCTET_STR, RWRITE, var_ospf, 3, {7, 1, 16}},
{ospfIfStatus, ASN_INTEGER, RWRITE, var_ospf, 3, {7, 1, 17}},
{ospfIfMulticastForwarding, ASN_INTEGER, RWRITE, var_ospf, 3, {7, 1, 18}},
{ospfIfMetricIpAddress, ASN_IPADDRESS, RONLY, var_ospf, 3, {8, 1, 1}},
{ospfIfMetricAddressLessIf, ASN_INTEGER, RONLY, var_ospf, 3, {8, 1, 2}},
{ospfIfMetricTOS, ASN_INTEGER, RONLY, var_ospf, 3, {8, 1, 3}},
{ospfIfMetricValue, ASN_INTEGER, RWRITE, var_ospf, 3, {8, 1, 4}},
{ospfIfMetricStatus, ASN_INTEGER, RWRITE, var_ospf, 3, {8, 1, 5}},
{ospfVirtIfAreaId, ASN_IPADDRESS, RONLY, var_ospf, 3, {9, 1, 1}},
{ospfVirtIfNeighbor, ASN_IPADDRESS, RONLY, var_ospf, 3, {9, 1, 2}},
{ospfVirtIfTransitDelay, ASN_INTEGER, RWRITE, var_ospf, 3, {9, 1, 3}},
{ospfVirtIfRetransInterval, ASN_INTEGER, RWRITE, var_ospf, 3, {9, 1, 4}},
{ospfVirtIfHelloInterval, ASN_INTEGER, RWRITE, var_ospf, 3, {9, 1, 5}},
{ospfVirtIfRtrDeadInterval, ASN_INTEGER, RWRITE, var_ospf, 3, {9, 1, 6}},
{ospfVirtIfState, ASN_INTEGER, RONLY, var_ospf, 3, {9, 1, 7}},
{ospfVirtIfEvents, ASN_COUNTER, RONLY, var_ospf, 3, {9, 1, 8}},
{ospfVirtIfAuthKey, ASN_OCTET_STR, RWRITE, var_ospf, 3, {9, 1, 9}},
{ospfVirtIfStatus, ASN_INTEGER, RWRITE, var_ospf, 3, {9, 1, 10}},
{ospfNbrIpAddr, ASN_IPADDRESS, RONLY, var_ospf, 3, {10, 1, 1}},
{ospfNbrAddressLessIndex, ASN_INTEGER, RONLY, var_ospf, 3, {10, 1, 2}},
{ospfNbrRtrId, ASN_IPADDRESS, RONLY, var_ospf, 3, {10, 1, 3}},
{ospfNbrOptions, ASN_INTEGER, RONLY, var_ospf, 3, {10, 1, 4}},
{ospfNbrPriority, ASN_INTEGER, RWRITE, var_ospf, 3, {10, 1, 5}},
{ospfNbrState, ASN_INTEGER, RONLY, var_ospf, 3, {10, 1, 6}},
{ospfNbrEvents, ASN_COUNTER, RONLY, var_ospf, 3, {10, 1, 7}},
{ospfNbrLsRetransQLen, ASN_GAUGE, RONLY, var_ospf, 3, {10, 1, 8}},
{ospfNbmaNbrStatus, ASN_INTEGER, RWRITE, var_ospf, 3, {10, 1, 9}},
{ospfNbmaNbrPermanence, ASN_INTEGER, RWRITE, var_ospf, 3, {10, 1, 10}},
{ospfVirtNbrArea, ASN_IPADDRESS, RONLY, var_ospf, 3, {11, 1, 1}},
{ospfVirtNbrRtrId, ASN_IPADDRESS, RONLY, var_ospf, 3, {11, 1, 2}},
{ospfVirtNbrIpAddr, ASN_IPADDRESS, RONLY, var_ospf, 3, {11, 1, 3}},
{ospfVirtNbrOptions, ASN_INTEGER, RONLY, var_ospf, 3, {11, 1, 4}},
{ospfVirtNbrState, ASN_INTEGER, RONLY, var_ospf, 3, {11, 1, 5}},
{ospfVirtNbrEvents, ASN_COUNTER, RONLY, var_ospf, 3, {11, 1, 6}},
{ospfVirtNbrLsRetransQLen, ASN_GAUGE, RONLY, var_ospf, 3, {11, 1, 7}},
{ospfExtLsdbType, ASN_INTEGER, RONLY, var_ospf, 3, {12, 1, 1}},
{ospfExtLsdbLsid, ASN_IPADDRESS, RONLY, var_ospf, 3, {12, 1, 2}},
{ospfExtLsdbRouterId, ASN_IPADDRESS, RONLY, var_ospf, 3, {12, 1, 3}},
{ospfExtLsdbSequence, ASN_INTEGER, RONLY, var_ospf, 3, {12, 1, 4}},
{ospfExtLsdbAge, ASN_INTEGER, RONLY, var_ospf, 3, {12, 1, 5}},
{ospfExtLsdbChecksum, ASN_INTEGER, RONLY, var_ospf, 3, {12, 1, 6}},
{ospfExtLsdbAdvertisement, ASN_OCTET_STR, RONLY, var_ospf, 3, {12, 1, 7}},
{ospfAreaAggregateAreaID, ASN_IPADDRESS, RONLY, var_ospf, 3, {14, 1, 1}},
{ospfAreaAggregateLsdbType, ASN_INTEGER, RONLY, var_ospf, 3, {14, 1, 2}},
{ospfAreaAggregateNet, ASN_IPADDRESS, RONLY, var_ospf, 3, {14, 1, 3}},
{ospfAreaAggregateMask, ASN_IPADDRESS, RWRITE, var_ospf, 3, {14, 1, 4}},
{ospfAreaAggregateStatus, ASN_INTEGER, RWRITE, var_ospf, 3, {14, 1, 5}},
{ospfAreaAggregateEffect, ASN_INTEGER, RWRITE, var_ospf, 3, {14, 1, 6}}
};

config_load_mib( MIB.14, 7, ospf_variables)

#endif
#endif /* _MIBGROUP_SNMP_OSPF_H */
