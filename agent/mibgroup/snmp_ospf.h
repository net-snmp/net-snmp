/*
 *  snmp_ospf.h
 *
 */
#ifndef _MIBGROUP_SNMP_OSPF_H
#define _MIBGROUP_SNMP_OSPF_H

config_require(smux)

extern u_char	*var_ospf();

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
{ospfRouterId, IPADDRESS, RWRITE, var_ospf, 3, {1, 1, 1}},
{ospfAdminStat, INTEGER, RWRITE, var_ospf, 3, {1, 1, 2}},
{ospfVersionNumber, INTEGER, RONLY, var_ospf, 3, {1, 1, 3}},
{ospfAreaBdrRtrStatus, INTEGER, RONLY, var_ospf, 3, {1, 1, 4}},
{ospfASBdrRtrStatus, INTEGER, RWRITE, var_ospf, 3, {1, 1, 5}},
{ospfExternLsaCount, GAUGE, RONLY, var_ospf, 3, {1, 1, 6}},
{ospfExternLsaCksumSum, INTEGER, RONLY, var_ospf, 3, {1, 1, 7}},
{ospfTOSSupport, INTEGER, RWRITE, var_ospf, 3, {1, 1, 8}},
{ospfOriginateNewLsas, COUNTER, RONLY, var_ospf, 3, {1, 1, 9}},
{ospfRxNewLsas, COUNTER, RONLY, var_ospf, 3, {1, 1, 10, 0}},
{ospfExtLsdbLimit, INTEGER, RWRITE, var_ospf, 3, {1, 1, 11}},
{ospfMulticastExtensions, INTEGER, RWRITE, var_ospf, 3, {1, 1, 12}},
{ospfAreaId, IPADDRESS, RONLY, var_ospf, 3, {2, 1, 1}},
{ospfAuthType, INTEGER, RWRITE, var_ospf, 3, {2, 1, 2}},
{ospfImportAsExtern, INTEGER, RWRITE, var_ospf, 3, {2, 1, 3}},
{ospfSpfRuns, COUNTER, RONLY, var_ospf, 3, {2, 1, 4}},
{ospfAreaBdrRtrCount, GAUGE, RONLY, var_ospf, 3, {2, 1, 5}},
{ospfAsBdrRtrCount, GAUGE, RONLY, var_ospf, 3, {2, 1, 6}},
{ospfAreaLsaCount, GAUGE, RONLY, var_ospf, 3, {2, 1, 7}},
{ospfAreaLsaCksumSum, INTEGER, RONLY, var_ospf, 3, {2, 1, 8}},
{ospfAreaSummary, INTEGER, RWRITE, var_ospf, 3, {2, 1, 9}},
{ospfAreaStatus, INTEGER, RWRITE, var_ospf, 3, {2, 1, 10}},
{ospfStubAreaId, IPADDRESS, RONLY, var_ospf, 3, {3, 1, 1}},
{ospfStubTOS, INTEGER, RONLY, var_ospf, 3, {3, 1, 2}},
{ospfStubMetric, INTEGER, RWRITE, var_ospf, 3, {3, 1, 3}},
{ospfStubStatus, INTEGER, RWRITE, var_ospf, 3, {3, 1, 4}},
{ospfStubMetricType, INTEGER, RWRITE, var_ospf, 3, {3, 1, 5}},
{ospfLsdbAreaId, IPADDRESS, RONLY, var_ospf, 3, {4, 1, 1}},
{ospfLsdbType, INTEGER, RONLY, var_ospf, 3, {4, 1, 2}},
{ospfLsdbLsid, IPADDRESS, RONLY, var_ospf, 3, {4, 1, 3}},
{ospfLsdbRouterId, IPADDRESS, RONLY, var_ospf, 3, {4, 1, 4}},
{ospfLsdbSequence, INTEGER, RONLY, var_ospf, 3, {4, 1, 5}},
{ospfLsdbAge, INTEGER, RONLY, var_ospf, 3, {4, 1, 6}},
{ospfLsdbChecksum, INTEGER, RONLY, var_ospf, 3, {4, 1, 7}},
{ospfLsdbAdvertisement, STRING, RONLY, var_ospf, 3, {4, 1, 8}},
{ospfAreaRangeAreaId, IPADDRESS, RONLY, var_ospf, 3, {5, 1, 1}},
{ospfAreaRangeNet, IPADDRESS, RONLY, var_ospf, 3, {5, 1, 2}},
{ospfAreaRangeMask, IPADDRESS, RWRITE, var_ospf, 3, {5, 1, 3}},
{ospfAreaRangeStatus, INTEGER, RWRITE, var_ospf, 3, {5, 1, 4}},
{ospfAreaRangeEffect, INTEGER, RWRITE, var_ospf, 3, {5, 1, 5}},
{ospfHostIpAddress, IPADDRESS, RONLY, var_ospf, 3, {6, 1, 1}},
{ospfHostTOS, INTEGER, RONLY, var_ospf, 3, {6, 1, 2}},
{ospfHostMetric, INTEGER, RWRITE, var_ospf, 3, {6, 1, 3}},
{ospfHostStatus, INTEGER, RWRITE, var_ospf, 3, {6, 1, 4}},
{ospfHostAreaID, IPADDRESS, RONLY, var_ospf, 3, {6, 1, 5}},
{ospfIfIpAddress, IPADDRESS, RONLY, var_ospf, 3, {7, 1, 1}},
{ospfAddressLessIf, INTEGER, RONLY, var_ospf, 3, {7, 1, 2}},
{ospfIfAreaId, IPADDRESS, RWRITE, var_ospf, 3, {7, 1, 3}},
{ospfIfType, INTEGER, RWRITE, var_ospf, 3, {7, 1, 4}},
{ospfIfAdminStat, INTEGER, RWRITE, var_ospf, 3, {7, 1, 5}},
{ospfIfRtrPriority, INTEGER, RWRITE, var_ospf, 3, {7, 1, 6}},
{ospfIfTransitDelay, INTEGER, RWRITE, var_ospf, 3, {7, 1, 7}},
{ospfIfRetransInterval, INTEGER, RWRITE, var_ospf, 3, {7, 1, 8}},
{ospfIfHelloInterval, INTEGER, RWRITE, var_ospf, 3, {7, 1, 9}},
{ospfIfRtrDeadInterval, INTEGER, RWRITE, var_ospf, 3, {7, 1, 10}},
{ospfIfPollInterval, INTEGER, RWRITE, var_ospf, 3, {7, 1, 11}},
{ospfIfState, INTEGER, RONLY, var_ospf, 3, {7, 1, 12}},
{ospfIfDesignatedRouter, IPADDRESS, RONLY, var_ospf, 3, {7, 1, 13}},
{ospfIfBackupDesignatedRouter, IPADDRESS, RONLY, var_ospf, 3, {7, 1, 14}},
{ospfIfEvents, COUNTER, RONLY, var_ospf, 3, {7, 1, 15}},
{ospfIfAuthKey, STRING, RWRITE, var_ospf, 3, {7, 1, 16}},
{ospfIfStatus, INTEGER, RWRITE, var_ospf, 3, {7, 1, 17}},
{ospfIfMulticastForwarding, INTEGER, RWRITE, var_ospf, 3, {7, 1, 18}},
{ospfIfMetricIpAddress, IPADDRESS, RONLY, var_ospf, 3, {8, 1, 1}},
{ospfIfMetricAddressLessIf, INTEGER, RONLY, var_ospf, 3, {8, 1, 2}},
{ospfIfMetricTOS, INTEGER, RONLY, var_ospf, 3, {8, 1, 3}},
{ospfIfMetricValue, INTEGER, RWRITE, var_ospf, 3, {8, 1, 4}},
{ospfIfMetricStatus, INTEGER, RWRITE, var_ospf, 3, {8, 1, 5}},
{ospfVirtIfAreaId, IPADDRESS, RONLY, var_ospf, 3, {9, 1, 1}},
{ospfVirtIfNeighbor, IPADDRESS, RONLY, var_ospf, 3, {9, 1, 2}},
{ospfVirtIfTransitDelay, INTEGER, RWRITE, var_ospf, 3, {9, 1, 3}},
{ospfVirtIfRetransInterval, INTEGER, RWRITE, var_ospf, 3, {9, 1, 4}},
{ospfVirtIfHelloInterval, INTEGER, RWRITE, var_ospf, 3, {9, 1, 5}},
{ospfVirtIfRtrDeadInterval, INTEGER, RWRITE, var_ospf, 3, {9, 1, 6}},
{ospfVirtIfState, INTEGER, RONLY, var_ospf, 3, {9, 1, 7}},
{ospfVirtIfEvents, COUNTER, RONLY, var_ospf, 3, {9, 1, 8}},
{ospfVirtIfAuthKey, STRING, RWRITE, var_ospf, 3, {9, 1, 9}},
{ospfVirtIfStatus, INTEGER, RWRITE, var_ospf, 3, {9, 1, 10}},
{ospfNbrIpAddr, IPADDRESS, RONLY, var_ospf, 3, {10, 1, 1}},
{ospfNbrAddressLessIndex, INTEGER, RONLY, var_ospf, 3, {10, 1, 2}},
{ospfNbrRtrId, IPADDRESS, RONLY, var_ospf, 3, {10, 1, 3}},
{ospfNbrOptions, INTEGER, RONLY, var_ospf, 3, {10, 1, 4}},
{ospfNbrPriority, INTEGER, RWRITE, var_ospf, 3, {10, 1, 5}},
{ospfNbrState, INTEGER, RONLY, var_ospf, 3, {10, 1, 6}},
{ospfNbrEvents, COUNTER, RONLY, var_ospf, 3, {10, 1, 7}},
{ospfNbrLsRetransQLen, GAUGE, RONLY, var_ospf, 3, {10, 1, 8}},
{ospfNbmaNbrStatus, INTEGER, RWRITE, var_ospf, 3, {10, 1, 9}},
{ospfNbmaNbrPermanence, INTEGER, RWRITE, var_ospf, 3, {10, 1, 10}},
{ospfVirtNbrArea, IPADDRESS, RONLY, var_ospf, 3, {11, 1, 1}},
{ospfVirtNbrRtrId, IPADDRESS, RONLY, var_ospf, 3, {11, 1, 2}},
{ospfVirtNbrIpAddr, IPADDRESS, RONLY, var_ospf, 3, {11, 1, 3}},
{ospfVirtNbrOptions, INTEGER, RONLY, var_ospf, 3, {11, 1, 4}},
{ospfVirtNbrState, INTEGER, RONLY, var_ospf, 3, {11, 1, 5}},
{ospfVirtNbrEvents, COUNTER, RONLY, var_ospf, 3, {11, 1, 6}},
{ospfVirtNbrLsRetransQLen, GAUGE, RONLY, var_ospf, 3, {11, 1, 7}},
{ospfExtLsdbType, INTEGER, RONLY, var_ospf, 3, {12, 1, 1}},
{ospfExtLsdbLsid, IPADDRESS, RONLY, var_ospf, 3, {12, 1, 2}},
{ospfExtLsdbRouterId, IPADDRESS, RONLY, var_ospf, 3, {12, 1, 3}},
{ospfExtLsdbSequence, INTEGER, RONLY, var_ospf, 3, {12, 1, 4}},
{ospfExtLsdbAge, INTEGER, RONLY, var_ospf, 3, {12, 1, 5}},
{ospfExtLsdbChecksum, INTEGER, RONLY, var_ospf, 3, {12, 1, 6}},
{ospfExtLsdbAdvertisement, STRING, RONLY, var_ospf, 3, {12, 1, 7}},
{ospfAreaAggregateAreaID, IPADDRESS, RONLY, var_ospf, 3, {14, 1, 1}},
{ospfAreaAggregateLsdbType, INTEGER, RONLY, var_ospf, 3, {14, 1, 2}},
{ospfAreaAggregateNet, IPADDRESS, RONLY, var_ospf, 3, {14, 1, 3}},
{ospfAreaAggregateMask, IPADDRESS, RWRITE, var_ospf, 3, {14, 1, 4}},
{ospfAreaAggregateStatus, INTEGER, RWRITE, var_ospf, 3, {14, 1, 5}},
{ospfAreaAggregateEffect, INTEGER, RWRITE, var_ospf, 3, {14, 1, 6}}
};

config_load_mib( MIB.14, 7, ospf_variables)

#endif
#endif /* _MIBGROUP_SNMP_OSPF_H */
