#ifndef SNMP_TC_H
#define SNMP_TC_H

#ifdef __cplusplus
extern "C" {
#endif
/* snmp-tc.h: Provide some standard #defines for Textual Convention
   related value information */

/* TrueValue */
#define TV_TRUE 1
#define TV_FALSE 2

/* RowStatus */
#define RS_ACTIVE	        1
#define RS_NOTINSERVICE	        2
#define RS_NOTREADY	        3
#define RS_CREATEANDGO	        4
#define RS_CREATEANDWAIT	5
#define RS_DESTROY		6

/* StorageType */
#define ST_OTHER	1
#define ST_VOLATILE	2
#define ST_NONVOLATILE	3
#define ST_PERMANENT	4
#define ST_READONLY	5

#ifdef __cplusplus
}
#endif

#endif /* SNMP_TC_H */
