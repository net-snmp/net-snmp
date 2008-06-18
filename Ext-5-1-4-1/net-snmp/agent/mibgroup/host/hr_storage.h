/*
 *  Host Resources MIB - storage group interface - hr_system.h
 *
 */
#ifndef _MIBGROUP_HRSTORAGE_H
#define _MIBGROUP_HRSTORAGE_H

extern void     init_hr_storage(void);
extern FindVarMethod var_hrstore;


#define	HRS_TYPE_MBUF		1
#define	HRS_TYPE_MEM		2
#define	HRS_TYPE_SWAP		3
#define	HRS_TYPE_FIXED_MAX	3     /* the largest fixed type */

#endif                          /* _MIBGROUP_HRSTORAGE_H */
