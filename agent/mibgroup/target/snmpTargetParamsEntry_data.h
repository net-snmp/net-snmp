/*
 * This file was created to separate notification data storage from
 * the MIB implementation.
 */

#ifndef _MIBGROUP_SNMPTARGETPARAMSENTRY_DATA_H
#define _MIBGROUP_SNMPTARGETPARAMSENTRY_DATA_H

/*
 * structure definitions
 */
struct targetParamTable_struct {
    char           *paramName;
    int             mpModel;
    int             secModel;
    char           *secName;
    int             secLevel;
    int             storageType;
    int             rowStatus;
    struct targetParamTable_struct *next;
    time_t          updateTime;
};

/*
 * utility functions
 */
struct targetParamTable_struct *get_paramEntry(char *name);

void snmpTargetParamTable_add(struct targetParamTable_struct *newEntry);

struct targetParamTable_struct *snmpTargetParamTable_create(void);

void snmpTargetParamTable_dispose(struct targetParamTable_struct *);

/*
 * function definitions
 */

void            init_snmpTargetParamsEntry_data(void);
void            shutdown_snmpTargetParamsEntry_data(void);

#endif                          /* _MIBGROUP_SNMPTARGETPARAMSENTRY_DATA_H */
