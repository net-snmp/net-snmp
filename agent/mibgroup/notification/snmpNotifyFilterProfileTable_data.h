/*
 * This file was created to separate data storage from MIB implementation.
 */


#ifndef _MIBGROUP_SNMPNOTIFYFILTERPROFILETABLE_DATA_H
#define _MIBGROUP_SNMPNOTIFYFILTERPROFILETABLE_DATA_H


/*
 * our storage structure(s)
 */
struct snmpNotifyFilterProfileTable_data {
    char           *snmpTargetParamsName;
    size_t          snmpTargetParamsNameLen;
    char           *snmpNotifyFilterProfileName;
    size_t          snmpNotifyFilterProfileNameLen;
    long            snmpNotifyFilterProfileStorType;
    long            snmpNotifyFilterProfileRowStatus;
};


/*
 * function prototypes
 */

void            init_snmpNotifyFilterProfileTable_data(void);

int
snmpNotifyFilterProfileTable_add(struct snmpNotifyFilterProfileTable_data *);

struct snmpNotifyFilterProfileTable_data *
snmpNotifyFilterProfileTable_create(char *paramsName, size_t paramName_len,
                                    char *profileName, size_t profileName_len);

void
snmpNotifyFilterProfileTable_free(struct snmpNotifyFilterProfileTable_data *);

struct snmpNotifyFilterProfileTable_data *
snmpNotifyFilterProfileTable_find(const char *name, size_t len);

char           *get_FilterProfileName(const char *paramName,
                                      size_t paramName_len,
                                      size_t * profileName_len);


#endif           /* _MIBGROUP_SNMPNOTIFYFILTERPROFILETABLE_DATA_H */
