/*
 * This file was created to separate data storage from  MIB implementation.
 */


#ifndef _MIBGROUP_SNMPNOTIFYTABLE_DATA_H
#define _MIBGROUP_SNMPNOTIFYTABLE_DATA_H


/*
 * we may use header_complex from the header_complex module
 */
config_require(header_complex)
config_require(target/target)
config_require(snmp-notification-mib/snmpNotifyFilterTable/snmpNotifyFilterTable_data_storage)

#define NOTIFY_NAME_MAX       32
#define NOTIFY_TAG_MAX       255

/*
 * our storage structure(s)
 */
struct snmpNotifyTable_data {
    char           *snmpNotifyName;
    size_t          snmpNotifyNameLen;
    char           *snmpNotifyTag;
    size_t          snmpNotifyTagLen;
    long            snmpNotifyType;
    long            snmpNotifyStorageType;
    long            snmpNotifyRowStatus;
};


/*
 * enum definitions from the covered mib sections
 */

#define SNMPNOTIFYTYPE_TRAP                      1
#define SNMPNOTIFYTYPE_INFORM                    2


/*
 * function prototypes
 */
void            init_snmpNotifyTable_data(void);
void            shutdown_snmpNotifyTable_data(void);

int             snmpNotifyTable_add(struct snmpNotifyTable_data *thedata);
int             snmpNotifyTable_remove(struct snmpNotifyTable_data *thedata);

struct snmpNotifyTable_data *get_notifyTable(const char *name);


#endif                          /* _MIBGROUP_SNMPNOTIFYTABLE_DATA_H */
