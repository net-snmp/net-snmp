/*
 * snmpTargetAddrEntry MIB
 *
 * This file was created tooo separate notification data storage from
 * the MIB implementation.
 */

#include <net-snmp/net-snmp-config.h>
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#include <stdlib.h>
#include <ctype.h>

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "snmpTargetAddrEntry_data.h"
#include "util_funcs/header_generic.h"

static struct targetAddrTable_struct *aAddrTable = NULL;


/*
 * Utility routines
 */
struct targetAddrTable_struct *
get_addrTable(void)
{
    return aAddrTable;
}

struct targetAddrTable_struct *
get_addrForName(char *name)
{
    struct targetAddrTable_struct *ptr;
    for (ptr = aAddrTable; ptr != NULL; ptr = ptr->next) {
        if (ptr->name && strcmp(ptr->name, name) == 0)
            return ptr;
    }
    return NULL;
}


/*
 * TargetAddrTable_create creates and returns a pointer
 * to a targetAddrTable_struct with default values set
 */
struct targetAddrTable_struct *
snmpTargetAddrTable_create(void)
{
    struct targetAddrTable_struct *newEntry;

    newEntry = (struct targetAddrTable_struct *)
        malloc(sizeof(struct targetAddrTable_struct));

    if (newEntry) {
        newEntry->name = NULL;

        newEntry->tDomainLen = 0;
        newEntry->tAddress = NULL;

        newEntry->timeout = 1500;
        newEntry->retryCount = 3;

        newEntry->tagList = strdup("");
        newEntry->params = NULL;

        newEntry->storageType = SNMP_STORAGE_NONVOLATILE;
        newEntry->rowStatus = SNMP_ROW_NONEXISTENT;
        newEntry->sess = (netsnmp_session *) NULL;
        newEntry->next = NULL;
    }

    return newEntry;
}                               /* snmpTargetAddrTable_create */


/*
 * TargetAddrTable_dispose frees the space allocated to a
 * targetAddrTable_struct
 */
void
snmpTargetAddrTable_dispose(struct targetAddrTable_struct *reaped)
{
    if (reaped->sess)
        snmp_close(reaped->sess);
    else
        SNMP_FREE(reaped->tAddress);
    SNMP_FREE(reaped->name);
    SNMP_FREE(reaped->tagList);
    SNMP_FREE(reaped->params);

    SNMP_FREE(reaped);
}                               /* snmpTargetAddrTable_dispose  */

/*
 * snmpTargetAddrTable_addToList adds a targetAddrTable_struct
 * to a list passed in. The list is assumed to be in a sorted order,
 * low to high and this procedure inserts a new struct in the proper
 * location. Sorting uses OID values based on name. A new equal value
 * overwrites a current one.
 */
void
snmpTargetAddrTable_addToList(struct targetAddrTable_struct *newEntry,
                              struct targetAddrTable_struct **listPtr)
{
    static struct targetAddrTable_struct *curr_struct, *prev_struct;
    int             i;
    size_t          newOIDLen = 0, currOIDLen = 0;
    oid             newOID[128], currOID[128];

    /*
     * if the list is empty, add the new entry to the top
     */
    if ((prev_struct = curr_struct = *listPtr) == NULL) {
        *listPtr = newEntry;
        return;
    } else {
        /*
         * get the 'OID' value of the new entry
         */
        newOIDLen = strlen(newEntry->name);
        for (i = 0; i < (int) newOIDLen; i++) {
            newOID[i] = newEntry->name[i];
        }

        /*
         * search through the list for an equal or greater OID value
         */
        while (curr_struct != NULL) {
            currOIDLen = strlen(curr_struct->name);
            for (i = 0; i < (int) currOIDLen; i++) {
                currOID[i] = curr_struct->name[i];
            }

            i = snmp_oid_compare(newOID, newOIDLen, currOID, currOIDLen);
            if (i == 0) {       /* Exact match, overwrite with new struct */
                newEntry->next = curr_struct->next;
                /*
                 * if curr_struct is the top of the list
                 */
                if (*listPtr == curr_struct)
                    *listPtr = newEntry;
                else
                    prev_struct->next = newEntry;
                snmpTargetAddrTable_dispose(curr_struct);
                return;
            } else if (i < 0) { /* Found a greater OID, insert struct in front of it. */
                newEntry->next = curr_struct;
                /*
                 * if curr_struct is the top of the list
                 */
                if (*listPtr == curr_struct)
                    *listPtr = newEntry;
                else
                    prev_struct->next = newEntry;
                return;
            }
            prev_struct = curr_struct;
            curr_struct = curr_struct->next;
        }
    }
    /*
     * if we're here, no larger OID was ever found, insert on end of list
     */
    prev_struct->next = newEntry;
}                               /* snmpTargeAddrTable_addToList  */


void
snmpTargetAddrTable_add(struct targetAddrTable_struct *newEntry)
{
    snmpTargetAddrTable_addToList(newEntry, &aAddrTable);
}


/*
 * snmpTargetAddrTable_remFromList removes a targetAddrTable_struct
 * from the list passed in
 */
void
snmpTargetAddrTable_remFromList(struct targetAddrTable_struct *oldEntry,
                                struct targetAddrTable_struct **listPtr)
{
    struct targetAddrTable_struct *tptr;

    if ((tptr = *listPtr) == NULL)
        return;
    else if (tptr == oldEntry) {
        *listPtr = (*listPtr)->next;
        snmpTargetAddrTable_dispose(tptr);
        return;
    } else {
        while (tptr->next != NULL) {
            if (tptr->next == oldEntry) {
                tptr->next = tptr->next->next;
                snmpTargetAddrTable_dispose(oldEntry);
                return;
            }
            tptr = tptr->next;
        }
    }
}                               /* snmpTargetAddrTable_remFromList  */


/*
 * lookup OID in the link list of Addr Table Entries
 */
struct targetAddrTable_struct *
search_snmpTargetAddrTable(oid * baseName,
                           size_t baseNameLen,
                           oid * name, size_t * length, int exact)
{
    static struct targetAddrTable_struct *temp_struct;
    int             i;
    size_t          myOIDLen = 0;
    oid             newNum[128];

    /*
     * lookup entry in addrTable linked list, Get Current MIB ID
     */
    memcpy(newNum, baseName, baseNameLen * sizeof(oid));

    for (temp_struct = aAddrTable; temp_struct != NULL;
         temp_struct = temp_struct->next) {
        for (i = 0; i < (int) strlen(temp_struct->name); i++) {
            newNum[baseNameLen + i] = temp_struct->name[i];
        }
        myOIDLen = baseNameLen + strlen(temp_struct->name);
        i = snmp_oid_compare(name, *length, newNum, myOIDLen);
        /*
         * Assumes that the linked list sorted by OID, low to high
         */
        if ((i == 0 && exact != 0) || (i < 0 && exact == 0)) {
            if (exact == 0) {
                memcpy(name, newNum, myOIDLen * sizeof(oid));
                *length = myOIDLen;
            }
            return temp_struct;
        }
    }
    return NULL;
}                               /* search_snmpTargetAddrTable  */


/*
 * Init routines
 */

void
init_snmpTargetAddrEntry_data(void)
{
    aAddrTable = NULL;
}                               /* init_snmpTargetAddrEntry */


/*
 * Shutdown routines
 */

void
shutdown_snmpTargetAddrEntry(void)
{
    struct targetAddrTable_struct *ptr;
    struct targetAddrTable_struct *next;

    for (ptr = aAddrTable; ptr; ptr = next) {
        next = ptr->next;
        snmpTargetAddrTable_dispose(ptr);
    }
    aAddrTable = NULL;
}
