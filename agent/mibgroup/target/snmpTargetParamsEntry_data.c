/*
 * TargetParamTable data storage
 *
 * This file was created to separate data storage from the MIB implementation
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

#include "snmpTargetParamsEntry_data.h"

#define snmpTargetParamsOIDLen 11       /*This is base+column,
                                         * i.e. everything but index */

oid             snmpTargetParamsOID[snmpTargetParamsOIDLen] =
    { 1, 3, 6, 1, 6, 3, 12, 1, 3, 1, 0 };

static struct targetParamTable_struct *aPTable = NULL;


/*
 * Utility routines
 */


/*
 * TargetParamTable_create creates and returns a pointer
 * to a targetParamTable_struct with default values set
 */
struct targetParamTable_struct
               *
snmpTargetParamTable_create(void)
{
    struct targetParamTable_struct *newEntry;

    newEntry = (struct targetParamTable_struct *)
        malloc(sizeof(struct targetParamTable_struct));

    newEntry->paramName = NULL;
    newEntry->mpModel = -1;

    newEntry->secModel = -1;
    newEntry->secName = NULL;
    newEntry->secLevel = -1;

    newEntry->storageType = SNMP_STORAGE_NONVOLATILE;
    newEntry->rowStatus = SNMP_ROW_NONEXISTENT;
    newEntry->next = NULL;
    return newEntry;
}


/*
 * TargetParamTable_dispose frees the space allocated to a
 * targetParamTable_struct
 */
void
snmpTargetParamTable_dispose(struct targetParamTable_struct *reaped)
{
    free(reaped->paramName);
    free(reaped->secName);

    free(reaped);
}                               /* snmpTargetParamTable_dispose  */


/*
 * snmpTargetParamTable_addToList adds a targetParamTable_struct
 * to a list passed in. The list is assumed to be in a sorted order,
 * low to high and this procedure inserts a new struct in the proper
 * location. Sorting uses OID values based on paramName. A new equal value
 * overwrites a current one.
 */
void
snmpTargetParamTable_addToList(struct targetParamTable_struct *newEntry,
                               struct targetParamTable_struct **listPtr)
{
    static struct targetParamTable_struct *curr_struct, *prev_struct;
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
        newOIDLen = strlen(newEntry->paramName);
        for (i = 0; i < (int) newOIDLen; i++) {
            newOID[i] = newEntry->paramName[i];
        }

        /*
         * search through the list for an equal or greater OID value
         */
        while (curr_struct != NULL) {
            currOIDLen = strlen(curr_struct->paramName);
            for (i = 0; i < (int) currOIDLen; i++) {
                currOID[i] = curr_struct->paramName[i];
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
                snmpTargetParamTable_dispose(curr_struct);
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
}                               /* snmpTargeParamTable_addToList  */

void
snmpTargetParamTable_add(struct targetParamTable_struct *newEntry)
{
    snmpTargetParamTable_addToList(newEntry, &aPTable);
}

/*
 * snmpTargetParamTable_remFromList removes a targetParamTable_struct
 * from the list passed in
 */
void
snmpTargetParamTable_remFromList(struct targetParamTable_struct *oldEntry,
                                 struct targetParamTable_struct **listPtr)
{
    struct targetParamTable_struct *tptr;

    if ((tptr = *listPtr) == NULL)
        return;
    else if (tptr == oldEntry) {
        *listPtr = (*listPtr)->next;
        snmpTargetParamTable_dispose(tptr);
        return;
    } else {
        while (tptr->next != NULL) {
            if (tptr->next == oldEntry) {
                tptr->next = tptr->next->next;
                snmpTargetParamTable_dispose(oldEntry);
                return;
            }
            tptr = tptr->next;
        }
    }
}                               /* snmpTargetParamTable_remFromList  */


/*
 * lookup OID in the link list of Table Entries
 */
struct targetParamTable_struct *
search_snmpTargetParamsTable(oid * baseName,
                             size_t baseNameLen,
                             oid * name, size_t * length, int exact)
{
    static struct targetParamTable_struct *temp_struct;
    int             i;
    size_t          myOIDLen = 0;
    oid             newNum[128];

    /*
     * lookup entry in p / * Get Current MIB ID
     */
    memcpy(newNum, baseName, baseNameLen * sizeof(oid));

    for (temp_struct = aPTable; temp_struct != NULL;
         temp_struct = temp_struct->next) {
        for (i = 0; i < (int) strlen(temp_struct->paramName); i++) {
            newNum[baseNameLen + i] = temp_struct->paramName[i];
        }
        myOIDLen = baseNameLen + strlen(temp_struct->paramName);
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
}                               /* search_snmpTargetParamsTable */


struct targetParamTable_struct *
get_paramEntry(char *name)
{
    static struct targetParamTable_struct *ptr;
    for (ptr = aPTable; ptr; ptr = ptr->next) {
        if (strcmp(ptr->paramName, name) == 0) {
            return ptr;
        }
    }
    return NULL;
}


/*
 * initialization routines
 */

void
init_snmpTargetParamsEntry_data(void)
{
    aPTable = NULL;
}                               /*  init_snmpTargetParmsEntry  */


/*
 * shutdown routines
 */

void
shutdown_snmpTargetParamsEntry(void)
{
    while (aPTable)
	snmpTargetParamTable_remFromList(aPTable, &aPTable);
}
