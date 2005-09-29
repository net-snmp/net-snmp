/*
 * DisMan Event MIB:
 *     Core implementation of the trigger handling behaviour
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "disman/event/mteTrigger.h"
#include "disman/event/mteEvent.h"

netsnmp_tdata *trigger_table_data;

    /*
     * Initialize the container for the (combined) mteTrigger*Table,
     * regardless of which table initialisation routine is called first.
     */

void
init_trigger_table_data(void)
{
    DEBUGMSGTL(("disman:event:init", "init trigger container\n"));
    if (!trigger_table_data) {
        trigger_table_data = netsnmp_tdata_create("mteTriggerTable");
        trigger_table_data->store_indexes = 1;
        DEBUGMSGTL(("disman:event:init", "create trigger container (%x)\n",
                                          trigger_table_data));
    }
}


/** Initializes the mteTrigger module */
void
init_mteTrigger(void)
{
    init_trigger_table_data();

}

    /* ===================================================
     *
     * APIs for maintaining the contents of the (combined)
     *    mteTrigger*Table container.
     *
     * =================================================== */

void
_mteTrigger_dump(void)
{
    struct mteTrigger *entry;
    netsnmp_tdata_row *row;
    int i = 0;

    for (row = netsnmp_tdata_get_first_row(trigger_table_data);
         row;
         row = netsnmp_tdata_get_next_row(trigger_table_data, row)) {
        entry = (struct mteTrigger *)row->data;
        DEBUGMSGTL(("disman:event:dump", "TriggerTable entry %d: ", i));
        DEBUGMSGOID(("disman:event:dump", row->oid_index.oids, row->oid_index.len));
        DEBUGMSG(("disman:event:dump", "(%s, %s)",
                                         row->indexes->val.string,
                                         row->indexes->next_variable->val.string));
        DEBUGMSG(("disman:event:dump", ": %x, %x\n", row, entry));
        i++;
    }
    DEBUGMSGTL(("disman:event:dump", "TriggerTable %d entries\n", i));
}


/*
 * Create a new row in the trigger table 
 */
netsnmp_tdata_row *
mteTrigger_createEntry(char *mteOwner, char *mteTName, int fixed)
{
    struct mteTrigger *entry;
    netsnmp_tdata_row *row;
    size_t mteOwner_len = (mteOwner) ? strlen(mteOwner) : 0;
    size_t mteTName_len = (mteTName) ? strlen(mteTName) : 0;
    oid sysUpTime_instance[] = { 1, 3, 6, 1, 2, 1, 1, 0 };
    oid sysUpTime_inst_len   = OID_LENGTH(sysUpTime_instance);

    DEBUGMSGTL(("disman:event:table", "Create trigger entry (%s, %s)\n",
                                       mteOwner, mteTName));
    /*
     * Create the mteTrigger entry, and the
     * (table-independent) row wrapper structure...
     */
    entry = SNMP_MALLOC_TYPEDEF(struct mteTrigger);
    if (!entry)
        return NULL;

    row = netsnmp_tdata_create_row();
    if (!row) {
        SNMP_FREE(entry);
        return NULL;
    }
    row->data = entry;

    /*
     * ... initialize this row with the indexes supplied
     *     and the default values for the row...
     */
    if (mteOwner)
        memcpy(entry->mteOwner, mteOwner, mteOwner_len);
    netsnmp_table_row_add_index(row, ASN_OCTET_STR,
                                entry->mteOwner, mteOwner_len);
    if (mteTName)
        memcpy(entry->mteTName, mteTName, mteTName_len);
    netsnmp_table_row_add_index(row, ASN_PRIV_IMPLIED_OCTET_STR,
                                entry->mteTName, mteTName_len);

  //entry->mteTriggerTest         = MTE_TRIGGER_BOOLEAN;
    entry->mteTriggerValueID_len  = 2;  /* .0.0 */
    entry->mteTriggerFrequency    = 600;
    memcpy(entry->mteDeltaDiscontID, sysUpTime_instance,
                              sizeof(sysUpTime_instance));
    entry->mteDeltaDiscontID_len  = sysUpTime_inst_len;
    entry->mteDeltaDiscontIDType  = MTE_DELTAD_TTICKS;
    entry->mteTExTest             = (MTE_EXIST_PRESENT | MTE_EXIST_ABSENT);
    entry->mteTExStartup          = (MTE_EXIST_PRESENT | MTE_EXIST_ABSENT);
    entry->mteTBoolComparison     = MTE_BOOL_UNEQUAL;
    entry->flags                 |= MTE_TRIGGER_FLAG_BSTART;
    entry->mteTThStartup          = MTE_THRESH_START_RISEFALL;

    if (fixed)
        entry->flags |= MTE_TRIGGER_FLAG_FIXED;

    /*
     * ... and insert the row into the (common) table container
     */
    netsnmp_tdata_add_row(trigger_table_data, row);
    DEBUGMSGTL(("disman:event:table", "Trigger entry created\n"));
    return row;
}

/*
 * Remove a row from the trigger table 
 */
void
mteTrigger_removeEntry(netsnmp_tdata_row *row)
{
    struct mteTrigger *entry;

    if (!row)
        return;                 /* Nothing to remove */
    entry = (struct mteTrigger *)
        netsnmp_tdata_remove_and_delete_row(trigger_table_data, row);
    if (entry)
        SNMP_FREE(entry);
}

    /* ===================================================
     *
     * APIs for evaluating a trigger,
     *   and firing the appropriate event
     *
     * =================================================== */

void
mteTrigger_run( unsigned int reg, void *clientarg)
{
    struct mteTrigger *entry = (struct mteTrigger *)clientarg;
    netsnmp_variable_list *var, *vp1, *vp2 = NULL;
    netsnmp_variable_list *dvar = NULL;
    netsnmp_variable_list sysUT_var;
    oid    sysUT_oid[] = { 1, 3, 6, 1, 2, 1, 1, 3, 0 };
    size_t sysUT_oid_len = OID_LENGTH( sysUT_oid );
    int  cmp = 0, n;
    long value;

    if (!entry) {
        snmp_alarm_unregister( reg );
        return;
    }
    if (!(entry->flags & MTE_TRIGGER_FLAG_ENABLED ) ||
        !(entry->flags & MTE_TRIGGER_FLAG_ACTIVE )) {
        return;
    }

    /*
     * Retrieve the requested MIB value(s)...
     */
    DEBUGMSGTL(( "disman:event:trigger:monitor", "Running trigger (%s)\n", entry->mteTName));
    var = (netsnmp_variable_list *)SNMP_MALLOC_TYPEDEF( netsnmp_variable_list );
    snmp_set_var_objid( var, entry->mteTriggerValueID,
                             entry->mteTriggerValueID_len );
    if ( entry->flags & MTE_TRIGGER_FLAG_VWILD ) {
        netsnmp_query_walk( var, entry->session );
    } else {
        netsnmp_query_get(  var, entry->session );
    }
        /*
         * XXX - Deal with failures
         */

    /*
     * ... flatten missing values/exceptions into a single form
     *     (to simplify later comparisons) ...
     */
    for ( vp1 = var; vp1; vp1=vp1->next_variable ) {
        switch (vp1->type) {
        case SNMP_NOSUCHINSTANCE:
        case SNMP_NOSUCHOBJECT:
        case ASN_PRIV_RETRY:   /* Internal only ? */
        case ASN_NULL:
            vp1->type = ASN_NULL;
        }
    }

    /*
     * ... and then work through these result(s), deciding
     *     whether or not to trigger the corresponding event.
     *
     *  Note that there's no point in evaluating Existence or
     *    Boolean tests where there's no corresponding event.
     *   (Even if the trigger matches, nothing will be done anyway).
     */
    if ((entry->mteTriggerTest & MTE_TRIGGER_EXISTENCE) &&
        (entry->mteTExEvent[0] != '\0' )) {
        if ( !entry->old_results ) {
            /*
             * If we don't have a record of previous results,
             * this must be the first time through, so consider
             * the mteTriggerExistenceStartup tests.
             *
             * With the 'present(0)' test, the trigger should fire
             *   for each value in the varbind list returned
             *   (whether the monitored value is wildcarded or not).
             * An initial 'absent(1)' test only makes sense when
             *   monitoring a non-wildcarded OID (how would we know
             *   which rows of the table "ought" to exist, but don't?)
             */
            if (entry->mteTExTest & entry->mteTExStartup & MTE_EXIST_PRESENT) {
                for (vp1 = var; vp1; vp1=vp1->next_variable) {
                    DEBUGMSGTL(( "disman:event:trigger:fire",
                                 "Firing initial existence test: "));
                    DEBUGMSGOID(("disman:event:trigger:fire",
                                 vp1->name, vp1->name_length));
                    DEBUGMSG((   "disman:event:trigger:fire",
                                 " (present)\n"));;
                    entry->mteTriggerXOwner   = entry->mteTExObjOwner;
                    entry->mteTriggerXObjects = entry->mteTExObjects;
                    entry->mteTriggerFired    = vp1;
                    n = entry->mteTriggerValueID_len;
                    mteEvent_fire(entry->mteTExEvOwner, entry->mteTExEvent, 
                                  entry, vp1->name+n, vp1->name_length-n);
                }
            }
            if (entry->mteTExTest & entry->mteTExStartup & MTE_EXIST_ABSENT) {
                if (!(entry->flags & MTE_TRIGGER_FLAG_VWILD) &&
                    vp1->type == ASN_NULL ) {
                    DEBUGMSGTL(( "disman:event:trigger:fire",
                                 "Firing initial existence test: "));
                    DEBUGMSGOID(("disman:event:trigger:fire",
                                 var->name, var->name_length));
                    DEBUGMSG((   "disman:event:trigger:fire",
                                 " (absent)\n"));;
   /* XXX - what value should the 'mteHotValue' payload varbind take ?? */ 
                    entry->mteTriggerXOwner   = entry->mteTExObjOwner;
                    entry->mteTriggerXObjects = entry->mteTExObjects;
                    entry->mteTriggerFired    = vp1;
                    n = entry->mteTriggerValueID_len;
                    mteEvent_fire(entry->mteTExEvOwner, entry->mteTExEvent, 
                                  entry, vp1->name+n, vp1->name_length-n);
                }
            }
        } /* !old_results */
        else {
            /*
             * Otherwise, compare the current set of results with
             * the previous ones, looking for changes.
             */
            vp1 = var;
            vp2 = entry->old_results;
            while (vp1) {
                cmp = snmp_oid_compare(vp1->name, vp1->name_length,
                                       vp2->name, vp2->name_length);
                if ( cmp == 0 ) {
                    /*
                     * If the OIDs match, then compare the two values
                     * before moving on to the next pair of results.
                     */
                    if ((entry->mteTExTest & MTE_EXIST_PRESENT) &&
                        (vp1->type == ASN_NULL) &&
                        (vp2->type != ASN_NULL)) {
                        DEBUGMSGTL(( "disman:event:trigger:fire",
                                     "Firing existence test: "));
                        DEBUGMSGOID(("disman:event:trigger:fire",
                                     var->name, var->name_length));
                        DEBUGMSG((   "disman:event:trigger:fire",
                                     " (present)\n"));;
                        entry->mteTriggerXOwner   = entry->mteTExObjOwner;
                        entry->mteTriggerXObjects = entry->mteTExObjects;
                        entry->mteTriggerFired    = vp1;
                        n = entry->mteTriggerValueID_len;
                        mteEvent_fire(entry->mteTExEvOwner, entry->mteTExEvent, 
                                      entry, vp1->name+n, vp1->name_length-n);
                    } else if ((entry->mteTExTest & MTE_EXIST_ABSENT) &&
                        (vp1->type != ASN_NULL) &&
                        (vp2->type == ASN_NULL)) {
                        DEBUGMSGTL(( "disman:event:trigger:fire",
                                     "Firing existence test: "));
                        DEBUGMSGOID(("disman:event:trigger:fire",
                                     var->name, var->name_length));
                        DEBUGMSG((   "disman:event:trigger:fire",
                                     " (absent)\n"));;
                        entry->mteTriggerXOwner   = entry->mteTExObjOwner;
                        entry->mteTriggerXObjects = entry->mteTExObjects;
                        entry->mteTriggerFired    = vp1;
                        n = entry->mteTriggerValueID_len;
                        mteEvent_fire(entry->mteTExEvOwner, entry->mteTExEvent, 
                                      entry, vp1->name+n, vp1->name_length-n);
                    } else if ((entry->mteTExTest & MTE_EXIST_CHANGED) &&
                        ((vp1->val_len != vp2->val_len) || 
                         (memcmp( vp1->val.string, vp2->val.string,
                                  vp1->val_len) != 0 ))) {
                        /*
                         * This comparison detects changes in *any* type
                         *  of value, numeric or string (or even OID).
                         *
                         * Unfortunately, the default 'mteTriggerFired'
                         *  notification payload can't report non-numeric
                         *  changes properly (see syntax of 'mteHotValue')
                         */
                        DEBUGMSGTL(( "disman:event:trigger:fire",
                                     "Firing existence test: "));
                        DEBUGMSGOID(("disman:event:trigger:fire",
                                     var->name, var->name_length));
                        DEBUGMSG((   "disman:event:trigger:fire",
                                     " (changed)\n"));;
                        entry->mteTriggerXOwner   = entry->mteTExObjOwner;
                        entry->mteTriggerXObjects = entry->mteTExObjects;
                        entry->mteTriggerFired    = vp1;
                        n = entry->mteTriggerValueID_len;
                        mteEvent_fire(entry->mteTExEvOwner, entry->mteTExEvent, 
                                      entry, vp1->name+n, vp1->name_length-n);
                    }

                    vp1 = vp1->next_variable;
                    vp2 = vp2->next_variable;
                } else if ( cmp < 0 ) {
                    /*
                     * If a new value has appeared, then fire a 'present(0)'
                     * test, and move on to the next 'current' result.
                     */
                    if (entry->mteTExTest & MTE_EXIST_PRESENT) {
                        DEBUGMSGTL(( "disman:event:trigger:fire",
                                     "Firing existence test: "));
                        DEBUGMSGOID(("disman:event:trigger:fire",
                                     vp1->name, vp1->name_length));
                        DEBUGMSG((   "disman:event:trigger:fire",
                                     " (present)\n"));;
                        entry->mteTriggerXOwner   = entry->mteTExObjOwner;
                        entry->mteTriggerXObjects = entry->mteTExObjects;
                        entry->mteTriggerFired    = vp1;
                        n = entry->mteTriggerValueID_len;
                        mteEvent_fire(entry->mteTExEvOwner, entry->mteTExEvent, 
                                      entry, vp1->name+n, vp1->name_length-n);
                    }
                    vp1 = vp1->next_variable;
                } else {
                    /*
                     * While if an entry has disappeared, fire an 'absent(1)'
                     * test, and move on to the next 'old' result.
                     */
                    if (entry->mteTExTest & MTE_EXIST_ABSENT) {
                        DEBUGMSGTL(( "disman:event:trigger:fire",
                                     "Firing existence test: "));
                        DEBUGMSGOID(("disman:event:trigger:fire",
                                     vp2->name, vp2->name_length));
                        DEBUGMSG((   "disman:event:trigger:fire",
                                     " (absent)\n"));;
                        entry->mteTriggerXOwner   = entry->mteTExObjOwner;
                        entry->mteTriggerXObjects = entry->mteTExObjects;
                        entry->mteTriggerFired    = vp2;
                        /*
                         * XXX - the 'mteHotValue' payload varbind
                         *       will report the *previous* value.
                         */ 
                        n = entry->mteTriggerValueID_len;
                        mteEvent_fire(entry->mteTExEvOwner, entry->mteTExEvent, 
                                      entry, vp1->name+n, vp1->name_length-n);
                    }
                    vp2 = vp2->next_variable;
                }
            }
        } /* !old_results - else block */
    } /* MTE_TRIGGER_EXISTENCE */


    if (( entry->mteTriggerTest & MTE_TRIGGER_BOOLEAN   ) ||
        ( entry->mteTriggerTest & MTE_TRIGGER_THRESHOLD )) {
        /*
         * Although Existence tests can work with any syntax values,
         * Boolean and Threshold tests are integer-only.  Ensure that
         * the returned value(s) are appropriate.
         *
         * Note that we only need to check the first value, since all
         *  instances of a given object should have the same syntax.
         */
        switch (var->type) {
        case ASN_INTEGER:
        case ASN_COUNTER:
        case ASN_GAUGE:
        case ASN_TIMETICKS:
        case ASN_UINTEGER:
        case ASN_COUNTER64:
#ifdef OPAQUE_SPECIAL_TYPES
        case ASN_OPAQUE_COUNTER64:
        case ASN_OPAQUE_U64:
        case ASN_OPAQUE_I64:
#endif
            /* OK */
            break;
        default:
            /*
             * Other syntax values can't be used for Boolean/Theshold
             * tests. Report this as an error, and then rotate the
             * results ready for the next run, (which will presumably
             * also detect this as an error once again!)
             */
            DEBUGMSGTL(( "disman:event:trigger:fire",
                         "Returned non-integer result(s): "));
            DEBUGMSGOID(("disman:event:trigger:fire",
                         var->name, var->name_length));
            DEBUGMSG((   "disman:event:trigger:fire",
                         " (boolean/threshold)\n"));;
            snmp_free_varbind( entry->old_results );
            entry->old_results = var;
            return;
        }

        /*
         * Copy across the flags indicating which triggers are armed
         */
        if (entry->old_results) {
            vp2 = entry->old_results;
            for ( vp1 = var; vp1; vp1 = vp1->next_variable ) {
                if (vp2)
                    cmp = snmp_oid_compare(vp1->name, vp1->name_length,
                                           vp2->name, vp2->name_length);
                else
                    cmp = -1;
                if ( cmp == 0 ) {
                    /* Copy across armed flags */
                    vp1->index = vp2->index;
                    vp2 = vp2->next_variable;
                } else if ( cmp < 0 ) {
                    /* New entry */
                    vp1->index = MTE_ARMED_ALL;
                } else {
                    // XXX - Need to handle multiple deletions!
                    // while (cmp < 0)
                    /* Deleted entr(ies) */
                    vp2 = vp2->next_variable;
                    cmp = snmp_oid_compare(vp1->name, vp1->name_length,
                                       vp2->name, vp2->name_length);
                }
            }
        } else {
            for ( vp1 = var; vp1; vp1 = vp1->next_variable )
               vp1->index = MTE_ARMED_ALL;
        }

        /*
         * Retrieve the discontinuity markers for delta-valued samples.
         * (including sysUpTime.0 if not specified explicitly).
         */
        if ( entry->flags & MTE_TRIGGER_FLAG_DELTA ) {
            /*
             * We'll need sysUpTime.0 regardless...
             */
            snmp_set_var_objid( &sysUT_var, sysUT_oid, sysUT_oid_len );
            netsnmp_query_get(  &sysUT_var, entry->session );

            if ( snmp_oid_compare( entry->mteDeltaDiscontID, sysUT_oid_len-1,
                                   sysUT_oid, sysUT_oid_len-1) != 0 ) {
                /*
                 * ... but only retrieve the configured discontinuity
                 *      marker(s) if they refer to something different.
                 */
                dvar = (netsnmp_variable_list *)
                                SNMP_MALLOC_TYPEDEF( netsnmp_variable_list );
                snmp_set_var_objid( dvar, entry->mteDeltaDiscontID,
                                          entry->mteDeltaDiscontID_len );
                if ( entry->flags & MTE_TRIGGER_FLAG_DWILD ) {
                    netsnmp_query_walk( dvar, entry->session );
                } else {
                    netsnmp_query_get(  dvar, entry->session );
                }
                /* XXX - handle errors */
            }

            /*
             * If this is the first time through, we can't calculate
             *  the delta values, so there's no point in trying to
             *  evaluate the remaining tests.
             *
             * Save the results (and discontinuity markers),
             *  ready for the next run.
             */
            if ( !entry->old_results ) {
                entry->old_results =  var;
                entry->old_deltaDs = dvar;
                entry->sysUpTime   = *sysUT_var.val.integer;
                return;
            }
            /*
             * If the sysUpTime value (or another non-wildcarded
             *  discontinuity value) has changed, then there's no
             *  point in trying to evaluate these tests either.
             */
            if ((entry->sysUpTime != *sysUT_var.val.integer) ||
                (!(entry->flags & MTE_TRIGGER_FLAG_DWILD) &&
                  (entry->old_deltaDs->val.integer != dvar->val.integer))) {
                snmp_free_varbind( entry->old_results );
                snmp_free_varbind( entry->old_deltaDs );
                entry->old_results =  var;
                entry->old_deltaDs = dvar;
                entry->sysUpTime   = *sysUT_var.val.integer;
                return;
            }
        } /* delta samples */
    } /* Boolean/Threshold test checks */


    if ((entry->mteTriggerTest & MTE_TRIGGER_BOOLEAN) &&
        (entry->mteTBoolEvent[0] != '\0' )) {

        if (entry->flags & MTE_TRIGGER_FLAG_DWILD)
            vp2 = entry->old_results;
        for ( vp1 = var; vp1; vp1=vp1->next_variable ) {
            /*
             * Determine the value to be monitored...
             */
            if (entry->flags & MTE_TRIGGER_FLAG_DWILD) {
                /* XXX - check the suffix matches      */
                /* XXX - check the discontinuity value */
                value = (*vp1->val.integer - *vp2->val.integer);
                vp2 = vp2->next_variable;
            } else {
                value = *vp1->val.integer;
            }

            /*
             * ... evaluate the comparison ...
             */
            switch (entry->mteTBoolComparison) {
            case MTE_BOOL_UNEQUAL:
                cmp = ( value != entry->mteTBoolValue );
                break;
            case MTE_BOOL_EQUAL:
                cmp = ( value == entry->mteTBoolValue );
                break;
            case MTE_BOOL_LESS:
                cmp = ( value <  entry->mteTBoolValue );
                break;
            case MTE_BOOL_LESSEQUAL:
                cmp = ( value <= entry->mteTBoolValue );
                break;
            case MTE_BOOL_GREATER:
                cmp = ( value >  entry->mteTBoolValue );
                break;
            case MTE_BOOL_GREATEREQUAL:
                cmp = ( value >= entry->mteTBoolValue );
                break;
            }

            /*
             * ... and decide whether to trigger the event.
             *    (using the 'index' field of the varbind structure
             *     to remember whether the trigger has already fired)
             */
            if ( cmp ) {
                if ((!entry->old_results &&
                     (entry->flags & MTE_TRIGGER_FLAG_BSTART)) ||
                    (vp1->index & MTE_ARMED_BOOLEAN )) {
                    DEBUGMSGTL(( "disman:event:trigger:fire",
                                 "Firing boolean test: "));
                    DEBUGMSGOID(("disman:event:trigger:fire",
                                 vp1->name, vp1->name_length));
                    DEBUGMSG((   "disman:event:trigger:fire", "%s\n",
                                  (entry->old_results ? "" : " (startup)")));
                    vp1->index &= ~MTE_ARMED_BOOLEAN;
                    entry->mteTriggerXOwner   = entry->mteTBoolObjOwner;
                    entry->mteTriggerXObjects = entry->mteTBoolObjects;
                    entry->mteTriggerFired    = vp1;
                    n = entry->mteTriggerValueID_len;
                    mteEvent_fire(entry->mteTBoolEvOwner, entry->mteTBoolEvent, 
                                  entry, vp1->name+n, vp1->name_length-n);
                }
            } else {
                vp1->index |= MTE_ARMED_BOOLEAN;
            }
        }
    }

    if ( entry->mteTriggerTest & MTE_TRIGGER_THRESHOLD ) {
        if (entry->flags & MTE_TRIGGER_FLAG_DWILD)
            vp2 = entry->old_results;
        for ( vp1 = var; vp1; vp1=vp1->next_variable ) {
            /*
             * Determine the value to be monitored...
             */
            if (entry->flags & MTE_TRIGGER_FLAG_DWILD) {
                /* XXX - check the suffix matches      */
                /* XXX - check the discontinuity value */
                value = (*vp1->val.integer - *vp2->val.integer);
                vp2 = vp2->next_variable;
            } else {
                value = *vp1->val.integer;
            }

            /*
             * ... evaluate the single-value comparisons,
             *     and decide whether to trigger the event.
             */
            cmp = vp1->index;   /* working copy of 'armed' flags */
            if ( value >= entry->mteTThRiseValue ) {
                if ((!entry->old_results &&
                     (entry->mteTThStartup & MTE_THRESH_START_RISE)) || 
                    (vp1->index & MTE_ARMED_TH_RISE )) {
                    DEBUGMSGTL(( "disman:event:trigger:fire",
                                 "Firing rising threshold test: "));
                    DEBUGMSGOID(("disman:event:trigger:fire",
                                 vp1->name, vp1->name_length));
                    DEBUGMSG((   "disman:event:trigger:fire", "%s\n",
                                 (entry->old_results ? "" : " (startup)")));
                    cmp &= ~MTE_ARMED_TH_RISE;
                    cmp |=  MTE_ARMED_TH_FALL;
                    entry->mteTriggerXOwner   = entry->mteTThObjOwner;
                    entry->mteTriggerXObjects = entry->mteTThObjects;
                    entry->mteTriggerFired    = vp1;
                    n = entry->mteTriggerValueID_len;
                    mteEvent_fire(entry->mteTThRiseOwner, entry->mteTThRiseEvent, 
                                  entry, vp1->name+n, vp1->name_length-n);
                }
            }

            if ( value <= entry->mteTThFallValue ) {
                if ((!entry->old_results &&
                     (entry->mteTThStartup & MTE_THRESH_START_FALL)) || 
                    (vp1->index & MTE_ARMED_TH_FALL )) {
                    DEBUGMSGTL(( "disman:event:trigger:fire",
                                 "Firing falling threshold test: "));
                    DEBUGMSGOID(("disman:event:trigger:fire",
                                 vp1->name, vp1->name_length));
                    DEBUGMSG((   "disman:event:trigger:fire", "%s\n",
                                 (entry->old_results ? "" : " (startup)")));
                    cmp &= ~MTE_ARMED_TH_FALL;
                    cmp |=  MTE_ARMED_TH_RISE;
                    entry->mteTriggerXOwner   = entry->mteTThObjOwner;
                    entry->mteTriggerXObjects = entry->mteTThObjects;
                    entry->mteTriggerFired    = vp1;
                    n = entry->mteTriggerValueID_len;
                    mteEvent_fire(entry->mteTThFallOwner, entry->mteTThFallEvent, 
                                  entry, vp1->name+n, vp1->name_length-n);
                }
            }
            vp1->index = cmp;
        }
    }

    /*
     * Finally, rotate the results - ready for the next run.
     */
    snmp_free_varbind( entry->old_results );
    entry->old_results = var;
    if ( entry->flags & MTE_TRIGGER_FLAG_DELTA ) {
        snmp_free_varbind( entry->old_deltaDs );
        entry->old_deltaDs = dvar;
        entry->sysUpTime   = *sysUT_var.val.integer;
    }
}

void
mteTrigger_enable( struct mteTrigger *entry )
{
    if (!entry)
        return;

    if (entry->alarm)
        snmp_alarm_unregister( entry->alarm );

    if (entry->mteTriggerFrequency) {
        entry->alarm = snmp_alarm_register(
                           entry->mteTriggerFrequency, SA_REPEAT,
                           mteTrigger_run, entry );
        mteTrigger_run( entry->alarm, (void*)entry );
    }
}

void
mteTrigger_disable( struct mteTrigger *entry )
{
    if (!entry)
        return;

    if (entry->alarm) {
        snmp_alarm_unregister( entry->alarm );
        entry->alarm = 0;
        /* XXX - perhaps release any previous results */
    }
}
