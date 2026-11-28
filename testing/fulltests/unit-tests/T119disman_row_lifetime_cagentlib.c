/* HEADER Testing DISMAN-SCHEDULE/EXPRESSION-MIB rows removed while in use */

#include <net-snmp/agent/mib_module_config.h>

#if defined(USING_DISMAN_SCHEDULE_SCHEDTABLE_MODULE) && \
    defined(USING_UTILITIES_IQUERY_MODULE) && \
    !defined(NETSNMP_NO_WRITE_SUPPORT) && \
    !defined(NETSNMP_DISABLE_SET_SUPPORT)
#define HAVE_SCHED_TEST 1
#endif

#if defined(USING_DISMAN_EXPR_EXPEXPRESSION_MODULE) && \
    defined(USING_DISMAN_EXPR_EXPOBJECT_MODULE)
#define HAVE_EXPR_TEST 1
#endif

#if !defined(HAVE_SCHED_TEST) && !defined(HAVE_EXPR_TEST)
printf("1..0 # skip disman/schedule and disman/expr tests not enabled\n");
__did_plan = 1;
return 0;
#else
#ifdef HAVE_SCHED_TEST
#include "disman/schedule/schedCore.h"
#include "disman/schedule/schedTable.h"
#include "utilities/iquery.h"
#endif
#ifdef HAVE_EXPR_TEST
#include "disman/expr/expExpression.h"
#include "disman/expr/expObject.h"
#endif

/*
 * snmp_alarm_reset() fails for an alarm id that is not registered (and
 * restarts the interval of one that is, which does not matter here).
 */
#define REGISTERED(id) ((id) != 0 && snmp_alarm_reset(id) == 0)

SOCK_STARTUP;

/* Run alarms only from run_alarms() below, as snmpd does. */
netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_ALARM_DONT_USE_SIG, 1);
netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_DONT_PERSIST_STATE, 1);
init_agent("snmpd");
#ifdef HAVE_SCHED_TEST
init_schedTable();
#endif
#ifdef HAVE_EXPR_TEST
init_expr_table_data();
init_expObject_table_data();
#endif
init_snmp("snmpd");

#ifdef HAVE_SCHED_TEST
/* A scheduled action that deletes its own row. */
{
    /* schedRowStatus."o"."n" */
    static const oid rowstatus_oid[] = { 1, 3, 6, 1, 2, 1, 63, 1, 2, 1,
                                         COLUMN_SCHEDROWSTATUS,
                                         1, 'o', 1, 'n' };
    char rwuser_line[] = "rwuser internal";
    netsnmp_tdata_row *row;
    struct schedTable_entry *sched;
    struct timeval now, deadline;
#ifndef WIN32
    struct timeval tv;
#endif

    netsnmp_config(rwuser_line);

    row = schedTable_createEntry("o", "n");
    OK(row != NULL, "schedule entry created");
    sched = (struct schedTable_entry *)row->data;
    memcpy(sched->schedVariable, rowstatus_oid, sizeof(rowstatus_oid));
    sched->schedVariable_len = OID_LENGTH(rowstatus_oid);
    sched->schedValue = RS_DESTROY;
    sched->schedType = SCHED_TYPE_PERIODIC;
    sched->schedInterval = 1;
    sched->session = netsnmp_iquery_user_session("internal");
    OK(sched->session != NULL, "internal query session created");
    sched->flags = SCHEDULE_FLAG_ENABLED | SCHEDULE_FLAG_ACTIVE |
                   SCHEDULE_FLAG_VALID;
    sched_nextTime(sched);
    OK(sched->schedCallbackID != 0, "schedule entry registers its alarm");

    netsnmp_get_monotonic_clock(&now);
    deadline = now;
    deadline.tv_sec += 10;
    while (netsnmp_tdata_row_count(schedule_table) > 0 &&
           (now.tv_sec < deadline.tv_sec ||
            (now.tv_sec == deadline.tv_sec && now.tv_usec < deadline.tv_usec))) {
        run_alarms();
        if (netsnmp_tdata_row_count(schedule_table) == 0)
            break;
#ifdef WIN32
        Sleep(10);
#else
        tv.tv_sec = 0;
        tv.tv_usec = 10000;
        select(0, NULL, NULL, NULL, &tv);
#endif
        netsnmp_get_monotonic_clock(&now);
    }
    OK(netsnmp_tdata_row_count(schedule_table) == 0,
       "the scheduled action deletes its own row");

    netsnmp_get_monotonic_clock(&now);
    deadline = now;
    deadline.tv_sec += 2;
    while (now.tv_sec < deadline.tv_sec ||
           (now.tv_sec == deadline.tv_sec && now.tv_usec < deadline.tv_usec)) {
        run_alarms();
#ifdef WIN32
        Sleep(10);
#else
        tv.tv_sec = 0;
        tv.tv_usec = 10000;
        select(0, NULL, NULL, NULL, &tv);
#endif
        netsnmp_get_monotonic_clock(&now);
    }
    OK(netsnmp_tdata_row_count(schedule_table) == 0,
       "no entry is left after the deletion");
}
#endif

#ifdef HAVE_EXPR_TEST
{
    netsnmp_tdata_row *row;
    struct expExpression *exp;
    struct expObject *obj1, *obj2, *obj3;
    unsigned int alarm;

    /* An expression removed while in use is freed when it is released. */
    row = expExpression_createRow("o", "e", 0);
    OK(row != NULL, "expression created");
    exp = (struct expExpression *)row->data;
    exp->expDeltaInterval = 600;
    expExpression_enable(exp);
    alarm = exp->alarm;
    OK(REGISTERED(alarm), "enable registers the sampling alarm");
    expExpression_hold(exp);
    expExpression_removeEntry(row);
    OK(exp->removed, "removing an expression in use defers the free");
    OK(!REGISTERED(alarm), "removing an expression cancels its alarm");
    OK(expExpression_getEntry("o", "e") == NULL,
       "a removed expression is no longer in the table");
    expExpression_release(exp);

    /* Iteration goes on past an object removed while in use. */
    obj1 = expObject_createEntry("o", "e", 1, 0);
    obj2 = expObject_createEntry("o", "e", 2, 0);
    obj3 = expObject_createEntry("o", "e", 3, 0);
    OK(obj1 && obj2 && obj3, "expression objects created");
    row = expObject_getFirst("o", "e");
    OK(row != NULL && row->data == obj1, "first object found");
    row = expObject_getNext(row);
    OK(row != NULL && row->data == obj2, "second object found");
    expObject_hold(obj2);
    expObject_removeEntry(row);
    OK(obj2->removed, "removing an object in use defers the free");
    row = expObject_getNextEntry(obj2);
    OK(row != NULL && row->data == obj3,
       "the object after a removed one is found");
    expObject_release(obj2);
    expObject_removeEntry(expObject_getFirst("o", "e"));
    expObject_removeEntry(expObject_getFirst("o", "e"));
    OK(expObject_getFirst("o", "e") == NULL, "all objects removed");

    /* An expression held twice is freed by the last release only. */
    row = expExpression_createRow("o", "n", 0);
    OK(row != NULL, "second expression created");
    exp = (struct expExpression *)row->data;
    expExpression_hold(exp);
    expExpression_hold(exp);
    expExpression_removeEntry(row);
    expExpression_release(exp);
    OK(exp->removed && exp->in_use == 1,
       "an expression held twice stays allocated after one release");
    expExpression_release(exp);

    /* No object follows a removed last object. */
    obj1 = expObject_createEntry("o", "n", 1, 0);
    OK(obj1 != NULL, "single object created");
    expObject_hold(obj1);
    expObject_removeEntry(expObject_getFirst("o", "n"));
    OK(expObject_getNextEntry(obj1) == NULL,
       "no object follows a removed last object");
    expObject_release(obj1);

    /* The prefix object stores its own copy of the expression's prefix list. */
    {
        static const oid prefix_oid[] = { 1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1 };
        long value = 1;

        row = expExpression_createRow("o", "p", 0);
        OK(row != NULL, "wildcarded expression created");
        exp = (struct expExpression *)row->data;
        snmp_varlist_add_variable(&exp->pvars, prefix_oid,
                                  OID_LENGTH(prefix_oid), ASN_INTEGER,
                                  &value, sizeof(value));
        obj1 = expObject_createEntry("o", "p", 1, 0);
        OK(obj1 != NULL && exp->pvars != NULL, "prefix object created");
        obj1->flags |= EXP_OBJ_FLAG_PREFIX;
        expObject_getData(exp, obj1);
        OK(obj1->vars != NULL && obj1->vars != exp->pvars &&
           snmp_oid_compare(obj1->vars->name, obj1->vars->name_length,
                            prefix_oid, OID_LENGTH(prefix_oid)) == 0,
           "expObject_getData stores a copy of the prefix list");
        expObject_removeEntry(expObject_getFirst("o", "p"));
        OK(exp->pvars != NULL &&
           snmp_oid_compare(exp->pvars->name, exp->pvars->name_length,
                            prefix_oid, OID_LENGTH(prefix_oid)) == 0,
           "the prefix list outlives its prefix object");
        expExpression_removeEntry(row);
        OK(expExpression_getEntry("o", "p") == NULL,
           "the wildcarded expression is removed");
    }
}
#endif

snmp_shutdown("snmpd");
shutdown_agent();
SOCK_CLEANUP;
#endif
