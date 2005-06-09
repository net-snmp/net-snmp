#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <ctype.h>
#include "disman/schedCore.h"
#include "disman/schedConf.h"

extern netsnmp_table_data *schedTable;
static int schedEntries;

/** Initializes the schedConf module */
void
init_schedConf(void)
{
    DEBUGMSGTL(("sched", "Initializing config module\n"));

    /*
     * Register public configuration directives
     */
    snmpd_register_config_handler("repeat", parse_sched_periodic,
                                            NULL, NULL);
    snmpd_register_config_handler("cron",   parse_sched_timed,
                                            NULL, NULL);
    snmpd_register_config_handler("at",     parse_sched_timed,
                                            NULL, NULL);
    /*
     * Register internal configuration directive,
     *   and arrange for dynamically configured entries to be saved
     */
    snmpd_register_config_handler("schedTable", parse_schedTable,
                                            NULL, NULL);
    snmp_register_callback(SNMP_CALLBACK_LIBRARY, SNMP_CALLBACK_STORE_DATA,
                           store_schedTable, NULL);

    schedEntries = 0;
}


/*
 * Handle a "repeat" config directive, to set up a periodically
 *     scheduled action
 */
void
parse_sched_periodic( const char *token, char *line )
{
    netsnmp_table_row *row;
    struct schedTable_entry *entry;
    char buf[24];
    long frequency;
    long value;
    size_t tmpint;
    oid  variable[MAX_OID_LEN], *var_ptr = variable;
    size_t var_len = MAX_OID_LEN;
    
    schedEntries++;
    sprintf(buf, "_conf%03d", schedEntries);

    DEBUGMSGTL(( "sched", "config: %s %s\n", token, line));
    /*
     *  Parse the configure directive line
     */
    line = read_config_read_data(ASN_INTEGER,   line, &frequency, &tmpint);
    line = read_config_read_data(ASN_OBJECT_ID, line, &var_ptr,   &var_len);
    if (var_len == 0) {
        config_perror("invalid specification for schedVariable");
        return;
    }
    /*
     * Skip over optional assignment in "var = value"
     */
    while (line && isspace(*line))
        line++;
    if (line && *line == '=' ) {
        line++;
        while (line && isspace(*line)) {
            line++;
        }
    }
    line = read_config_read_data(ASN_INTEGER,   line, &value, &tmpint);
    
    /*
     * Create an entry in the schedTable
     */
    row = schedTable_createEntry(schedTable, "snmpd.conf", strlen("snmpd.conf"),
                                             buf, strlen(buf), NULL );
    entry = (struct schedTable_entry *)row->data;

    entry->schedInterval     = frequency;
    memcpy(entry->schedVariable, variable, var_len*sizeof(oid));
    entry->schedVariable_len = var_len;
    entry->schedValue        = value;

    entry->schedType         = SCHED_TYPE_PERIODIC;

    entry->schedAdminStatus = 1;  /* Enable the entry */
    entry->schedRowStatus   = 1;
    entry->schedStorageType = ST_READONLY;

    sched_nextTime( entry );
}


/*
 * Handle a "cron" or "at config directive, to set up a
 *     time-scheduled action
 */
void
parse_sched_timed( const char *token, char *line )
{
    netsnmp_table_row *row;
    struct schedTable_entry *entry;
    char buf[24];

    char *minConf;   size_t min_len;   char minVal[8];
    char *hourConf;  size_t hour_len;  char hourVal[3];
    char *dateConf;  size_t date_len;  char dateVal[8];
    char *monConf;   size_t mon_len;   char monVal[2];
    char *dayConf;   size_t day_len;   char dayVal;

    long value;
    size_t tmpint;
    oid *variable;
    size_t var_len = MAX_OID_LEN;
    
    schedEntries++;
    sprintf(buf, "_conf%03d", schedEntries);

    DEBUGMSGTL(( "sched", "config: %s %s\n", token, line));
    /*
     *  Parse the configure directive line
     */
    line = read_config_read_data(ASN_OCTET_STR, line, &minConf,   &min_len);
    line = read_config_read_data(ASN_OCTET_STR, line, &hourConf,  &hour_len);
    line = read_config_read_data(ASN_OCTET_STR, line, &dateConf,  &date_len);
    line = read_config_read_data(ASN_OCTET_STR, line, &monConf,   &mon_len);
    line = read_config_read_data(ASN_OCTET_STR, line, &dayConf,   &day_len);

    line = read_config_read_data(ASN_OBJECT_ID, line, &variable,  &var_len);
    if ( *line == '=' ) {
        line++;
        while (line && isspace(*line)) {
            line++;
        }
    }
    line = read_config_read_data(ASN_INTEGER,   line, &value, &tmpint);
    /* XXX - Check for errors & bail out */

    /* XXX - Convert from cron-style spec into bits */
    
    row = schedTable_createEntry(schedTable, "snmpd.conf", strlen("snmpd.conf"),
                                             buf, strlen(buf), NULL );
    entry = (struct schedTable_entry *)row->data;

/*
    entry->schedWeekDay = dayVal;
    memcpy(entry->schedMonth,  monVal,  2);
    memcpy(entry->schedDay,    dateVal, 4+4);
    memcpy(entry->schedHour,   hourVal, 3);
    memcpy(entry->schedMinute, minVal,  8);
 */
    
    memcpy(entry->schedVariable, variable, var_len*sizeof(oid));
    entry->schedVariable_len = var_len;
    entry->schedValue        = value;

    if ( !strcmp( token, "at" ))
        entry->schedType     = SCHED_TYPE_ONESHOT;
    else
        entry->schedType     = SCHED_TYPE_CALENDAR;

    entry->schedAdminStatus = 1;  /* Enable the entry */
    entry->schedRowStatus   = 1;
    entry->schedStorageType = ST_READONLY;

    sched_nextTime( entry );
}


/*
 * Handle a "schedTable" config directive, to set up a
 *     dynamically-configured scheduled entry
 */
void
parse_schedTable( const char *token, char *line )
{
    netsnmp_table_row *row;
    struct schedTable_entry *entry;

    DEBUGMSGTL(( "sched", "config: %s %s\n", token, line));

    /* XXX - TODO */
}

/*
 * Save dynamically-configured schedTable entries into persistent storage
 */
int
store_schedTable(int majorID, int minorID, void *serverarg, void *clientarg)
{
    netsnmp_table_row *row;
    struct schedTable_entry *entry;

    char            line[SNMP_MAXBUF];
    char           *cptr;
    size_t          tmpint;

    DEBUGMSGTL(( "sched", "config: store schedTable\n"));

    for ( row =  netsnmp_table_data_get_first_row( schedTable );
          row;
          row =  netsnmp_table_data_get_next_row(  schedTable, row )) {

        if (!row->data)
            continue;
        entry = (struct schedTable_entry *)row->data;

            /* Only save 'nonVolatile' or 'permanent' entries */
        if (entry->schedStorageType != ST_NONVOLATILE &&
            entry->schedStorageType != ST_PERMANENT )
            continue;

        memset(line, 0, sizeof(line));
        strcpy(line, "schedTable ");
        cptr = line + strlen(line);

        cptr = read_config_store_data(ASN_OCTET_STR, cptr,
                      "XXX - TODO", &tmpint);

        snmpd_store_config(line);
    }
    return SNMPERR_SUCCESS;
}
