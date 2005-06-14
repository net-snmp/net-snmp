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
    char  *schedUser = netsnmp_ds_get_string(NETSNMP_DS_APPLICATION_ID,
                                             NETSNMP_DS_AGENT_INTERNAL_SECNAME);
    
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
    if ( !schedUser ) {
        config_perror("no authorization configured for schedEntry");
        return;
    }
    row = schedTable_createEntry(schedTable,
                                 schedUser, strlen(schedUser),
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
 * Convert from a cron-style specification to the equivalent set of bits.
 * Note that minute, hour and weekday crontab fields are 0-based,
 * while day and month more naturally start from 1.
 */
void
_sched_convert_bits( char *cron_spec, char *bit_buf,
                     int  bit_buf_len, int max_val, int startAt1 ) {
    char *cp = cron_spec;
    char b[] = {0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01};
    int val, major, minor;
 
    /*
     * Wildcard field - set all bits
     */
    if ( *cp == '*' ) {
        memset( bit_buf, 0xff, bit_buf_len );

        /*
         * An "all-bits" specification may not be an exact multiple of 8.
         * Work out how far we've overshot things, and tidy up the excess.
         */
        int overshoot = 8*bit_buf_len-max_val;
        while ( overshoot > 0 ) {
            bit_buf[ bit_buf_len-1 ] ^= b[8-overshoot];
            overshoot--;
        }
        return;
    }

    /*
     * Otherwise, clear the bit string buffer,
     * and start calculating which bits to set
     */
    memset( bit_buf, 0, bit_buf_len );

    while (1) {
        sscanf( cp, "%d", &val);
        /* Handle negative day specification */
        if ( val < 0 ) {
            val = max_val - val; 
        }
        if ( startAt1 )
            val--;
        major = val/8;
        minor = val%8;
        bit_buf[ major ] |= b[minor];

        /* XXX - ideally we should handle "X-Y" syntax as well */
        while (*cp && *cp!=',')
            cp++;
        if (!*cp)
            break;
        cp++;
    }
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
    char buf[24], *cp;
    char  *schedUser = netsnmp_ds_get_string(NETSNMP_DS_APPLICATION_ID,
                                             NETSNMP_DS_AGENT_INTERNAL_SECNAME);

    char  minConf[512];  size_t  min_len = sizeof(minConf);  char  minVal[8];
    char hourConf[512];  size_t hour_len = sizeof(hourConf); char hourVal[3];
    char dateConf[512];  size_t date_len = sizeof(dateConf); char dateVal[8];
    char  monConf[512];  size_t  mon_len = sizeof(monConf);  char  monVal[2];
    char  dayConf[512];  size_t  day_len = sizeof(dayConf);  char  dayVal;

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
    cp       = minConf;
    line = read_config_read_data(ASN_OCTET_STR, line, &cp,   &min_len);
    cp       = hourConf;
    line = read_config_read_data(ASN_OCTET_STR, line, &cp,  &hour_len);
    cp       = dateConf;
    line = read_config_read_data(ASN_OCTET_STR, line, &cp,  &date_len);
    cp       = monConf;
    line = read_config_read_data(ASN_OCTET_STR, line, &cp,   &mon_len);
    cp       = dayConf;
    line = read_config_read_data(ASN_OCTET_STR, line, &cp,   &day_len);
    if (!line) {
        config_perror("invalid schedule time specification");
        return;
    }

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
    if ( *line == '=' ) {
        line++;
        while (line && isspace(*line)) {
            line++;
        }
    }
    line = read_config_read_data(ASN_INTEGER,   line, &value, &tmpint);

    /*
     * Convert from cron-style specifications into bits
     */
    _sched_convert_bits( minConf,  minVal,  8, 60, 0 );
    _sched_convert_bits( hourConf, hourVal, 3, 24, 0 );
    memset(dateVal+4, 0, 4); /* Clear the reverse day bits */
    _sched_convert_bits( dateConf, dateVal, 4, 31, 1 );
    _sched_convert_bits( monConf,  monVal,  2, 12, 1 );
    _sched_convert_bits( dayConf, &dayVal,  1,  8, 0 );
    if ( dayVal & 0x01 ) {  /* sunday(7) = sunday(0) */
         dayVal |= 0x80;
         dayVal &= 0xfe;
    }
    
    /*
     * Create an entry in the schedTable
     */
    if ( !schedUser ) {
        config_perror("no authorization configured for schedEntry");
        return;
    }
    row = schedTable_createEntry(schedTable,
                                 schedUser, strlen(schedUser),
                                 buf, strlen(buf), NULL );
    entry = (struct schedTable_entry *)row->data;

    entry->schedWeekDay = dayVal;
    memcpy(entry->schedMonth,  monVal,  2);
    memcpy(entry->schedDay,    dateVal, 4+4);
    memcpy(entry->schedHour,   hourVal, 3);
    memcpy(entry->schedMinute, minVal,  8);
    
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
