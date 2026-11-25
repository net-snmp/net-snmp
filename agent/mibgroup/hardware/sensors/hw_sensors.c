#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/hardware/sensors.h>
#include "hw_sensors_private.h"


static int  _sensor_load( void );
static void _sensor_free( void );
static void _sensor_remove_inactive( void );
static int  _sensor_index_for( const char *name );
static void _sensor_parse_index( const char *token, char *line );
static int  _sensor_store_index( int majorID, int minorID,
                                 void *serverarg, void *clientarg );

static int _sensorAutoUpdate = 0;   /* 0 means on-demand caching */
static void _sensor_update_stats( unsigned int, void* );

netsnmp_cache     *_sensor_cache     = NULL;
netsnmp_container *_sensor_container = NULL;
static netsnmp_container *_sensor_name_container = NULL;
static netsnmp_container *_sensor_index_map      = NULL;
static int         _sensor_idx       = 0;

/*
 * The index assigned to each sensor name.
 *
 * This is kept in persistent storage, so that a sensor keeps the same
 *  index across agent restarts, and when it disappears and comes back.
 */
struct sensor_index_entry {
    char *name;
    int   idx;
};

static int
_sensor_name_compare( const void *lhs, const void *rhs )
{
    return strcmp( ((const netsnmp_sensor_info *)lhs)->name,
                   ((const netsnmp_sensor_info *)rhs)->name );
}

static int
_sensor_index_compare( const void *lhs, const void *rhs )
{
    return strcmp( ((const struct sensor_index_entry *)lhs)->name,
                   ((const struct sensor_index_entry *)rhs)->name );
}

void init_hw_sensors( void ) {

    if ( _sensor_container )
        return;   /* Already initialised */

    DEBUGMSGTL(("sensors", "Initialise Hardware Sensors module\n"));

    /*
     * Define a container to hold the basic list of sensors
     * The four LM-SENSOR-MIB containers will be created in
     *  the relevant initialisation routine(s)
     */
    _sensor_container = netsnmp_container_find("sensorTable:table_container");
    if ( NULL == _sensor_container ) {
        snmp_log( LOG_ERR, "failed to create container for sensorTable");
        return;
    }

    /*
     * A secondary index, for looking up sensors by name
     */
    _sensor_name_container = netsnmp_container_find("sensorName:binary_array");
    if ( NULL == _sensor_name_container ) {
        snmp_log( LOG_ERR, "failed to create sensor name container");
        return;
    }
    _sensor_name_container->compare = _sensor_name_compare;
    netsnmp_container_add_index( _sensor_container, _sensor_name_container );

    _sensor_index_map = netsnmp_container_find("sensorIndex:binary_array");
    if ( NULL == _sensor_index_map ) {
        snmp_log( LOG_ERR, "failed to create sensor index container");
        return;
    }
    _sensor_index_map->compare = _sensor_index_compare;
    snmpd_register_config_handler( "sensorIndex", _sensor_parse_index,
                                   NULL, NULL );
    snmp_register_callback( SNMP_CALLBACK_LIBRARY, SNMP_CALLBACK_STORE_DATA,
                            _sensor_store_index, NULL );

    netsnmp_sensor_arch_init( );

    /*
     * If we're sampling the sensor information automatically,
     *   then arrange for this to be triggered regularly.
     *
     * If we're not sampling these values regularly,
     *   create a suitable cache handler instead.
     */
    if ( _sensorAutoUpdate ) {
        DEBUGMSGTL(("sensors", "Reloading Hardware Sensors automatically (%d)\n",
                               _sensorAutoUpdate));
        snmp_alarm_register( _sensorAutoUpdate, SA_REPEAT,
                             _sensor_update_stats, NULL );
    }
    else {
        _sensor_cache = netsnmp_cache_create( 5, netsnmp_sensor_load,
                                                 netsnmp_sensor_free, NULL, 0 );
        DEBUGMSGTL(("sensors", "Reloading Hardware Sensors on-demand (%p)\n",
                               _sensor_cache));
    }
}

void shutdown_hw_sensors( void ) {
    _sensor_free();
}

/*
 *  Return the main sensor container
 */
netsnmp_container *get_sensor_container( void ) { return _sensor_container; }

/*
 *  Return the main sensor cache control structure (if defined)
 */
netsnmp_cache *get_sensor_cache( void ) { return _sensor_cache; }


/*
 * Wrapper routine for automatically updating sensor statistics
 */
void
_sensor_update_stats( unsigned int clientreg, void *data )
{
    _sensor_free();
    _sensor_load();
}

/*
 * Wrapper routine for re-loading sensor statistics on demand
 */
int
netsnmp_sensor_load( netsnmp_cache *cache, void *data )
{
    return _sensor_load();
}

/*
 * Wrapper routine for releasing expired sensor statistics
 */
void
netsnmp_sensor_free( netsnmp_cache *cache, void *data )
{
    _sensor_free();
}


/*
 * Architecture-independent processing of loading sensor statistics
 */
static int
_sensor_load( void )
{
    _sensor_free();
    /*
     * Drop any sensors that were not seen during this reload,
     *  unless the reload itself failed.
     */
    if ( netsnmp_sensor_arch_load( NULL, NULL ) == 0 )
        _sensor_remove_inactive();
    return 0;
}

/*
 * Remove sensor entries that are no longer active
 */
static void
_sensor_remove_inactive( void )
{
    netsnmp_sensor_info **stale, *sp;
    size_t                n = 0, i;

    if ( !CONTAINER_SIZE( _sensor_container ))
        return;
    stale = calloc( CONTAINER_SIZE( _sensor_container ), sizeof(*stale));
    if ( !stale )
        return;

    for (sp = CONTAINER_FIRST( _sensor_container );
         sp;
         sp = CONTAINER_NEXT(  _sensor_container, sp )) {

         if ( !( sp->flags & NETSNMP_SENSOR_FLAG_ACTIVE ))
             stale[n++] = sp;
    }

    for ( i = 0; i < n; i++ ) {
        DEBUGMSGTL(("sensors:name", "Remove sensor entry (%s)\n",
                                     stale[i]->name));
        CONTAINER_REMOVE( _sensor_container, stale[i] );
        free( stale[i]->idx.oids );
        free( stale[i] );
    }
    free( stale );
}

/*
 * Architecture-independent release of sensor statistics
 */
static void
_sensor_free( void )
{
    netsnmp_sensor_info *sp;

    for (sp = CONTAINER_FIRST( _sensor_container );
         sp;
         sp = CONTAINER_NEXT(  _sensor_container, sp )) {

         sp->flags &= ~ NETSNMP_SENSOR_FLAG_ACTIVE;
    }
}


/*
 * Retrieve a sensor entry by name,
 *  or (optionally) insert a new one into the container
 */
netsnmp_sensor_info *
sensor_by_name( const char *name, int create_type )
{
    netsnmp_sensor_info *sp;
    netsnmp_sensor_info  key;
    int                  idx;

    DEBUGMSGTL(("sensors:name", "Get sensor entry (%s)\n", name));

    if (strlen(name) >= sizeof(key.name)) {
        if ( create_type != NETSNMP_SENSOR_FIND_EXIST )
            snmp_log(LOG_ERR, "Sensor name is too large: %s\n", name);
        return NULL;
    }

    /*
     *  Look for a matching entry
     */
    strlcpy(key.name, name, sizeof(key.name));
    sp = CONTAINER_FIND( _sensor_name_container, &key );
    if ( sp )
        return sp;

    /*
     * Not found...
     */
    if ( create_type == NETSNMP_SENSOR_FIND_EXIST ) {
        DEBUGMSGTL(("sensors:name", "No such sensor entry\n"));
        return NULL;
    }

    /*
     * ... so let's create a new one, using the type supplied
     */
    idx = _sensor_index_for( name );
    if ( idx <= 0 )
        return NULL;
    sp = SNMP_MALLOC_TYPEDEF( netsnmp_sensor_info );
    if ( !sp )
        return NULL;
    strlcpy(sp->name, name, sizeof(sp->name));
    sp->type = create_type;
    /*
     * Set up the index value.
     *
     * All this trouble, just for a simple integer.
     * Surely there must be a better way?
     */
    sp->idx.len  = 1;
    sp->idx.oids = SNMP_MALLOC_TYPEDEF( oid );
    if ( !sp->idx.oids ) {
        free( sp );
        return NULL;
    }
    sp->idx.oids[0] = idx;

    DEBUGMSGTL(("sensors:name", "Create sensor entry (type = %d, index = %d\n",
                                 create_type, idx));
    if ( CONTAINER_INSERT( _sensor_container, sp )) {
        free( sp->idx.oids );
        free( sp );
        return NULL;
    }
    return sp;
}


/*
 * Add a name to index mapping
 */
static int
_sensor_index_add( const char *name, int idx )
{
    struct sensor_index_entry *ip;

    ip = SNMP_MALLOC_TYPEDEF( struct sensor_index_entry );
    if ( !ip )
        return -1;
    ip->name = strdup( name );
    ip->idx  = idx;
    if ( !ip->name || CONTAINER_INSERT( _sensor_index_map, ip )) {
        free( ip->name );
        free( ip );
        return -1;
    }
    if ( idx > _sensor_idx )
        _sensor_idx = idx;
    return 0;
}

/*
 * Return the index for the named sensor,
 *  allocating (and saving) a new one if necessary
 */
static int
_sensor_index_for( const char *name )
{
    struct sensor_index_entry  key, *ip;

    key.name = NETSNMP_REMOVE_CONST(char *, name);
    ip = CONTAINER_FIND( _sensor_index_map, &key );
    if ( ip )
        return ip->idx;

    if ( _sensor_idx >= 65535 ) {
        snmp_log(LOG_ERR, "No sensor index available for %s\n", name);
        return -1;
    }
    if ( _sensor_index_add( name, _sensor_idx + 1 ) < 0 )
        return -1;
    snmp_store_needed( NULL );
    return _sensor_idx;
}

/*
 * Read a saved name to index mapping:
 *    sensorIndex <index> <name>
 */
static void
_sensor_parse_index( const char *token, char *line )
{
    struct sensor_index_entry  key, *ip;
    char         name[sizeof(((netsnmp_sensor_info *)0)->name)];
    char        *np  = name;
    size_t       len = sizeof(name);
    unsigned int idx = 0;

    line = read_config_read_data( ASN_UNSIGNED,  line, &idx, NULL );
    line = read_config_read_data( ASN_OCTET_STR, line, &np,  &len );
    if ( idx < 1 || idx > 65535 || len == 0 ) {
        config_perror("invalid sensorIndex entry");
        return;
    }

    key.name = name;
    if ( CONTAINER_FIND( _sensor_index_map, &key )) {
        config_perror("duplicate sensorIndex name");
        return;
    }
    for (ip = CONTAINER_FIRST( _sensor_index_map );
         ip;
         ip = CONTAINER_NEXT(  _sensor_index_map, ip )) {
        if ( ip->idx == (int)idx ) {
            config_perror("duplicate sensorIndex index");
            return;
        }
    }
    DEBUGMSGTL(("sensors:name", "Saved index %u for %s\n", idx, name));
    _sensor_index_add( name, idx );
}

/*
 * Save the name to index mappings into persistent storage
 */
static int
_sensor_store_index( int majorID, int minorID,
                     void *serverarg, void *clientarg )
{
    struct sensor_index_entry *ip;
    char         line[SNMP_MAXBUF];
    char        *cptr;
    size_t       tint;
    unsigned int idx;

    for (ip = CONTAINER_FIRST( _sensor_index_map );
         ip;
         ip = CONTAINER_NEXT(  _sensor_index_map, ip )) {

        strlcpy(line, "sensorIndex ", sizeof(line));
        cptr = line + strlen(line);
        idx  = ip->idx;
        cptr = read_config_store_data( ASN_UNSIGNED,  cptr, &idx, NULL );
        tint = strlen( ip->name );
        cptr = read_config_store_data( ASN_OCTET_STR, cptr, &ip->name, &tint );
        snmpd_store_config( line );
    }
    return SNMPERR_SUCCESS;
}

