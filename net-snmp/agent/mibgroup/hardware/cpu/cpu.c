#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/hardware/cpu.h>

extern NetsnmpCacheLoad netsnmp_cpu_arch_load;

netsnmp_cpu_info *_cpu_head  = NULL;
netsnmp_cpu_info *_cpu_tail  = NULL;
netsnmp_cache    *_cpu_cache = NULL;

void init_cpu( void ) {
    _cpu_cache = netsnmp_cache_create( 5, netsnmp_cpu_arch_load, NULL, NULL, 0);
}



netsnmp_cpu_info *netsnmp_cpu_get_first( void ) {
    return _cpu_head;
}
netsnmp_cpu_info *netsnmp_cpu_get_next( netsnmp_cpu_info *this ) {
    return ( this ? this->next : NULL );
}

    /*
     * Work with a list of CPU entries, indexed numerically
     */
netsnmp_cpu_info *netsnmp_cpu_get_byIdx(  int idx, int create ) {
    netsnmp_cpu_info *cpu, *cpu2;

        /*
         * Find the specified CPU entry
         */
    for ( cpu=_cpu_head; cpu; cpu=cpu->next ) {
        if ( cpu->idx == idx )
            return cpu;
    }
    if (!create)
        return NULL;

        /*
         * Create a new CPU entry, and insert it into the list....
         */
    cpu = SNMP_MALLOC_TYPEDEF( netsnmp_cpu_info );
    if (!cpu)
        return NULL;
    cpu->idx = idx;
        /* ... either as the first (or only) entry....  */
    if ( !_cpu_head || _cpu_head->idx > idx ) {
        cpu->next = _cpu_head;
        _cpu_head = cpu;
        if (!_cpu_tail)
            _cpu_tail = cpu;
        return cpu;
    }
        /* ... or in the appropriate position  */
    for ( cpu2=_cpu_head; cpu2; cpu2=cpu2->next ) {
        if ( !cpu2->next || cpu2->next->idx > idx ) {
            cpu->next  = cpu2->next;
            cpu2->next = cpu;
            if (!cpu->next)
                _cpu_tail = cpu;
            return cpu;
        }
    }
    return NULL;  /* Shouldn't happen! */
}

    /*
     * Work with a list of CPU entries, indexed by name
     */
netsnmp_cpu_info *netsnmp_cpu_get_byName( char *name, int create ) {
    netsnmp_cpu_info *cpu;

        /*
         * Find the specified CPU entry
         */
    for ( cpu=_cpu_head; cpu; cpu=cpu->next ) {
        if ( !strcmp(cpu->name, name))
            return cpu;
    }
    if (!create)
        return NULL;

        /*
         * Create a new CPU entry, and append it to the list
         */
    cpu = SNMP_MALLOC_TYPEDEF( netsnmp_cpu_info );
    if (!cpu)
        return NULL;
    strcpy(cpu->name, name);
    if ( _cpu_tail ) {
        cpu->idx = _cpu_tail->idx+1;
        _cpu_tail->next = cpu;
        _cpu_tail       = cpu;
    } else {
        cpu->idx = 0;
        _cpu_head = cpu;
        _cpu_tail = cpu;
    }
    return cpu;
}

netsnmp_cache *netsnmp_cpu_get_cache( void ) {
    return _cpu_cache;
}

int netsnmp_cpu_load( void ) {
     return netsnmp_cache_check_and_reload( _cpu_cache );
}
