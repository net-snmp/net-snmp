#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/library/container.h>

void
netsnmp_init_container(netsnmp_container         *c,
                       netsnmp_container_rc      *init,
                       netsnmp_container_rc      *free,
                       netsnmp_container_size    *size,
                       netsnmp_container_compare *cmp,
                       netsnmp_container_op      *ins,
                       netsnmp_container_op      *rem,
                       netsnmp_container_rtn     *fnd)
{
    if (c == NULL)
        return;

    c->init = init;
    c->free = free;
    c->get_size = size;
    c->compare = cmp;
    c->insert_data = ins;
    c->remove_data = rem;
    c->find_data = fnd;
}

void
netsnmp_init_sorted_container(netsnmp_sorted_container  *sc,
                              netsnmp_container_rtn     *first,
                              netsnmp_container_rtn     *next,
                              netsnmp_container_set     *subset)
{
    if (sc == NULL)
        return;

    sc->first = first;
    sc->next = next;
    sc->subset = subset;
}
