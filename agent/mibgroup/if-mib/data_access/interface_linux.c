/*
 *  Interface MIB architecture support
 *
 * $Id$
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include "mibII/mibII_common.h"

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/data_access/interface.h>

/*
 *
 * @retval  0 success
 * @retval -1 no container specified
 * @retval -2 could not open /proc/net/dev
 * @retval -3 could not create entry (probably malloc)
 */
int
netsnmp_access_interface_container_arch_load(netsnmp_container* container,
                                             u_int load_flags)
{
    FILE           *devin;
    char            line[256];
    const char     *scan_line_2_2 =
        "%llu %llu %llu %llu %*llu %*llu %*llu %*llu %llu %llu %llu %llu %*llu %llu";
    const char     *scan_line_2_0 =
        "%llu %llu %*llu %*llu %*llu %llu %llu %*llu %*llu %llu";
    static const char     *scan_line_to_use = NULL;
    static char     scan_expected;
    int             scan_count;
    unsigned long long rec_pkt, rec_oct, rec_err, rec_drop;
    unsigned long long snd_pkt, snd_oct, snd_err, snd_drop, coll;
    netsnmp_interface_entry *entry = NULL;

    DEBUGMSGTL(("access:interface", "ifcontainer_arch_load (flags %p)\n",
                load_flags));

    if (NULL == container) {
        snmp_log(LOG_ERR, "no container specified/found for access_interface_\n");
        return -1;
    }

    if (!(devin = fopen("/proc/net/dev", "r"))) {
        DEBUGMSGTL(("access:interface",
                    "Failed to load Interface Table (linux1)\n"));
        snmp_log(LOG_ERR, "snmpd: cannot open /proc/net/dev ...\n");
        return -2;
    }

    /*
     * Read the first two lines of the file, containing the header
     * This indicates which version of the kernel we're working with,
     * and hence which statistics are actually available.
     *
     * Wes originally suggested parsing the field names in this header
     * to detect the position of individual fields directly,
     * but I suspect this is probably more trouble than it's worth.
     */
    fgets(line, sizeof(line), devin);
    fgets(line, sizeof(line), devin);
    /*
     * XXX - What's the format for the 2.6 kernel ?
     */
    if( NULL == scan_line_to_use ) {
        if (strstr(line, "compressed")) {
            scan_line_to_use = scan_line_2_2;
            scan_expected = 9;
            DEBUGMSGTL(("access:interface",
                        "using linux 2.2 kernel /proc/net/dev\n"));
        } else {
            scan_line_to_use = scan_line_2_0;
            scan_expected = 5;
            DEBUGMSGTL(("access:interface",
                        "using linux 2.0 kernel /proc/net/dev\n"));
        }
    }

    /*
     * The rest of the file provides the statistics for each interface.
     * Read in each line in turn, isolate the interface name
     *   and retrieve (or create) the corresponding data structure.
     */
    while (fgets(line, sizeof(line), devin)) {
        char           *stats, *ifstart = line;

        if (line[strlen(line) - 1] == '\n')
            line[strlen(line) - 1] = '\0';

        while (*ifstart && *ifstart == ' ')
            ifstart++;

        if ((!*ifstart) || ((stats = strrchr(ifstart, ':')) == NULL)) {
            snmp_log(LOG_ERR,
                     "interface data format error 1, line ==|%s|\n", line);
            continue;
        }
        if ((scan_line_to_use == scan_line_2_2) && ((stats - line) < 6)) {
            snmp_log(LOG_ERR,
                     "interface data format error 2 (%d < 6), line ==|%s|\n",
                     line, stats - line);
        }

        DEBUGMSGTL(("9:access:ifcontainer", "processing '%s'\n", ifstart));

        /*
         * If we've met this interface before, use the same index.
         * Otherwise find an unused index value and use that.
         */
        *stats++ = 0; /* null terminate name */
        entry = netsnmp_access_interface_entry_create(ifstart);
        if(NULL == entry) {
            netsnmp_access_interface_container_free(container,
                                                    NETSNMP_ACCESS_INTERFACE_FREE_NOFLAGS);
            fclose(devin);
            return -3;
        }
        entry->if_speed = 10000000; // xxx-rks: lookup token?
        entry->if_type = 6;


        /*
         * OK - we've now got (or created) the data structure for
         *      this interface, including any "static" information.
         * Now parse the rest of the line (i.e. starting from 'stats')
         *      to extract the relevant statistics, and populate
         *      data structure accordingly.
         * Use the ifentry flags field to indicate which counters are valid
         */
        while (*stats == ' ')
            stats++;

        rec_pkt = rec_oct = rec_err = rec_drop = 0;
        snd_pkt = snd_oct = snd_err = snd_drop = coll = 0;
        if (scan_line_to_use == scan_line_2_2) {
            scan_count = sscanf(stats, scan_line_to_use,
                                &rec_oct, &rec_pkt, &rec_err, &rec_drop,
                                &snd_oct, &snd_pkt, &snd_err, &snd_drop,
                                &coll);
            if (scan_count == scan_expected) {
                entry->flags |= NETSNMP_INTERFACE_FLAGS_HAS_BYTES;
                entry->flags |= NETSNMP_INTERFACE_FLAGS_HAS_DROPS;
                /*
                 *  2.4 kernel includes a single multicast (input) counter?
                 */
                entry->flags |= NETSNMP_INTERFACE_FLAGS_HAS_MCAST_PKTS;
                entry->flags |= NETSNMP_INTERFACE_FLAGS_HAS_HIGH_SPEED;
                entry->flags |= NETSNMP_INTERFACE_FLAGS_HAS_HIGH_BYTES;
                entry->flags |= NETSNMP_INTERFACE_FLAGS_HAS_HIGH_PACKETS;
            }
        } else {
            scan_count = sscanf(stats, scan_line_to_use,
                                &rec_pkt, &rec_err,
                                &snd_pkt, &snd_err, &coll);
            if (scan_count == scan_expected) {
                entry->flags &= ~NETSNMP_INTERFACE_FLAGS_HAS_MCAST_PKTS;
                rec_oct = rec_drop = 0;
                snd_oct = snd_drop = 0;
            }
        }
        if(scan_count != scan_expected) {
            snmp_log(LOG_ERR,
                     "error scanning interface data (expected %d, got %d)\n",
                     scan_expected, scan_count);
            netsnmp_access_interface_entry_free(entry);
            continue;
        }
        entry->flags |= NETSNMP_INTERFACE_FLAGS_ACTIVE;

        /*
         * linux previous to 1.3.~13 may miss transmitted loopback pkts: 
         */
        if (!strcmp(entry->if_name, "lo") && rec_pkt > 0 && !snd_pkt)
            snd_pkt = rec_pkt;

        /*
         * //xxx-rks: get descr by linking mem from /proc/pci and /proc/iomem
         */


        entry->if_ibytes.low = rec_oct & 0xffffffff;
        entry->if_ibytes.high = rec_oct >> 32;
        entry->if_iucast.low = rec_pkt & 0xffffffff;
        entry->if_iucast.high = rec_pkt >> 32;
        entry->if_ierrors = rec_err;
        entry->if_idiscards = rec_drop;
        entry->if_obytes.low = snd_oct & 0xffffffff;
        entry->if_obytes.high = snd_oct >> 32;
        entry->if_oucast.low = snd_pkt & 0xffffffff;
        entry->if_oucast.high = snd_pkt >> 32;
        entry->if_oerrors = snd_err;
        entry->if_odiscards = snd_drop;
        entry->if_collisions = coll;
        
        /*
         * add to container
         */
        CONTAINER_INSERT(container, entry);
    }
    fclose(devin);
    return 0;
}
