/*
 *  Interface MIB architecture support
 *
 * $Id$
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/data_access/ipstats.h>
#include <net-snmp/data_access/systemstats.h>

void
netsnmp_access_systemstats_arch_init(void)
{
    /*
     * nothing to do
     */
}

/*
  /proc/net/snmp

  Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates
  Ip: 2 64 7083534 0 0 0 0 0 6860233 6548963 0 0 1 286623 63322 1 259920 0 0
  
  Icmp: InMsgs InErrors InDestUnreachs InTimeExcds InParmProbs InSrcQuenchs InRedirects InEchos InEchoReps InTimestamps InTimestampReps InAddrMasks InAddrMaskReps OutMsgs OutErrors OutDestUnreachs OutTimeExcds OutParmProbs OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps OutTimestampReps OutAddrMasks OutAddrMaskReps
  Icmp: 335 36 254 72 0 0 0 0 9 0 0 0 0 257 0 257 0 0 0 0 0 0 0 0 0 0
  
  Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts
  Tcp: 1 200 120000 -1 5985 55 27 434 10 5365077 5098096 10902 2 4413
  
  Udp: InDatagrams NoPorts InErrors OutDatagrams
  Udp: 1491094 122 0 1466178
*/


/*
 *
 * @retval  0 success
 * @retval -1 no container specified
 * @retval -2 could not open /proc/net/dev
 * @retval -3 could not create entry (probably malloc)
 * @retval -4 file format error
 */
int
netsnmp_access_systemstats_container_arch_load(netsnmp_container* container,
                                             u_int load_flags)
{
    FILE           *devin;
    char            line[1024];
    netsnmp_systemstats_entry *entry = NULL;
    int             scan_count;
    char           *stats, *start = line;
    int             len;
    uintmax_t       scan_vals[26];

    DEBUGMSGTL(("access:systemstats:container:arch", "load (flags %p)\n",
                load_flags));

    if (NULL == container) {
        snmp_log(LOG_ERR, "no container specified/found for access_systemstats_\n");
        return -1;
    }

    if (!(devin = fopen("/proc/net/snmp", "r"))) {
        DEBUGMSGTL(("access:systemstats",
                    "Failed to load Systemstats Table (linux1)\n"));
        snmp_log(LOG_ERR, "cannot open /proc/net/snmp ...\n");
        return -2;
    }

    /*
     * skip header. make sure it's then length we expect...
     */
    fgets(line, sizeof(line), devin);
    len = strlen(line);
    snmp_log(LOG_ERR, "first line = %d\n", strlen(line));

    /*
     * This file provides the statistics for each systemstats.
     * Read in each line in turn, isolate the systemstats name
     *   and retrieve (or create) the corresponding data structure.
     */
    start = fgets(line, sizeof(line), devin);
    fclose(devin);
    if (start) {

        len = strlen(line);
        if (line[len - 1] == '\n')
            line[len - 1] = '\0';

        while (*start && *start == ' ')
            start++;

        if ((!*start) || ((stats = strrchr(start, ':')) == NULL)) {
            snmp_log(LOG_ERR,
                     "systemstats data format error 1, line ==|%s|\n", line);
            return -4;
        }

        DEBUGMSGTL(("access:systemstats", "processing '%s'\n", start));

        *stats++ = 0; /* null terminate name */
        while (*stats == ' ') /* skip spaces before stats */
            stats++;

        entry = netsnmp_access_systemstats_entry_create(4);
        if(NULL == entry) {
            netsnmp_access_systemstats_container_free(container,
                                                      NETSNMP_ACCESS_SYSTEMSTATS_FREE_NOFLAGS);
            return -3;
        }

        /*
         * OK - we've now got (or created) the data structure for
         *      this systemstats, including any "static" information.
         * Now parse the rest of the line (i.e. starting from 'stats')
         *      to extract the relevant statistics, and populate
         *      data structure accordingly.
         */

        memset(scan_vals, 0x0, sizeof(scan_vals));
        scan_count = sscanf(stats,
                            "%llu %llu %llu %llu %llu %llu %llu %llu %llu %llu"
                            "%llu %llu %llu %llu %llu %llu %llu %llu %llu",
                            &scan_vals[0],&scan_vals[1],&scan_vals[2],
                            &scan_vals[3],&scan_vals[4],&scan_vals[5],
                            &scan_vals[6],&scan_vals[7],&scan_vals[8],
                            &scan_vals[9],&scan_vals[10],&scan_vals[11],
                            &scan_vals[12],&scan_vals[13],&scan_vals[14],
                            &scan_vals[15],&scan_vals[16],&scan_vals[17],
                            &scan_vals[18]);
        DEBUGMSGTL(("access:systemstats", "  read %d values\n", scan_count));

        if(scan_count != 19) {
            snmp_log(LOG_ERR,
                     "error scanning systemstats data (expected %d, got %d)\n",
                     19, scan_count);
            netsnmp_access_systemstats_entry_free(entry);
            return -4;
        }
        /* entry->stats. = scan_vals[0]; /* Forwarding */
        /* entry->stats. = scan_vals[1]; /* DefaultTTL */
        entry->stats.HCInReceives.low = scan_vals[2] & 0xffffffff;
        entry->stats.HCInReceives.high = scan_vals[2] >> 32;
        entry->stats.InHdrErrors = scan_vals[3];
        entry->stats.InAddrErrors = scan_vals[4];
        entry->stats.HCInForwDatagrams.low = scan_vals[5] & 0xffffffff;
        entry->stats.HCInForwDatagrams.high = scan_vals[5] >> 32;
        entry->stats.InUnknownProtos = scan_vals[6];
        entry->stats.InDiscards = scan_vals[7];
        entry->stats.HCInDelivers.low = scan_vals[8] & 0xffffffff;
        entry->stats.HCInDelivers.high = scan_vals[8] >> 32;
        entry->stats.HCOutRequests.low = scan_vals[9] & 0xffffffff;
        entry->stats.HCOutRequests.high = scan_vals[9] >> 32;
        entry->stats.OutDiscards = scan_vals[10];
        entry->stats.OutNoRoutes = scan_vals[11];
        /* entry->stats. = scan_vals[12]; /* ReasmTimeout */
        entry->stats.ReasmReqds = scan_vals[13];
        entry->stats.ReasmOKs = scan_vals[14];
        entry->stats.ReasmFails = scan_vals[15];
        entry->stats.OutFragOKs = scan_vals[16];
        entry->stats.OutFragFails = scan_vals[17];
        entry->stats.OutFragCreates = scan_vals[18];
#if 0
        entry->stats.ibytes.low = rec_oct & 0xffffffff;
        entry->stats.ibytes.high = rec_oct >> 32;
#endif
        /*
         * calculated stats.
         */

        /*
         * add to container
         */
        CONTAINER_INSERT(container, entry);
    }
    return 0;
}
