/*
 * table_mfd.h
 * $Id$
 */
#ifndef _TABLE_MFD_HANDLER_H_
#define _TABLE_MFD_HANDLER_H_

#include <net-snmp/agent/table_array.h>

#ifdef __cplusplus
extern          "C" {
#endif

#define TABLE_MFD_NAME "table_mfd"

    /*
     * forward declares
     */
    struct netsnmp_mfd_registration_s;
    typedef struct netsnmp_mfd_registration_s netsnmp_mfd_registration;
    struct netsnmp_request_group;

    /* Legend: (test) [optional] <required>
     *
     * OLD              NEW
     * ========  ============================================
     * +++           [pre_request]
     *                    |
     *               (row exists?) N ->(row_creation) N >-->+
     *                    |                   | Y           |
     *                    |<------------------+             |
     *                   \|/                                |
     * RESERVE1  <object_syntax_checks>                     |
     *                    |                                \|/
     *                  (err?)  Y >------------------------>+
     *                    |                                 |
     *                   \|/                               \|/
     * +++          (row existed?) N ->[row_creation] ERR ->+
     *                    |                   | OK          |
     *                    |<------------------+             |
     *                   \|/                                |
     * RESERVER2     [undo_setup]                           |
     *                    |                                 |
     *                  (err?)  Y --->------------------>+  |
     *                    |                              |  |
     * ACTION        <set_values>                        |  |
     *                    |                              |  |
     *                  (err?)  Y >---------+            |  |
     *                    |                 |            |  |
     * +++        [consistency_checks]      |            |  |
     *                    |                \|/           |  |
     * UNDO             (err?)  Y >-------[undo]-------->+  |
     *                    |                              |  |
     *            [reversible_commit]                    |  |
     * +++                |                              | \|/
     *                  (err?)  Y >--[reverse_commit]    |  |
     *                    |              |               |  |
     * COMMIT        <final_commit>      |               |  |
     *                    |              |               |  |
     *                  (err?)  Y >--[log msg]           |  |
     *                    |              |               |  |
     *                    |             \|/             \|/ |
     *                    | <-----------<+---<-----------+  |
     *                   \|/                                |
     * FREE          [undo_cleanup]                         |
     *                    |                                \|/
     *                    |<--------------<-----------------+
     *                   \|/
     *               [post_request]
     */

    /*
     * typedef
     */
    typedef int (Netsnmp_MFD_Organize_Op)(netsnmp_mfd_registration *reg,
                                          u_long id);
    typedef int (Netsnmp_MFD_Request_Op)(netsnmp_mfd_registration *reg,
                                         netsnmp_request_group *rg);

    /*
     * structures 
     */
    typedef struct netsnmp_mfd_callbacks_set_min_s {
       Netsnmp_MFD_Request_Op *     data_lookup;
       Netsnmp_MFD_Request_Op *     get_values;
       Netsnmp_MFD_Request_Op *     object_syntax_checks;
       Netsnmp_MFD_Request_Op *     set_values;
       Netsnmp_MFD_Request_Op *     final_commit;
    } netsnmp_mfd_callbacks_set_min;

    typedef struct netsnmp_mfd_callbacks_set_extra_s {
       Netsnmp_MFD_Organize_Op *    pre_request;
       Netsnmp_MFD_Request_Op *     row_creation;
       Netsnmp_MFD_Request_Op *     undo_setup;
       Netsnmp_MFD_Request_Op *     undo_sets;
       Netsnmp_MFD_Request_Op *     undo_cleanup;
       Netsnmp_MFD_Request_Op *     consistency_checks;
       Netsnmp_MFD_Request_Op *     undoable_commit;
       Netsnmp_MFD_Request_Op *     undo_commit;
       Netsnmp_MFD_Organize_Op *    post_request;
    } netsnmp_mfd_callbacks_set_extra;

    struct netsnmp_mfd_registration_s {

       netsnmp_table_registration_info *table_info;
       netsnmp_container               *container;

       u_long mfd_flags;

       netsnmp_mfd_callbacks_set_min   cbsm;
       netsnmp_mfd_callbacks_set_extra cbse;

       void * mfd_user_ctx;

    };

    int netsnmp_mfd_register_table( netsnmp_handler_registration *reginfo,
                                    netsnmp_table_registration_info *tabreg,
                                    netsnmp_container *container,
                                    netsnmp_mfd_registration *mfdr);

#define MFD_GROUP_GET                        0x01
#define MFD_DONT_GROUP_SET                   0x02

#if 0
    /*
     * mfd request group
     */
    typedef struct netsnmp_mfd_request_group_s {
       /*
        */
       netsnmp_request_group rg;

    } netsnmp_mfd_request_group;
#endif /* 0 */


#ifdef __cplusplus
};
#endif

#endif                          /* _TABLE_MFD_HANDLER_H_ */
