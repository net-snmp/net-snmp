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
     *                 [commit]                          |  |
     * +++                |                              | \|/
     *                  (err?)  Y >--[undo_commit]       |  |
     *                    |              |               |  |
     * COMMIT   <irreversible_commit>    |               |  |
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

    /*******************************************************************
     * typedef
     */
    struct mfd_pdu_context_s; /** fwd decl */
    typedef int (Netsnmp_MFD_Organize_Op)(struct mfd_pdu_context_s *reg,
                                          netsnmp_data_list *list,
                                          u_long id);
    typedef int (Netsnmp_MFD_Request_Op)(struct mfd_pdu_context_s  *reg,
                                         netsnmp_request_info *requests,
                                         void *requests_parent);

    /*******************************************************************
     * structures 
     */

    /**
     * data structure for lower handler use
     */
    typedef struct mfd_pdu_context_s {

       /*
        * pointer to registration
        */
       void *                        *mfd_user_ctx;

       /*
        * request mode
        */
       int                            next_mode_ok;
       int                            request_mode;

       /*
        * data pointer for this request (row or object)
        */
       void                          *mfd_data;

       /*
        * storage for future expansion
        */
       netsnmp_data_list             *mfd_data_list;

    } mfd_pdu_context;

    /**
     * @internal
     * Mibs For Dummies registration structure
     */
    typedef struct netsnmp_mfd_registration_s {

       netsnmp_table_registration_info *table_info;
       netsnmp_container               *container;

       u_long                           mfd_flags;

       /*
        * pointer supplied by the user during registration.
        */
       void                           *mfd_user_ctx;

       /*
        * INTERNAL callbacks
        */
       Netsnmp_MFD_Organize_Op *    pre_request;
       Netsnmp_MFD_Request_Op *     object_lookup;
       Netsnmp_MFD_Request_Op *     get_values;
       Netsnmp_MFD_Request_Op *     object_syntax_checks;
       Netsnmp_MFD_Request_Op *     row_creation;
       Netsnmp_MFD_Request_Op *     undo_setup;
       Netsnmp_MFD_Request_Op *     set_values;
       Netsnmp_MFD_Request_Op *     consistency_checks;
       Netsnmp_MFD_Request_Op *     commit;
       Netsnmp_MFD_Request_Op *     undo_sets;
       Netsnmp_MFD_Request_Op *     undo_cleanup;
       Netsnmp_MFD_Request_Op *     undo_commit;
       Netsnmp_MFD_Request_Op *     irreversible_commit;
       Netsnmp_MFD_Organize_Op *    post_request;

       /*
        * extra data storage, just in case
        */
       netsnmp_data_list             *mfd_reg_data;

    } netsnmp_mfd_registration;

    /*******************************************************************
     * registration routine
     */
    int netsnmp_mfd_register_table(netsnmp_mfd_registration *mfdr,
                                   const char *name,
                                   Netsnmp_Node_Handler * handler,
                                   oid * reg_oid, size_t reg_oid_len,
                                   int modes);

#define MFD_SUCCESS              SNMP_ERR_NOERROR
#define MFD_SKIP                 SNMP_NOSUCHINSTANCE
#define MFD_ERROR                SNMP_ERR_GENERR
#define MFD_RESOURCE_UNAVAILABLE SNMP_ERR_RESOURCEUNAVAILABLE
#define MFD_INCONSISTENT_VALUE   SNMP_ERR_INCONSISTENTVALUE
#define MFD_BAD_VALUE            SNMP_ERR_BADVALUE
#define MFD_END_OF_DATA          SNMP_ENDOFMIBVIEW

#ifdef __cplusplus
};
#endif

#endif                          /* _TABLE_MFD_HANDLER_H_ */
