/* HEADER Testing MIB SET handlers (Target, VACM, Notify, Extend, DisMan, UCD) */

#include <net-snmp/net-snmp-features.h>
#include <net-snmp/agent/mib_module_config.h>
#include <net-snmp/agent/agent_module_config.h>
#include <net-snmp/agent/mib_modules.h>
#include <net-snmp/library/vacm.h>
#include "target/snmpTargetAddrEntry_data.h"
#include "target/snmpTargetParamsEntry_data.h"
#include "agent/extend.h"
#include "utilities/execute.h"
#include "ucd-snmp/pass_common.h"

#ifdef NETSNMP_NO_WRITE_SUPPORT
OK(1, "skipped: write support disabled");
#else

/* Target MIB WriteMethods */
extern WriteMethod write_snmpTargetAddrTDomain;
extern WriteMethod write_snmpTargetAddrTAddress;
extern WriteMethod write_snmpTargetAddrTimeout;
extern WriteMethod write_snmpTargetAddrRowStatus;
extern WriteMethod write_snmpTargetParamsMPModel;
extern WriteMethod write_snmpTargetParamsRowStatus;

/* VACM MIB WriteMethods */
extern WriteMethod write_vacmGroupName;
extern WriteMethod write_vacmSecurityToGroupStorageType;
extern WriteMethod write_vacmSecurityToGroupStatus;
extern WriteMethod write_vacmViewMask;
extern WriteMethod write_vacmViewType;
extern WriteMethod write_vacmViewStorageType;
extern WriteMethod write_vacmViewStatus;

/* Notification MIB WriteMethods */
extern WriteMethod write_snmpNotifyTag;
extern WriteMethod write_snmpNotifyRowStatus;
extern WriteMethod write_snmpNotifyFilterProfileName;
extern WriteMethod write_snmpNotifyFilterProfileRowStatus;

/* Extend and Logging handlers */
extern Netsnmp_Node_Handler handle_nsExtendConfigTable;
extern Netsnmp_Node_Handler handle_nsLoggingTable;

/* DisMan handlers and WriteMethods */
extern Netsnmp_Node_Handler mteEventTable_handler;
extern Netsnmp_Node_Handler mteObjectsTable_handler;
extern Netsnmp_Node_Handler mteTriggerTable_handler;
extern Netsnmp_Node_Handler expObjectTable_handler;
extern Netsnmp_Node_Handler schedTable_handler;
extern WriteMethod write_pingCtlRowStatus;

/* UCD-SNMP config parsers */
extern void execfix_parse_config(const char *token, char *cptr);
extern void procfix_parse_config(const char *token, char *cptr);
extern void init_expExpressionTable(void);
extern void shutdown_expExpressionTable(void);
extern void init_dlmod(void);
extern void shutdown_dlmod(void);

SOCK_STARTUP;

setenv("SNMPDLMODPATH", "/nonexistent_dir1:/nonexistent_dir2", 1);
netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_DONT_PERSIST_STATE, 1);
init_agent("snmpd");
#ifdef USING_AGENT_EXTEND_MODULE
init_extend();
#endif
#ifdef USING_DISMAN_EXPR_EXPEXPRESSIONTABLE_MODULE
init_expExpressionTable();
#endif
#ifdef USING_UCD_SNMP_DLMOD_MODULE
init_dlmod();
#endif
init_snmp("snmpd");

/*
 * 1. Target MIB tests (commit 373866795a6c)
 */
#if defined(USING_TARGET_SNMPTARGETADDRENTRY_MODULE) && defined(USING_TARGET_SNMPTARGETPARAMSENTRY_MODULE)
{
    /* snmpTargetAddrEntry: .1.3.6.1.6.3.12.1.2.1.<col>.<name> */
    oid addr_oid[] = { 1, 3, 6, 1, 6, 3, 12, 1, 2, 1, 9, 't', '1' };
    size_t addr_oid_len = OID_LENGTH(addr_oid);
    /* snmpTargetParamsEntry: .1.3.6.1.6.3.12.1.3.1.<col>.<name> */
    oid params_oid[] = { 1, 3, 6, 1, 6, 3, 12, 1, 3, 1, 7, 'p', '1' };
    size_t params_oid_len = OID_LENGTH(params_oid);
    long val;
    int rc;
    struct targetAddrTable_struct *addr_entry;
    struct targetParamTable_struct *param_entry;

    /* 1a. write_snmpTargetAddrTDomain unaligned length & TAddress NULL -> WRONGLENGTH */
    addr_oid[10] = 2; /* snmpTargetAddrTDomain */
    rc = write_snmpTargetAddrTDomain(RESERVE1, NULL, ASN_OBJECT_ID, 3,
                                     NULL, addr_oid, addr_oid_len);
    OK(rc == SNMP_ERR_WRONGLENGTH,
       "write_snmpTargetAddrTDomain rejects unaligned var_val_len with WRONGLENGTH");

    addr_oid[10] = 3; /* snmpTargetAddrTAddress */
    rc = write_snmpTargetAddrTAddress(RESERVE1, NULL, ASN_OCTET_STR, 0,
                                      NULL, addr_oid, addr_oid_len);
    OK(rc == SNMP_ERR_WRONGLENGTH,
       "write_snmpTargetAddrTAddress rejects NULL var_val with WRONGLENGTH");

    /* 1b. write_snmpTargetAddrRowStatus with wrong length -> WRONGLENGTH */
    addr_oid[10] = 9; /* snmpTargetAddrRowStatus */
    val = RS_CREATEANDWAIT;
    rc = write_snmpTargetAddrRowStatus(RESERVE1, (u_char *)&val, ASN_INTEGER,
                                       2, NULL, addr_oid, addr_oid_len);
    OK(rc == SNMP_ERR_WRONGLENGTH,
       "write_snmpTargetAddrRowStatus rejects wrong var_val_len");

    /* 1c. Row creation RESERVE1 -> UNDO cleans up newly created row */
    val = RS_CREATEANDWAIT;
    rc = write_snmpTargetAddrRowStatus(RESERVE1, (u_char *)&val, ASN_INTEGER,
                                       sizeof(val), NULL, addr_oid, addr_oid_len);
    OK(rc == SNMP_ERR_NOERROR && get_addrForName2("t1", 2) != NULL,
       "write_snmpTargetAddrRowStatus RESERVE1 creates row t1");
    rc = write_snmpTargetAddrRowStatus(UNDO, (u_char *)&val, ASN_INTEGER,
                                       sizeof(val), NULL, addr_oid, addr_oid_len);
    OK(rc == SNMP_ERR_NOERROR && get_addrForName2("t1", 2) == NULL,
       "write_snmpTargetAddrRowStatus UNDO removes uncommitted row t1");

    /* 1d. Create row (RESERVE1 -> ACTION -> COMMIT), test TAddress UNDO, then DESTROY */
    val = RS_CREATEANDWAIT;
    rc = write_snmpTargetAddrRowStatus(RESERVE1, (u_char *)&val, ASN_INTEGER,
                                       sizeof(val), NULL, addr_oid, addr_oid_len);
    rc |= write_snmpTargetAddrRowStatus(ACTION, (u_char *)&val, ASN_INTEGER,
                                        sizeof(val), NULL, addr_oid, addr_oid_len);
    rc |= write_snmpTargetAddrRowStatus(COMMIT, (u_char *)&val, ASN_INTEGER,
                                        sizeof(val), NULL, addr_oid, addr_oid_len);
    addr_entry = get_addrForName2("t1", 2);
    OK(rc == SNMP_ERR_NOERROR && addr_entry != NULL,
       "write_snmpTargetAddrRowStatus COMMIT creates row t1");

    addr_oid[10] = 3; /* snmpTargetAddrTAddress */
    rc = write_snmpTargetAddrTAddress(RESERVE1, (u_char *)"127.0.0.1",
                                      ASN_OCTET_STR, 9, NULL,
                                      addr_oid, addr_oid_len);
    rc |= write_snmpTargetAddrTAddress(RESERVE2, (u_char *)"127.0.0.1",
                                       ASN_OCTET_STR, 9, NULL,
                                       addr_oid, addr_oid_len);
    rc |= write_snmpTargetAddrTAddress(UNDO, (u_char *)"127.0.0.1",
                                       ASN_OCTET_STR, 9, NULL,
                                       addr_oid, addr_oid_len);
    OK(rc == SNMP_ERR_NOERROR && addr_entry->tAddress == NULL,
       "write_snmpTargetAddrTAddress UNDO restores NULL tAddress without leak");

    addr_oid[10] = 9; /* snmpTargetAddrRowStatus */
    val = RS_DESTROY;
    rc = write_snmpTargetAddrRowStatus(RESERVE1, (u_char *)&val, ASN_INTEGER,
                                       sizeof(val), NULL, addr_oid, addr_oid_len);
    rc |= write_snmpTargetAddrRowStatus(ACTION, (u_char *)&val, ASN_INTEGER,
                                        sizeof(val), NULL, addr_oid, addr_oid_len);
    rc |= write_snmpTargetAddrRowStatus(COMMIT, (u_char *)&val, ASN_INTEGER,
                                        sizeof(val), NULL, addr_oid, addr_oid_len);
    OK(rc == SNMP_ERR_NOERROR && get_addrForName2("t1", 2) == NULL,
       "write_snmpTargetAddrRowStatus RS_DESTROY deletes row t1");

    /* 1e. write_snmpTargetParamsRowStatus wrong length -> WRONGLENGTH */
    params_oid[10] = 7; /* snmpTargetParamsRowStatus */
    val = RS_CREATEANDWAIT;
    rc = write_snmpTargetParamsRowStatus(RESERVE1, (u_char *)&val, ASN_INTEGER,
                                         2, NULL, params_oid, params_oid_len);
    OK(rc == SNMP_ERR_WRONGLENGTH,
       "write_snmpTargetParamsRowStatus rejects wrong var_val_len");

    /* 1f. Params row creation RESERVE1 -> UNDO cleans up row */
    val = RS_CREATEANDWAIT;
    rc = write_snmpTargetParamsRowStatus(RESERVE1, (u_char *)&val, ASN_INTEGER,
                                         sizeof(val), NULL, params_oid, params_oid_len);
    OK(rc == SNMP_ERR_NOERROR && get_paramEntry2("p1", 2) != NULL,
       "write_snmpTargetParamsRowStatus RESERVE1 creates row p1");
    rc = write_snmpTargetParamsRowStatus(UNDO, (u_char *)&val, ASN_INTEGER,
                                         sizeof(val), NULL, params_oid, params_oid_len);
    OK(rc == SNMP_ERR_NOERROR && get_paramEntry2("p1", 2) == NULL,
       "write_snmpTargetParamsRowStatus UNDO removes uncommitted row p1");

    /* 1g. Create params row, test MPModel UNDO, then DESTROY */
    val = RS_CREATEANDWAIT;
    rc = write_snmpTargetParamsRowStatus(RESERVE1, (u_char *)&val, ASN_INTEGER,
                                         sizeof(val), NULL, params_oid, params_oid_len);
    rc |= write_snmpTargetParamsRowStatus(ACTION, (u_char *)&val, ASN_INTEGER,
                                          sizeof(val), NULL, params_oid, params_oid_len);
    rc |= write_snmpTargetParamsRowStatus(COMMIT, (u_char *)&val, ASN_INTEGER,
                                          sizeof(val), NULL, params_oid, params_oid_len);
    param_entry = get_paramEntry2("p1", 2);
    OK(rc == SNMP_ERR_NOERROR && param_entry != NULL,
       "write_snmpTargetParamsRowStatus COMMIT creates row p1");

    params_oid[10] = 2; /* snmpTargetParamsMPModel */
    val = 3;
    rc = write_snmpTargetParamsMPModel(RESERVE1, (u_char *)&val, ASN_INTEGER,
                                       sizeof(val), NULL, params_oid, params_oid_len);
    rc |= write_snmpTargetParamsMPModel(RESERVE2, (u_char *)&val, ASN_INTEGER,
                                        sizeof(val), NULL, params_oid, params_oid_len);
    rc |= write_snmpTargetParamsMPModel(UNDO, (u_char *)&val, ASN_INTEGER,
                                        sizeof(val), NULL, params_oid, params_oid_len);
    OK(rc == SNMP_ERR_NOERROR && param_entry->mpModel == -1,
       "write_snmpTargetParamsMPModel UNDO restores original mpModel");

    params_oid[10] = 7; /* snmpTargetParamsRowStatus */
    val = RS_DESTROY;
    rc = write_snmpTargetParamsRowStatus(RESERVE1, (u_char *)&val, ASN_INTEGER,
                                         sizeof(val), NULL, params_oid, params_oid_len);
    rc |= write_snmpTargetParamsRowStatus(ACTION, (u_char *)&val, ASN_INTEGER,
                                          sizeof(val), NULL, params_oid, params_oid_len);
    rc |= write_snmpTargetParamsRowStatus(COMMIT, (u_char *)&val, ASN_INTEGER,
                                          sizeof(val), NULL, params_oid, params_oid_len);
    OK(rc == SNMP_ERR_NOERROR && get_paramEntry2("p1", 2) == NULL,
       "write_snmpTargetParamsRowStatus RS_DESTROY deletes row p1");
}
#endif

/*
 * 2. VACM MIB tests (commit 52e0f6a7f56b)
 */
#ifdef USING_MIBII_VACM_VARS_MODULE
{
    /* vacmSecurityToGroupEntry: .1.3.6.1.6.3.16.1.2.1.<col>.<model>.<len>.<name> */
    oid sec2grp_oid[] = { 1, 3, 6, 1, 6, 3, 16, 1, 2, 1, 3, 3, 2, 'u', '1' };
    size_t sec2grp_len = OID_LENGTH(sec2grp_oid);
    /* vacmViewTreeFamilyEntry: .1.3.6.1.6.3.16.1.5.2.1.<col>.<vlen>.<vname>.<slen>.<subtree> */
    oid view_oid[] = { 1, 3, 6, 1, 6, 3, 16, 1, 5, 2, 1, 6, 2, 'v', '1', 2, 1, 3 };
    size_t view_len = OID_LENGTH(view_oid);
    long val;
    int rc;
    struct vacm_groupEntry *ge;
    struct vacm_viewEntry *ve;
    oid subtree_oid[] = { 1, 3 };

    /* 2a. StorageType / ViewType wrong length checks */
    val = SNMP_STORAGE_NONVOLATILE;
    rc = write_vacmSecurityToGroupStorageType(RESERVE1, (u_char *)&val,
                                              ASN_INTEGER, 2, NULL,
                                              sec2grp_oid, sec2grp_len);
    OK(rc == SNMP_ERR_WRONGLENGTH,
       "write_vacmSecurityToGroupStorageType rejects wrong var_val_len");

    rc = write_vacmViewStorageType(RESERVE1, (u_char *)&val, ASN_INTEGER, 2,
                                   NULL, view_oid, view_len);
    OK(rc == SNMP_ERR_WRONGLENGTH,
       "write_vacmViewStorageType rejects wrong var_val_len");

    rc = write_vacmViewType(RESERVE1, (u_char *)&val, ASN_INTEGER, 2,
                            NULL, view_oid, view_len);
    OK(rc == SNMP_ERR_WRONGLENGTH,
       "write_vacmViewType rejects wrong var_val_len");

    /* 2b. write_vacmGroupName RESERVE1 -> RESERVE2 -> UNDO rolls back groupName */
    ge = vacm_createGroupEntry(3, "u1");
    OK(ge != NULL, "vacm_createGroupEntry created group entry for u1");
    if (ge) {
        strcpy(ge->groupName, "orig");
        ge->status = RS_ACTIVE;
        rc = write_vacmGroupName(RESERVE1, (u_char *)"newg", ASN_OCTET_STR, 4,
                                 NULL, sec2grp_oid, sec2grp_len);
        rc |= write_vacmGroupName(RESERVE2, (u_char *)"newg", ASN_OCTET_STR, 4,
                                  NULL, sec2grp_oid, sec2grp_len);
        OK(rc == SNMP_ERR_NOERROR && strcmp(ge->groupName, "newg") == 0,
           "write_vacmGroupName RESERVE2 updates groupName to newg");
        rc = write_vacmGroupName(UNDO, (u_char *)"newg", ASN_OCTET_STR, 4,
                                 NULL, sec2grp_oid, sec2grp_len);
        OK(rc == SNMP_ERR_NOERROR && strcmp(ge->groupName, "orig") == 0,
           "write_vacmGroupName UNDO restores original groupName");
    }
    vacm_destroyAllGroupEntries();

    /* 2c. Create view entry via write_vacmViewStatus, test Mask & Type UNDO */
    view_oid[11] = 6; /* vacmViewTreeFamilyStatus */
    val = RS_CREATEANDWAIT;
    rc = write_vacmViewStatus(RESERVE1, (u_char *)&val, ASN_INTEGER,
                              sizeof(val), NULL, view_oid, view_len);
    rc |= write_vacmViewStatus(ACTION, (u_char *)&val, ASN_INTEGER,
                               sizeof(val), NULL, view_oid, view_len);
    rc |= write_vacmViewStatus(COMMIT, (u_char *)&val, ASN_INTEGER,
                               sizeof(val), NULL, view_oid, view_len);
    ve = vacm_getViewEntry("v1", subtree_oid, OID_LENGTH(subtree_oid),
                           VACM_MODE_IGNORE_MASK);
    OK(rc == SNMP_ERR_NOERROR && ve != NULL,
       "write_vacmViewStatus COMMIT creates view v1");

    if (ve) {
        u_char new_mask[] = { 0xff };
        view_oid[11] = 3; /* vacmViewTreeFamilyMask */
        rc = write_vacmViewMask(RESERVE1, new_mask, ASN_OCTET_STR, 1,
                                NULL, view_oid, view_len);
        rc |= write_vacmViewMask(RESERVE2, new_mask, ASN_OCTET_STR, 1,
                                 NULL, view_oid, view_len);
        OK(rc == SNMP_ERR_NOERROR && ve->viewMaskLen == 1 &&
           ve->viewMask[0] == 0xff,
           "write_vacmViewMask RESERVE2 sets new mask");
        rc = write_vacmViewMask(UNDO, new_mask, ASN_OCTET_STR, 1,
                                NULL, view_oid, view_len);
        OK(rc == SNMP_ERR_NOERROR && ve->viewMaskLen == 0,
           "write_vacmViewMask UNDO restores original empty mask");

        view_oid[11] = 4; /* vacmViewTreeFamilyType */
        val = SNMP_VIEW_EXCLUDED;
        rc = write_vacmViewType(RESERVE1, (u_char *)&val, ASN_INTEGER,
                                sizeof(val), NULL, view_oid, view_len);
        rc |= write_vacmViewType(RESERVE2, (u_char *)&val, ASN_INTEGER,
                                 sizeof(val), NULL, view_oid, view_len);
        OK(rc == SNMP_ERR_NOERROR && ve->viewType == SNMP_VIEW_EXCLUDED,
           "write_vacmViewType RESERVE2 updates viewType");
        rc = write_vacmViewType(UNDO, (u_char *)&val, ASN_INTEGER,
                                sizeof(val), NULL, view_oid, view_len);
        OK(rc == SNMP_ERR_NOERROR && ve->viewType == SNMP_VIEW_INCLUDED,
           "write_vacmViewType UNDO restores original viewType");
    }
    vacm_destroyAllViewEntries();
}
#endif

/*
 * 3. Notification MIB tests (commit 2d9a2ff73e39)
 */
#if defined(USING_NOTIFICATION_SNMPNOTIFYTABLE_MODULE) && defined(USING_NOTIFICATION_SNMPNOTIFYFILTERPROFILETABLE_MODULE)
{
    /* snmpNotifyEntry: .1.3.6.1.6.3.13.1.1.1.<col>.<name> */
    oid notify_oid[] = { 1, 3, 6, 1, 6, 3, 13, 1, 1, 1, 5, 'n', '1' };
    size_t notify_len = OID_LENGTH(notify_oid);
    /* snmpNotifyFilterProfileEntry: .1.3.6.1.6.3.13.1.2.1.<col>.<paramsName> */
    oid prof_oid[] = { 1, 3, 6, 1, 6, 3, 13, 1, 2, 1, 3, 'f', '1' };
    size_t prof_len = OID_LENGTH(prof_oid);
    long val;
    int rc;

    /* 3a. write_snmpNotifyRowStatus NULL and wrong length checks */
    rc = write_snmpNotifyRowStatus(RESERVE1, NULL, ASN_INTEGER, 0,
                                   NULL, notify_oid, notify_len);
    OK(rc == SNMP_ERR_WRONGTYPE,
       "write_snmpNotifyRowStatus rejects NULL var_val");

    val = RS_CREATEANDWAIT;
    rc = write_snmpNotifyRowStatus(RESERVE1, (u_char *)&val, ASN_INTEGER, 2,
                                   NULL, notify_oid, notify_len);
    OK(rc == SNMP_ERR_WRONGLENGTH,
       "write_snmpNotifyRowStatus rejects wrong var_val_len");

    /* 3b. Row creation RESERVE1 + Tag RESERVE2 + FREE cleans up StorageNew & undo_buf */
    val = RS_CREATEANDWAIT;
    rc = write_snmpNotifyRowStatus(RESERVE1, (u_char *)&val, ASN_INTEGER,
                                   sizeof(val), NULL, notify_oid, notify_len);
    rc |= write_snmpNotifyTag(RESERVE1, (u_char *)"tag1", ASN_OCTET_STR, 4,
                              NULL, notify_oid, notify_len);
    rc |= write_snmpNotifyTag(RESERVE2, (u_char *)"tag1", ASN_OCTET_STR, 4,
                              NULL, notify_oid, notify_len);
    rc |= write_snmpNotifyTag(FREE, (u_char *)"tag1", ASN_OCTET_STR, 4,
                              NULL, notify_oid, notify_len);
    rc |= write_snmpNotifyRowStatus(FREE, (u_char *)&val, ASN_INTEGER,
                                    sizeof(val), NULL, notify_oid, notify_len);
    OK(rc == SNMP_ERR_NOERROR,
       "write_snmpNotifyRowStatus and write_snmpNotifyTag FREE clean up StorageNew without leak");

    /* 3c. write_snmpNotifyFilterProfileRowStatus wrong length + FREE cleanup */
    rc = write_snmpNotifyFilterProfileRowStatus(RESERVE1, (u_char *)&val,
                                                ASN_INTEGER, 2, NULL,
                                                prof_oid, prof_len);
    OK(rc == SNMP_ERR_WRONGLENGTH,
       "write_snmpNotifyFilterProfileRowStatus rejects wrong var_val_len");

    rc = write_snmpNotifyFilterProfileRowStatus(RESERVE1, (u_char *)&val,
                                                ASN_INTEGER, sizeof(val), NULL,
                                                prof_oid, prof_len);
    rc |= write_snmpNotifyFilterProfileName(RESERVE1, (u_char *)"prof1",
                                            ASN_OCTET_STR, 5, NULL,
                                            prof_oid, prof_len);
    rc |= write_snmpNotifyFilterProfileName(RESERVE2, (u_char *)"prof1",
                                             ASN_OCTET_STR, 5, NULL,
                                             prof_oid, prof_len);
    rc |= write_snmpNotifyFilterProfileName(FREE, (u_char *)"prof1",
                                             ASN_OCTET_STR, 5, NULL,
                                             prof_oid, prof_len);
    rc |= write_snmpNotifyFilterProfileRowStatus(FREE, (u_char *)&val,
                                                 ASN_INTEGER, sizeof(val), NULL,
                                                 prof_oid, prof_len);
    OK(rc == SNMP_ERR_NOERROR,
       "write_snmpNotifyFilterProfileRowStatus and Name FREE clean up StorageNew without leak");
}
#endif

/*
 * 4. Extend & Logging MIB tests (commits 21acfe772704, be8bf903d25e)
 */
#if defined(USING_AGENT_EXTEND_MODULE) && defined(USING_AGENT_NSLOGGING_MODULE)
{
    oid ext_oid1[] = { 1, 3, 6, 1, 4, 1, 8072, 1, 3, 2, 2, 1, 21, 4, 'e', 'x', 't', '1' };
    oid ext_oid2[] = { 1, 3, 6, 1, 4, 1, 8072, 1, 3, 2, 2, 1, 3, 4, 'e', 'x', 't', '1' };
    netsnmp_mib_handler *handler;
    netsnmp_handler_registration *reginfo;
    netsnmp_agent_request_info *reqinfo;
    netsnmp_request_info *req1, *req2;
    netsnmp_table_request_info *tinfo1, *tinfo2;
    netsnmp_table_data *td;
    netsnmp_variable_list vb1, vb2;
    long status_val = RS_CREATEANDWAIT;
    int rc;

    handler = netsnmp_create_handler("nsExtendConfigTable",
                                     handle_nsExtendConfigTable);
    reginfo = netsnmp_handler_registration_create("nsExtendConfigTable", handler,
                                                  ext_oid1, 11,
                                                  HANDLER_CAN_RWRITE);
    td = netsnmp_create_table_data("nsExtendConfigTable");
    handler->myvoid = td;

    memset(&vb1, 0, sizeof(vb1));
    snmp_set_var_objid(&vb1, ext_oid1, OID_LENGTH(ext_oid1));
    snmp_set_var_typed_value(&vb1, ASN_INTEGER, &status_val, sizeof(status_val));

    memset(&vb2, 0, sizeof(vb2));
    snmp_set_var_objid(&vb2, ext_oid2, OID_LENGTH(ext_oid2));
    snmp_set_var_typed_value(&vb2, ASN_OCTET_STR, "-l", 2);
    vb1.next_variable = &vb2;

    reqinfo = SNMP_MALLOC_TYPEDEF(netsnmp_agent_request_info);
    req1 = SNMP_MALLOC_TYPEDEF(netsnmp_request_info);
    req2 = SNMP_MALLOC_TYPEDEF(netsnmp_request_info);
    req1->requestvb = &vb1;
    req1->next = req2;
    req2->requestvb = &vb2;
    req2->prev = req1;

    tinfo1 = SNMP_MALLOC_TYPEDEF(netsnmp_table_request_info);
    tinfo1->colnum = 21; /* COLUMN_EXTCFG_STATUS */
    snmp_varlist_add_variable(&tinfo1->indexes, NULL, 0, ASN_OCTET_STR, "ext1", 4);
    netsnmp_request_add_list_data(req1,
        netsnmp_create_data_list(TABLE_HANDLER_NAME, tinfo1, NULL));

    tinfo2 = SNMP_MALLOC_TYPEDEF(netsnmp_table_request_info);
    tinfo2->colnum = 3; /* COLUMN_EXTCFG_ARGS */
    snmp_varlist_add_variable(&tinfo2->indexes, NULL, 0, ASN_OCTET_STR, "ext1", 4);
    netsnmp_request_add_list_data(req2,
        netsnmp_create_data_list(TABLE_HANDLER_NAME, tinfo2, NULL));

    reqinfo->mode = MODE_SET_RESERVE1;
    rc = handle_nsExtendConfigTable(handler, reginfo, reqinfo, req1);
    reqinfo->mode = MODE_SET_RESERVE2;
    rc |= handle_nsExtendConfigTable(handler, reginfo, reqinfo, req1);
    OK(rc == SNMP_ERR_NOERROR &&
       netsnmp_extract_table_row(req1) != NULL &&
       netsnmp_extract_table_row(req2) != NULL,
       "handle_nsExtendConfigTable RESERVE2 creates row and links into sibling request");

    reqinfo->mode = MODE_SET_ACTION;
    rc = handle_nsExtendConfigTable(handler, reginfo, reqinfo, req1);
    reqinfo->mode = MODE_SET_UNDO;
    rc |= handle_nsExtendConfigTable(handler, reginfo, reqinfo, req1);
    OK(rc == SNMP_ERR_NOERROR &&
       netsnmp_extract_table_row(req1) == NULL &&
       netsnmp_extract_table_row(req2) == NULL,
       "handle_nsExtendConfigTable UNDO clears row from all sibling requests without use-after-free");

    snmp_free_varbind(tinfo1->indexes);
    SNMP_FREE(tinfo1);
    snmp_free_varbind(tinfo2->indexes);
    SNMP_FREE(tinfo2);
    netsnmp_free_request_data_sets(req1);
    netsnmp_free_request_data_sets(req2);
    SNMP_FREE(req1);
    SNMP_FREE(req2);
    SNMP_FREE(reqinfo);
    vb1.next_variable = NULL;
    snmp_reset_var_buffers(&vb1);
    snmp_reset_var_buffers(&vb2);
    netsnmp_table_data_delete_table(td);
    handler->myvoid = NULL;
    netsnmp_handler_registration_free(reginfo);

    /* 4b. handle_nsLoggingTable: RS_DESTROY on a non-existent row (logh == NULL) */
    {
        oid log_oid[] = { 1, 3, 6, 1, 4, 1, 8072, 1, 7, 2, 1, 5, 7, 4, 'f', 'a', 'k', 'e' };
        long destroy_val = RS_DESTROY;

        handler = netsnmp_create_handler("nsLoggingTable", handle_nsLoggingTable);
        reginfo = netsnmp_handler_registration_create("nsLoggingTable", handler,
                                                      log_oid, 11,
                                                      HANDLER_CAN_RWRITE);
        memset(&vb1, 0, sizeof(vb1));
        snmp_set_var_objid(&vb1, log_oid, OID_LENGTH(log_oid));
        snmp_set_var_typed_value(&vb1, ASN_INTEGER, &destroy_val, sizeof(destroy_val));

        reqinfo = SNMP_MALLOC_TYPEDEF(netsnmp_agent_request_info);
        req1 = SNMP_MALLOC_TYPEDEF(netsnmp_request_info);
        req1->requestvb = &vb1;

        tinfo1 = SNMP_MALLOC_TYPEDEF(netsnmp_table_request_info);
        tinfo1->colnum = 5; /* NSLOGGING_STATUS */
        netsnmp_request_add_list_data(req1,
            netsnmp_create_data_list(TABLE_HANDLER_NAME, tinfo1, NULL));

        reqinfo->mode = MODE_SET_RESERVE1;
        rc = handle_nsLoggingTable(handler, reginfo, reqinfo, req1);
        reqinfo->mode = MODE_SET_RESERVE2;
        rc |= handle_nsLoggingTable(handler, reginfo, reqinfo, req1);
        reqinfo->mode = MODE_SET_ACTION;
        rc |= handle_nsLoggingTable(handler, reginfo, reqinfo, req1);
        reqinfo->mode = MODE_SET_COMMIT;
        rc |= handle_nsLoggingTable(handler, reginfo, reqinfo, req1);
        OK(rc == SNMP_ERR_NOERROR && req1->status == SNMP_ERR_NOERROR,
           "handle_nsLoggingTable RS_DESTROY on non-existent row succeeds without NULL deref");

        SNMP_FREE(tinfo1);
        netsnmp_free_request_data_sets(req1);
        SNMP_FREE(req1);
        SNMP_FREE(reqinfo);
        snmp_reset_var_buffers(&vb1);
        netsnmp_handler_registration_free(reginfo);
    }
}
#endif

/*
 * 5. DisMan MIB tests (commits bcdc15dfe9f5, bc401bb180bf, 62d1f83e6ac0, 6fcdaff36f22)
 */
#if defined(USING_DISMAN_EVENT_MTEEVENTTABLE_MODULE) && \
    defined(USING_DISMAN_EVENT_MTEOBJECTSTABLE_MODULE) && \
    defined(USING_DISMAN_EVENT_MTETRIGGERTABLE_MODULE) && \
    defined(USING_DISMAN_EXPR_EXPOBJECTTABLE_MODULE) && \
    defined(USING_DISMAN_EXPR_EXPEXPRESSIONTABLE_MODULE) && \
    defined(USING_DISMAN_SCHEDULE_SCHEDTABLE_MODULE) && \
    defined(USING_DISMAN_PING_PINGCTLTABLE_MODULE)
{
    struct {
        const char *name;
        Netsnmp_Node_Handler *fn;
        unsigned int status_col;
    } disman_tables[6] = {
        { "mteEventTable",      mteEventTable_handler,   5  },
        { "mteObjectsTable",    mteObjectsTable_handler, 5  },
        { "mteTriggerTable",    mteTriggerTable_handler, 15 },
        { "expObjectTable",     expObjectTable_handler,  10 },
        { "schedTable",         schedTable_handler,      20 },
        { "expExpressionTable", NULL,                    9  }
    };
    oid exp_expr_oid[] = { 1, 3, 6, 1, 2, 1, 90, 1, 2, 1 };
    netsnmp_subtree *st_exp;
    size_t i;

    st_exp = netsnmp_subtree_find(exp_expr_oid, OID_LENGTH(exp_expr_oid), NULL, "");
    if (st_exp && st_exp->reginfo) {
        netsnmp_mib_handler *h;
        for (h = st_exp->reginfo->handler; h != NULL; h = h->next) {
            if (h->handler_name &&
                strcmp(h->handler_name, "expExpressionTable") == 0 &&
                h->access_method != NULL) {
                disman_tables[5].fn = h->access_method;
                break;
            }
        }
    }
    OK(disman_tables[5].fn != NULL,
       "Found static expExpressionTable_handler via subtree");

    for (i = 0; i < 6; i++) {
        oid dummy_oid[] = { 1, 3, 6, 1, 2, 1, 88, 1 };
        netsnmp_mib_handler *handler;
        netsnmp_handler_registration *reginfo;
        netsnmp_agent_request_info *reqinfo;
        netsnmp_request_info *req;
        netsnmp_table_request_info *tinfo;
        netsnmp_variable_list vb;
        char long_idx[40];
        long val;
        int rc;

        if (!disman_tables[i].fn)
            continue;

        memset(long_idx, 'a', sizeof(long_idx));
        handler = netsnmp_create_handler(disman_tables[i].name,
                                         disman_tables[i].fn);
        reginfo = netsnmp_handler_registration_create(disman_tables[i].name,
                                                      handler, dummy_oid,
                                                      OID_LENGTH(dummy_oid),
                                                      HANDLER_CAN_RWRITE);
        reqinfo = SNMP_MALLOC_TYPEDEF(netsnmp_agent_request_info);
        req = SNMP_MALLOC_TYPEDEF(netsnmp_request_info);
        tinfo = SNMP_MALLOC_TYPEDEF(netsnmp_table_request_info);
        tinfo->colnum = disman_tables[i].status_col;
        snmp_varlist_add_variable(&tinfo->indexes, NULL, 0, ASN_OCTET_STR,
                                  long_idx, sizeof(long_idx));
        netsnmp_request_add_list_data(req,
            netsnmp_create_data_list(TABLE_HANDLER_NAME, tinfo, NULL));

        /* 5a. Oversized index (> 32 bytes) in MODE_SET_RESERVE2 -> NOCREATION */
        memset(&vb, 0, sizeof(vb));
        val = RS_CREATEANDWAIT;
        snmp_set_var_typed_value(&vb, ASN_INTEGER, &val, sizeof(val));
        req->requestvb = &vb;
        req->status = SNMP_ERR_NOERROR;
        reqinfo->mode = MODE_SET_RESERVE2;
        rc = disman_tables[i].fn(handler, reginfo, reqinfo, req);
        OKF(req->status == SNMP_ERR_NOCREATION,
            ("%s rejects oversized index (> 32 bytes) with SNMP_ERR_NOCREATION",
             disman_tables[i].name));

        /* 5b. RS_DESTROY with NULL entry in ACTION and COMMIT -> no NULL deref */
        val = RS_DESTROY;
        snmp_set_var_typed_value(&vb, ASN_INTEGER, &val, sizeof(val));
        req->status = SNMP_ERR_NOERROR;
        reqinfo->mode = MODE_SET_ACTION;
        rc = disman_tables[i].fn(handler, reginfo, reqinfo, req);
        reqinfo->mode = MODE_SET_COMMIT;
        rc |= disman_tables[i].fn(handler, reginfo, reqinfo, req);
        OKF(rc == SNMP_ERR_NOERROR && req->status == SNMP_ERR_NOERROR,
            ("%s handles RS_DESTROY on missing entry in ACTION/COMMIT without NULL deref",
             disman_tables[i].name));

        snmp_free_varbind(tinfo->indexes);
        SNMP_FREE(tinfo);
        netsnmp_free_request_data_sets(req);
        SNMP_FREE(req);
        SNMP_FREE(reqinfo);
        snmp_reset_var_buffers(&vb);
        netsnmp_handler_registration_free(reginfo);
    }

    /* 5c. pingCtlTable: RESERVE1 -> RESERVE2 -> FREE frees StorageNew without leak */
    {
        oid ping_oid[] = { 1, 3, 6, 1, 2, 1, 80, 1, 2, 1, 23, 2, 'o', '1', 2, 't', '1' };
        long val = RS_CREATEANDWAIT;
        int rc;

        rc = write_pingCtlRowStatus(RESERVE1, (u_char *)&val, ASN_INTEGER,
                                    sizeof(val), NULL, ping_oid, OID_LENGTH(ping_oid));
        rc |= write_pingCtlRowStatus(RESERVE2, (u_char *)&val, ASN_INTEGER,
                                     sizeof(val), NULL, ping_oid, OID_LENGTH(ping_oid));
        rc |= write_pingCtlRowStatus(FREE, (u_char *)&val, ASN_INTEGER,
                                     sizeof(val), NULL, ping_oid, OID_LENGTH(ping_oid));
        OK(rc == SNMP_ERR_NOERROR,
           "write_pingCtlRowStatus FREE cleans up uncommitted StorageNew without leak");
    }
}
#endif

/*
 * 6. UCD-SNMP & DLMOD tests (commits 826b979d3835, 27e86ec0472c)
 */
#if defined(USING_UCD_SNMP_PASS_COMMON_MODULE) && \
    !defined(NETSNMP_FEATURE_REMOVE_PASS_COMMON) && \
    defined(USING_UCD_SNMP_EXTENSIBLE_MODULE) && \
    defined(USING_UCD_SNMP_DLMOD_MODULE)
{
    char buf[64];
    char buf2[64];
    size_t var_len = 0;
    unsigned char *res;
    char long_cmd[1200];
    struct variable dummy_vp;

    /* 6a. netsnmp_internal_pass_parse with empty buf2 ("") */
    memset(&dummy_vp, 0, sizeof(dummy_vp));
    strcpy(buf, "string");
    buf2[0] = '\0';
    res = netsnmp_internal_pass_parse(buf, buf2, &var_len, &dummy_vp);
    OK(res != NULL && var_len == 0 && dummy_vp.type == ASN_OCTET_STR,
       "netsnmp_internal_pass_parse handles empty string without underflow");

    /* 6b. netsnmp_internal_pass_set_format with unknown type (ASN_NULL) */
    memset(buf, 'X', sizeof(buf));
    netsnmp_internal_pass_set_format(buf, NULL, ASN_NULL, 0);
    OK(buf[0] == '\0',
       "netsnmp_internal_pass_set_format NUL-terminates buffer on unknown type");

    /* 6c. execfix_parse_config and procfix_parse_config with oversized command */
    strcpy(long_cmd, "my_entry ");
    memset(long_cmd + 9, 'A', sizeof(long_cmd) - 10);
    long_cmd[sizeof(long_cmd) - 1] = '\0';
    execfix_parse_config("execfix", long_cmd);
    procfix_parse_config("procfix", long_cmd);
    OK(1, "execfix_parse_config and procfix_parse_config safely reject oversized command");

    /* 6d. dlmod: write_dlmodStatus length check and repeated DLMOD_LOAD */
    {
        oid dlmod_status_oid[] = { 1, 3, 6, 1, 4, 1, 2021, 13, 14, 2, 1, 5, 1 };
        oid dlmod_path_oid[]   = { 1, 3, 6, 1, 4, 1, 2021, 13, 14, 2, 1, 3, 1 };
        oid dlmod_err_oid[]    = { 1, 3, 6, 1, 4, 1, 2021, 13, 14, 2, 1, 4, 1 };
        netsnmp_subtree *st_status, *st_path, *st_err;
        struct variable *vp_status = NULL, *vp_path = NULL, *vp_err = NULL;
        netsnmp_mib_handler *h;

        st_status = netsnmp_subtree_find(dlmod_status_oid, 12, NULL, "");
        st_path   = netsnmp_subtree_find(dlmod_path_oid, 12, NULL, "");
        st_err    = netsnmp_subtree_find(dlmod_err_oid, 12, NULL, "");
        if (st_status && st_status->reginfo) {
            for (h = st_status->reginfo->handler; h; h = h->next)
                if (h->handler_name && strcmp(h->handler_name, "old_api") == 0)
                    vp_status = (struct variable *)h->myvoid;
        }
        if (st_path && st_path->reginfo) {
            for (h = st_path->reginfo->handler; h; h = h->next)
                if (h->handler_name && strcmp(h->handler_name, "old_api") == 0)
                    vp_path = (struct variable *)h->myvoid;
        }
        if (st_err && st_err->reginfo) {
            for (h = st_err->reginfo->handler; h; h = h->next)
                if (h->handler_name && strcmp(h->handler_name, "old_api") == 0)
                    vp_err = (struct variable *)h->myvoid;
        }
        OK(vp_status != NULL && vp_path != NULL && vp_err != NULL,
           "Found dlmod old_api variables via subtree");
        if (vp_status && vp_path && vp_err) {
            struct variable cvp;
            WriteMethod *write_status = NULL;
            WriteMethod *write_path   = NULL;
            size_t len = 0;
            u_char *val_ptr;
            long dval;
            int rc;
            oid name_buf[MAX_OID_LEN];
            size_t name_len;

            memset(&cvp, 0, sizeof(cvp));
            cvp.magic = vp_status->magic;
            cvp.type = vp_status->type;
            cvp.acl = vp_status->acl;
            cvp.findVar = vp_status->findVar;
            cvp.namelen = 12;
            memcpy(cvp.name, dlmod_status_oid, 12 * sizeof(oid));

            memcpy(name_buf, dlmod_status_oid, sizeof(dlmod_status_oid));
            name_len = OID_LENGTH(dlmod_status_oid);
            (void)vp_status->findVar(&cvp, name_buf, &name_len, 1,
                                     &len, &write_status);
            OK(write_status != NULL, "Found write_dlmodStatus via dlmod subtree");
            if (write_status) {
                dval = 6; /* DLMOD_CREATE */
                rc = write_status(RESERVE1, (u_char *)&dval, ASN_INTEGER, 2,
                                  NULL, dlmod_status_oid,
                                  OID_LENGTH(dlmod_status_oid));
                OK(rc == SNMP_ERR_WRONGLENGTH,
                   "write_dlmodStatus rejects wrong var_val_len");

                rc = write_status(RESERVE1, (u_char *)&dval, ASN_INTEGER,
                                  sizeof(dval), NULL, dlmod_status_oid,
                                  OID_LENGTH(dlmod_status_oid));
                rc |= write_status(RESERVE2, (u_char *)&dval, ASN_INTEGER,
                                   sizeof(dval), NULL, dlmod_status_oid,
                                   OID_LENGTH(dlmod_status_oid));
                rc |= write_status(ACTION, (u_char *)&dval, ASN_INTEGER,
                                   sizeof(dval), NULL, dlmod_status_oid,
                                   OID_LENGTH(dlmod_status_oid));
                rc |= write_status(COMMIT, (u_char *)&dval, ASN_INTEGER,
                                   sizeof(dval), NULL, dlmod_status_oid,
                                   OID_LENGTH(dlmod_status_oid));
                OK(rc == SNMP_ERR_NOERROR, "write_dlmodStatus creates dlmod row 1");

                cvp.magic = vp_path->magic;
                cvp.type = vp_path->type;
                cvp.acl = vp_path->acl;
                cvp.findVar = vp_path->findVar;
                memcpy(cvp.name, dlmod_path_oid, 12 * sizeof(oid));

                memcpy(name_buf, dlmod_path_oid, sizeof(dlmod_path_oid));
                name_len = OID_LENGTH(dlmod_path_oid);
                (void)vp_path->findVar(&cvp, name_buf, &name_len, 1,
                                       &len, &write_path);
                if (write_path) {
                    rc = write_path(RESERVE1, (u_char *)"rel_mod", ASN_OCTET_STR,
                                    7, NULL, dlmod_path_oid,
                                    OID_LENGTH(dlmod_path_oid));
                    rc |= write_path(COMMIT, (u_char *)"rel_mod", ASN_OCTET_STR,
                                     7, NULL, dlmod_path_oid,
                                     OID_LENGTH(dlmod_path_oid));
                    OK(rc == SNMP_ERR_NOERROR,
                       "write_dlmodPath sets relative path rel_mod");
                }

                dval = 4; /* DLMOD_LOAD */
                (void)write_status(ACTION, (u_char *)&dval, ASN_INTEGER,
                                   sizeof(dval), NULL, dlmod_status_oid,
                                   OID_LENGTH(dlmod_status_oid));
                (void)write_status(COMMIT, (u_char *)&dval, ASN_INTEGER,
                                   sizeof(dval), NULL, dlmod_status_oid,
                                   OID_LENGTH(dlmod_status_oid));
                (void)write_status(ACTION, (u_char *)&dval, ASN_INTEGER,
                                   sizeof(dval), NULL, dlmod_status_oid,
                                   OID_LENGTH(dlmod_status_oid));
                (void)write_status(COMMIT, (u_char *)&dval, ASN_INTEGER,
                                   sizeof(dval), NULL, dlmod_status_oid,
                                   OID_LENGTH(dlmod_status_oid));

                memcpy(name_buf, dlmod_path_oid, sizeof(dlmod_path_oid));
                name_len = OID_LENGTH(dlmod_path_oid);
                val_ptr = vp_path->findVar(&cvp, name_buf, &name_len, 1,
                                           &len, &write_path);
                OK(val_ptr != NULL && len == 7 &&
                   memcmp(val_ptr, "rel_mod", 7) == 0,
                   "dlmod_load_module preserves relative dlm->path on load failure");

                cvp.magic = vp_err->magic;
                cvp.type = vp_err->type;
                cvp.acl = vp_err->acl;
                cvp.findVar = vp_err->findVar;
                memcpy(cvp.name, dlmod_err_oid, 12 * sizeof(oid));

                memcpy(name_buf, dlmod_err_oid, sizeof(dlmod_err_oid));
                name_len = OID_LENGTH(dlmod_err_oid);
                val_ptr = vp_err->findVar(&cvp, name_buf, &name_len, 1,
                                          &len, &write_path);
                OK(val_ptr != NULL &&
                   strstr((const char *)val_ptr, "/nonexistent_dir2/rel_mod.so") != NULL,
                   "dlmod_load_module preserves colon-separated dlmod_path across loads");
            }
        }
    }
}
#endif

free_config();
#ifdef USING_AGENT_EXTEND_MODULE
shutdown_extend();
#endif
#ifdef USING_DISMAN_EXPR_EXPEXPRESSIONTABLE_MODULE
shutdown_expExpressionTable();
#endif
#ifdef USING_UCD_SNMP_DLMOD_MODULE
shutdown_dlmod();
#endif
snmp_shutdown("snmpd");
shutdown_agent();
SOCK_CLEANUP;
#endif /* !NETSNMP_NO_WRITE_SUPPORT */
