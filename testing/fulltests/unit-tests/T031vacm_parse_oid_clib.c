/* HEADER Testing VACM OID parsing (access_parse_oid, view_parse_oid, sec2group_parse_oid) */

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/all_helpers.h>
#include <mibII/vacm_vars.h>

#if !defined(NETSNMP_NO_WRITE_SUPPORT) && defined(HAVE_LIBNL3)

/* =========================================================================
 * Test access_parse_oid() (Finding F-1 and edge cases)
 * ========================================================================= */
{
    unsigned char *groupName = NULL, *contextPrefix = NULL;
    size_t groupNameLen = 0, contextPrefixLen = 0;
    int model = 0, level = 0;
    int res;

    /*
     * Finding F-1: 0xFFFFFFFF in oidIndex[0] and oidIndex[1] with short oidLen.
     * Must be rejected without buffer underwrite or out-of-bounds access.
     */
    oid f1_oid[] = { 0xFFFFFFFFUL, 0xFFFFFFFFUL };
    res = access_parse_oid(f1_oid, sizeof(f1_oid) / sizeof(f1_oid[0]),
                           &groupName, &groupNameLen,
                           &contextPrefix, &contextPrefixLen,
                           &model, &level);
    OK(res != 0, "access_parse_oid with F-1 truncated OID rejected");

    /* Large groupName length exceeding oidLen */
    oid large_gn_oid[] = { 0xFFFFFFFFUL, 0, 0, 0, 0, 0 };
    res = access_parse_oid(large_gn_oid, sizeof(large_gn_oid) / sizeof(large_gn_oid[0]),
                           &groupName, &groupNameLen,
                           &contextPrefix, &contextPrefixLen,
                           &model, &level);
    OK(res != 0, "access_parse_oid with large groupName length rejected");

    /* Large contextPrefix length exceeding oidLen */
    oid large_cp_oid[] = { 1, 'a', 0xFFFFFFFFUL, 0, 0, 0 };
    res = access_parse_oid(large_cp_oid, sizeof(large_cp_oid) / sizeof(large_cp_oid[0]),
                           &groupName, &groupNameLen,
                           &contextPrefix, &contextPrefixLen,
                           &model, &level);
    OK(res != 0, "access_parse_oid with large contextPrefix length rejected");

    /* Short oidLen / NULL pointer checks */
    res = access_parse_oid(NULL, 10, &groupName, &groupNameLen,
                           &contextPrefix, &contextPrefixLen, &model, &level);
    OK(res != 0, "access_parse_oid with NULL oidIndex rejected");

    res = access_parse_oid(f1_oid, 0, &groupName, &groupNameLen,
                           &contextPrefix, &contextPrefixLen, &model, &level);
    OK(res != 0, "access_parse_oid with oidLen=0 rejected");

    res = access_parse_oid(f1_oid, 3, &groupName, &groupNameLen,
                           &contextPrefix, &contextPrefixLen, &model, &level);
    OK(res != 0, "access_parse_oid with oidLen=3 rejected");

    /* Character > 255 in groupName */
    oid oob_char_gn[] = { 1, 300, 0, 3, 1 };
    res = access_parse_oid(oob_char_gn, sizeof(oob_char_gn) / sizeof(oob_char_gn[0]),
                           &groupName, &groupNameLen,
                           &contextPrefix, &contextPrefixLen,
                           &model, &level);
    OK(res != 0, "access_parse_oid with groupName char > 255 rejected");

    /* Character > 255 in contextPrefix */
    oid oob_char_cp[] = { 1, 'a', 1, 300, 3, 1 };
    res = access_parse_oid(oob_char_cp, sizeof(oob_char_cp) / sizeof(oob_char_cp[0]),
                           &groupName, &groupNameLen,
                           &contextPrefix, &contextPrefixLen,
                           &model, &level);
    OK(res != 0, "access_parse_oid with contextPrefix char > 255 rejected");

    /* Valid access entry OID parsing */
    oid valid_access_oid[] = { 3, 'g', 'r', 'p', 3, 'c', 't', 'x', 3, 1 };
    groupName = NULL;
    contextPrefix = NULL;
    res = access_parse_oid(valid_access_oid,
                           sizeof(valid_access_oid) / sizeof(valid_access_oid[0]),
                           &groupName, &groupNameLen,
                           &contextPrefix, &contextPrefixLen,
                           &model, &level);
    OK(res == 0, "access_parse_oid with valid OID succeeded");
    OK(groupName != NULL && groupNameLen == 3 && strcmp((char *)groupName, "grp") == 0,
       "access_parse_oid parsed groupName correctly");
    OK(contextPrefix != NULL && contextPrefixLen == 3 && strcmp((char *)contextPrefix, "ctx") == 0,
       "access_parse_oid parsed contextPrefix correctly");
    OK(model == 3, "access_parse_oid parsed model correctly");
    OK(level == 1, "access_parse_oid parsed level correctly");
    free(groupName);
    free(contextPrefix);
}

/* =========================================================================
 * Test view_parse_oid() (Finding F-5 and edge cases)
 * ========================================================================= */
{
    unsigned char *viewName = NULL;
    size_t viewNameLen = 0, subtreeLen = 0;
    oid *subtree = NULL;
    int res;

    /*
     * Finding F-5: 0xFFFFFFFF in oidIndex[0] with short oidLen.
     * Must be rejected without buffer underwrite or out-of-bounds access.
     */
    oid f5_oid[] = { 0xFFFFFFFFUL };
    res = view_parse_oid(f5_oid, sizeof(f5_oid) / sizeof(f5_oid[0]),
                         &viewName, &viewNameLen, &subtree, &subtreeLen);
    OK(res != 0, "view_parse_oid with F-5 truncated OID rejected");

    /* Large viewName length exceeding oidLen */
    oid large_vn_oid[] = { 0xFFFFFFFFUL, 1, 3, 6, 1 };
    res = view_parse_oid(large_vn_oid, sizeof(large_vn_oid) / sizeof(large_vn_oid[0]),
                         &viewName, &viewNameLen, &subtree, &subtreeLen);
    OK(res != 0, "view_parse_oid with large viewName length rejected");

    /* Short oidLen / NULL pointer checks */
    res = view_parse_oid(NULL, 10, &viewName, &viewNameLen, &subtree, &subtreeLen);
    OK(res != 0, "view_parse_oid with NULL oidIndex rejected");

    res = view_parse_oid(f5_oid, 0, &viewName, &viewNameLen, &subtree, &subtreeLen);
    OK(res != 0, "view_parse_oid with oidLen=0 rejected");

    /* viewNameL >= oidLen */
    oid vn_ge_oid[] = { 5, 'a', 'b' };
    res = view_parse_oid(vn_ge_oid, sizeof(vn_ge_oid) / sizeof(vn_ge_oid[0]),
                         &viewName, &viewNameLen, &subtree, &subtreeLen);
    OK(res != 0, "view_parse_oid with viewNameLen >= oidLen rejected");

    /* Character > 255 in viewName */
    oid oob_char_vn[] = { 1, 300, 1, 3, 6, 1 };
    res = view_parse_oid(oob_char_vn, sizeof(oob_char_vn) / sizeof(oob_char_vn[0]),
                         &viewName, &viewNameLen, &subtree, &subtreeLen);
    OK(res != 0, "view_parse_oid with viewName char > 255 rejected");

    /* Valid view entry OID parsing */
    oid valid_view_oid[] = { 5, 'v', 'i', 'e', 'w', '1', 1, 3, 6, 1 };
    viewName = NULL;
    subtree = NULL;
    res = view_parse_oid(valid_view_oid,
                         sizeof(valid_view_oid) / sizeof(valid_view_oid[0]),
                         &viewName, &viewNameLen, &subtree, &subtreeLen);
    OK(res == 0, "view_parse_oid with valid OID succeeded");
    OK(viewName != NULL && viewNameLen == 5 && strcmp((char *)viewName, "view1") == 0,
       "view_parse_oid parsed viewName correctly");
    OK(subtree != NULL && subtreeLen == 4 &&
       subtree[0] == 1 && subtree[1] == 3 && subtree[2] == 6 && subtree[3] == 1,
       "view_parse_oid parsed subtree correctly");
    free(viewName);
    free(subtree);
}

/* =========================================================================
 * Test sec2group_parse_oid() (Related VACM OID parsing)
 * ========================================================================= */
{
    unsigned char *name = NULL;
    size_t nameLen = 0;
    int model = 0;
    int res;

    /* Large name length exceeding oidLen */
    oid large_s2g_oid[] = { 3, 0xFFFFFFFFUL };
    res = sec2group_parse_oid(large_s2g_oid, sizeof(large_s2g_oid) / sizeof(large_s2g_oid[0]),
                              &model, &name, &nameLen);
    OK(res != 0, "sec2group_parse_oid with large name length rejected");

    /* Short oidLen / NULL checks */
    res = sec2group_parse_oid(NULL, 10, &model, &name, &nameLen);
    OK(res != 0, "sec2group_parse_oid with NULL oidIndex rejected");

    res = sec2group_parse_oid(large_s2g_oid, 0, &model, &name, &nameLen);
    OK(res != 0, "sec2group_parse_oid with oidLen=0 rejected");

    res = sec2group_parse_oid(large_s2g_oid, 1, &model, &name, &nameLen);
    OK(res != 0, "sec2group_parse_oid with oidLen=1 rejected");

    /* Valid sec2group entry OID parsing */
    oid valid_s2g_oid[] = { 3, 5, 'u', 's', 'e', 'r', '1' };
    name = NULL;
    res = sec2group_parse_oid(valid_s2g_oid,
                              sizeof(valid_s2g_oid) / sizeof(valid_s2g_oid[0]),
                              &model, &name, &nameLen);
    OK(res == 0, "sec2group_parse_oid with valid OID succeeded");
    OK(model == 3, "sec2group_parse_oid parsed model correctly");
    OK(name != NULL && nameLen == 5 && strcmp((char *)name, "user1") == 0,
       "sec2group_parse_oid parsed name correctly");
    free(name);
}

#endif /* !NETSNMP_NO_WRITE_SUPPORT */
