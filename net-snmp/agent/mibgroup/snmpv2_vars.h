extern u_char *var_party __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));
extern int write_party __P((int, u_char *, u_char, int, u_char *, oid *, int));
extern u_char *var_context __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));
extern int write_context __P((int, u_char *, u_char, int, u_char *, oid *, int));
extern u_char *var_acl __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));
extern int write_acl __P((int, u_char *, u_char, int, u_char *, oid *, int));
extern u_char *var_view __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));
extern int write_view __P((int, u_char *, u_char, int, u_char *, oid *, int));

#ifdef IN_SNMP_VARS_C

struct variable2 party_variables[] = {
    {PARTYINDEX, INTEGER, RONLY, var_party, 1, {2}},
    {PARTYTDOMAIN, OBJID, RWRITE, var_party, 1, {3}},
    {PARTYTADDRESS, STRING, RWRITE, var_party, 1, {4}},
    {PARTYMAXMESSAGESIZE, INTEGER, RWRITE, var_party, 1, {5}},
    {PARTYLOCAL, INTEGER, RWRITE, var_party, 1, {6}},
    {PARTYAUTHPROTOCOL, OBJID, RWRITE, var_party, 1, {7}},
    {PARTYAUTHCLOCK, UINTEGER, RWRITE, var_party, 1, {8}},
    {PARTYAUTHPRIVATE, STRING, RWRITE, var_party, 1, {9}},
    {PARTYAUTHPUBLIC, STRING, RWRITE, var_party, 1, {10}},
    {PARTYAUTHLIFETIME, INTEGER, RWRITE, var_party, 1, {11}},
    {PARTYPRIVPROTOCOL, OBJID, RWRITE, var_party, 1, {12}},
    {PARTYPRIVPRIVATE, STRING, RWRITE, var_party, 1, {13}},
    {PARTYPRIVPUBLIC, STRING, RWRITE, var_party, 1, {14}},
    {PARTYCLONEFROM, OBJID, RONLY, var_party, 1, {15}},
    {PARTYSTORAGETYPE, INTEGER, RWRITE, var_party, 1, {16}},
    {PARTYSTATUS, INTEGER, RWRITE, var_party, 1, {17}}
};

struct variable2 context_variables[] = {
    {CONTEXTINDEX, INTEGER, RONLY, var_context, 1, {2}},
    {CONTEXTLOCAL, INTEGER, RONLY, var_context, 1, {3}},
    {CONTEXTVIEWINDEX, INTEGER, RONLY, var_context, 1, {4}},
    {CONTEXTLOCALENTITY, STRING, RWRITE, var_context, 1, {5}},
    {CONTEXTLOCALTIME, OBJID, RWRITE, var_context, 1, {6}},
    {CONTEXTDSTPARTYINDEX, OBJID, RWRITE, var_context, 1, {7}},
    {CONTEXTSRCPARTYINDEX, OBJID, RWRITE, var_context, 1, {8}},
    {CONTEXTPROXYCONTEXT, OBJID, RWRITE, var_context, 1, {9}},
    {CONTEXTSTORAGETYPE, INTEGER, RWRITE, var_context, 1, {10}},
    {CONTEXTSTATUS, INTEGER, RWRITE, var_context, 1, {11}}
};


/* No access for community SNMP, RW possible for Secure SNMP */
#define PRIVRW   (SNMPV2ANY | 0x5000)
/* No access for community SNMP, RO possible for Secure SNMP */
#define PRIVRO   (SNMPV2ANY)

struct variable2 acl_variables[] = {
    {ACLPRIVELEGES, INTEGER, PRIVRW, var_acl, 1, {4}},
    {ACLSTORAGETYPE, INTEGER, PRIVRW, var_acl, 1, {5}},
    {ACLSTATUS, INTEGER, PRIVRW, var_acl, 1, {6}}
};

struct variable2 view_variables[] = {
    {VIEWMASK, STRING, PRIVRW, var_view, 1, {3}},
    {VIEWTYPE, INTEGER, PRIVRW, var_view, 1, {4}},
    {VIEWSTORAGETYPE, INTEGER, PRIVRW, var_view, 1, {5}},
    {VIEWSTATUS, INTEGER, PRIVRW, var_view, 1, {6}}
};


struct variable2 alarmnextindex_variables[] = {
    {ALARMNEXTINDEX, INTEGER, RONLY, var_alarmnextindex, 1, {0}}
};

struct variable2 alarm_variables[] = {
    {ALARMTABVARIABLE, OBJID, RWRITE, var_alarmtab, 1, {2 }},
    {ALARMTABINTERVAL, INTEGER, RWRITE, var_alarmtab, 1, {3 }},
    {ALARMTABSAMPLETYPE, INTEGER, RWRITE, var_alarmtab, 1, {4 }},
    {ALARMTABVALUE, INTEGER, RONLY, var_alarmtab, 1, {5 }},
    {ALARMTABSTARTUPALARM, INTEGER, RWRITE, var_alarmtab, 1, {6 }},
    {ALARMTABRISINGTHRESH, INTEGER, RWRITE, var_alarmtab, 1, {7 }},
    {ALARMTABFALLINGTHRESH, INTEGER, RWRITE, var_alarmtab, 1, {8 }},
    {ALARMTABRISINGINDEX, INTEGER, RWRITE, var_alarmtab, 1, {9}},
    {ALARMTABFALLINGINDEX, INTEGER, RWRITE, var_alarmtab, 1, {10 }},
    {ALARMTABUNAVAILABLEINDEX, INTEGER, RWRITE, var_alarmtab, 1, {11 }},
    {ALARMTABSTATUS, INTEGER, RWRITE, var_alarmtab, 1, {12 }}
};

struct variable2 eventnextindex_variables[] = {
    {EVENTNEXTINDEX, INTEGER, RONLY, var_eventnextindex, 1, {0}}
};

struct variable2 eventtab_variables[] = {
        {EVENTTABID, OBJID, RWRITE, var_eventtab, 1, {2 }},
        {EVENTTABDESCRIPTION, STRING, RWRITE, var_eventtab, 1, {3 }},
        {EVENTTABEVENTS, COUNTER, RONLY, var_eventtab, 1, {4 }},
        {EVENTTABLASTTIMESENT, TIMETICKS, RONLY, var_eventtab, 1, {5 }},
        {EVENTTABSTATUS, INTEGER, RWRITE, var_eventtab, 1, {6 }}
};

struct variable2 eventmininterval_variables[] = {
    {EVENTMININTERVAL, INTEGER, RONLY, var_eventnotifyvars, 1, {0}}
};

struct variable2 eventmaxretrans_variables[] = {
    {EVENTMAXRETRANS, INTEGER, RONLY, var_eventnotifyvars, 1, {0}}
};

struct variable2 eventnotifytab_variables[] = {
        {EVENTNOTIFYTABINTERVAL, INTEGER, RWRITE, var_eventnotifytab, 1, {1 }},
        {EVENTNOTIFYTABRETRANSMISSIONS, INTEGER, RWRITE, var_eventnotifytab, 1, {2 }},
        {EVENTNOTIFYTABLIFETIME, INTEGER, RWRITE, var_eventnotifytab, 1, {3 }},
        {EVENTNOTIFYTABSTATUS, INTEGER, RWRITE, var_eventnotifytab, 1, {4 }},
};

#endif
