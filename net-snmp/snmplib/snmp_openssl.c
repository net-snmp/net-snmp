/*
 * snmptsmsm.c
 *
 * This code merely does openssl initialization so that multilpe
 * modules are safe to call netsnmp_init_openssl() for bootstrapping
 * without worrying about other callers that may have already done so.
 */

#include <net-snmp/net-snmp-config.h>

#include <net-snmp/net-snmp-includes.h>

#if defined(NETSNMP_USE_OPENSSL) && defined(HAVE_LIBSSL)

#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <net-snmp/library/snmp_debug.h>
#include <net-snmp/library/snmp_openssl.h>

static u_char have_started_already = 0;

void netsnmp_init_openssl(void) {

    /* avoid duplicate calls */
    if (have_started_already)
        return;
    have_started_already = 1;

    DEBUGMSGTL(("snmp_openssl", "initializing\n"));

    /* Initializing OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
}

/** netsnmp_openssl_cert_get_name: get subject name field from cert
 * @internal
 */
/** instead of exposing this function, make helper functions for each
 * field, like netsnmp_openssl_cert_get_commonName, below */
static char *
netsnmp_openssl_cert_get_name(X509 *ocert, int which, char **buf, int *len,
                              int flags)
{
    X509_NAME       *osubj_name;
    int              space;
    char            *buf_ptr;

    if ((NULL == ocert) || ((buf && !len) || (len && !buf)))
        return NULL;

    osubj_name = X509_get_subject_name(ocert);
    if (NULL == osubj_name) {
        DEBUGMSGT(("openssl:cert:name", "no subject name!\n"));
        return NULL;
    }

    /** see if buf is big enough, or allocate buf if none specified */
    space = X509_NAME_get_text_by_NID(osubj_name, which, NULL, 0);
    if (-1 == space)
        return NULL;
    ++space; /* for NUL */
    if (buf && *buf) {
        if (*len < space)
            return NULL;
        buf_ptr = *buf;
    }
    else {
        buf_ptr = calloc(1,space);
        if (!buf_ptr)
            return NULL;
    }
    space = X509_NAME_get_text_by_NID(osubj_name, which, buf_ptr, space);
    if (len)
        *len = space;

    return buf_ptr;
}

/** netsnmp_openssl_cert_get_subjectName: get subject name field from cert
 */
char *
netsnmp_openssl_cert_get_subjectName(X509 *ocert, char **buf, int *len)
{
    X509_NAME       *osubj_name;
    int              space;
    char            *buf_ptr;

    if ((NULL == ocert) || ((buf && !len) || (len && !buf)))
        return NULL;

    osubj_name = X509_get_subject_name(ocert);
    if (NULL == osubj_name) {
        DEBUGMSGT(("openssl:cert:name", "no subject name!\n"));
        return NULL;
    }

    if (buf) {
        buf_ptr = *buf;
        space = *len;
    }
    else {
        buf_ptr = NULL;
        space = 0;
    }
    buf_ptr = X509_NAME_oneline(osubj_name, buf_ptr, space);
    if (len)
        *len = strlen(buf_ptr);

    return buf_ptr;
}

/** netsnmp_openssl_cert_get_commonName: get commonName for cert
 * if a pointer to a buffer and its length are specified, they will be
 * used. otherwise, a new buffer will be allocated, which the caller will
 * be responsbile for releasing.
 */
char *
netsnmp_openssl_cert_get_commonName(X509 *ocert, char **buf, int *len)
{
    return netsnmp_openssl_cert_get_name(ocert, NID_commonName, buf, len, 0);
}

/** netsnmp_openssl_cert_dump_name: dump subject names in cert
 */
void
netsnmp_openssl_cert_dump_names(X509 *ocert)
{
    int              i, onid;
    X509_NAME_ENTRY *oname_entry;
    X509_NAME       *osubj_name;
    const char      *prefix_short, *prefix_long;

    if (NULL == ocert)
        return;

    osubj_name = X509_get_subject_name(ocert);
    if (NULL == osubj_name) {
        DEBUGMSGT(("openssl:dump_names", "no subject name!\n"));
        return;
    }

    for (i = 0; i < X509_NAME_entry_count(osubj_name); i++) {
        oname_entry = X509_NAME_get_entry(osubj_name, i);
        netsnmp_assert(NULL != oname_entry);

        if (oname_entry->value->type != V_ASN1_PRINTABLESTRING)
            continue;

        /** get NID */
        onid = OBJ_obj2nid(oname_entry->object);
        if (onid == NID_undef) {
            prefix_long = prefix_short = "UNKNOWN";
        }
        else {
            prefix_long = OBJ_nid2ln(onid);
            prefix_short = OBJ_nid2sn(onid);
        }

        DEBUGMSGT(("9:openssl:dump_names",
                   "[%02d] NID type %d, ASN type %d\n", i, onid,
                   oname_entry->value->type));
        DEBUGMSGT(("openssl:dump_names", "%s/%s: '%s'\n", prefix_long,
                   prefix_short, ASN1_STRING_data(oname_entry->value)));
    }
}

#endif /* NETSNMP_USE_OPENSSL && HAVE_LIBSSL */
