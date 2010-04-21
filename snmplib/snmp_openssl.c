/*
 * snmp_openssl.c
 */

#include <net-snmp/net-snmp-config.h>

#include <net-snmp/net-snmp-includes.h>

#if defined(NETSNMP_USE_OPENSSL) && defined(HAVE_LIBSSL)

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

#include <net-snmp/library/snmp_debug.h>
#include <net-snmp/library/snmp_openssl.h>
#include <net-snmp/library/cert_util.h>

static u_char have_started_already = 0;

/*
 * This code merely does openssl initialization so that multilpe
 * modules are safe to call netsnmp_init_openssl() for bootstrapping
 * without worrying about other callers that may have already done so.
 */
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

void
netsnmp_openssl_cert_dump_extensions(X509 *ocert)
{
    X509_EXTENSION  *extension;
    const char      *extension_name;
    int              i, num_extensions;

    if (NULL == ocert)
        return;

    num_extensions = X509_get_ext_count(ocert);
    DEBUGMSGT(("openssl:dump:extension", "%02d extensions\n", num_extensions));
    for(i = 0; i < num_extensions; i++) {
        extension = X509_get_ext(ocert, i);
        extension_name =
            OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(extension)));
        DEBUGMSGT(("openssl:dump:extension",
                   "    %2d: %s\n", i, extension_name));
        if (0 == strcmp(extension_name, "subjectAltName")) {
            /* foo */
        }
    }
   
}

/**
 * returns allocated pointer caller must free.
 */
char *
netsnmp_openssl_cert_get_fingerprint(X509 *ocert, int alg)
{
    u_char           fingerprint[EVP_MAX_MD_SIZE];
    u_int            fingerprint_len;
    const EVP_MD    *digest;
    char            *result = NULL;

    switch (alg) {
        case NS_HASH_MD5:
            snmp_log(LOG_ERR, "hash type md5 not yet supported\n");
            return NULL;
            break;
        
        case NS_HASH_NONE:
            snmp_log(LOG_ERR, "hash type none not supported. using SHA1\n");
            /** fall through */

        case NS_HASH_SHA1:
            digest = EVP_sha1();
            break;

        case NS_HASH_SHA224:
            digest = EVP_sha224();
            break;

        case NS_HASH_SHA256:
            digest = EVP_sha256();
            break;

        case NS_HASH_SHA384:
            digest = EVP_sha384();
            break;

        case NS_HASH_SHA512:
            digest = EVP_sha512();
            break;

        default:
            snmp_log(LOG_ERR, "unknown hash algorithm %d\n", alg);
            return NULL;
    }

    if (X509_digest(ocert,digest,fingerprint,&fingerprint_len)) {
        binary_to_hex(fingerprint, fingerprint_len, &result);
        DEBUGMSGT(("openssl:fingerprint", "fingerprint %s\n", result));
    }
    else
        snmp_log(LOG_ERR,"failed to compute fingerprint\n");

    return result;
}

int
netsnmp_openssl_cert_issued_by(X509 *issuer, X509 *cert)
{
    return (X509_check_issued(issuer, cert) == X509_V_OK);
}


void
netsnmp_openssl_err_log(const char *prefix)
{
    unsigned long err;
    for (err = ERR_get_error(); err; err = ERR_get_error()) {
        snmp_log(LOG_ERR,"%s: %ld\n", prefix ? prefix: "openssl error", err);
        snmp_log(LOG_ERR, "library=%d, function=%d, reason=%d\n",
                 ERR_GET_LIB(err), ERR_GET_FUNC(err), ERR_GET_REASON(err));
    }
}

#endif /* NETSNMP_USE_OPENSSL && HAVE_LIBSSL */
