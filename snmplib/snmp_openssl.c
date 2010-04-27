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
#include <openssl/objects.h>

#include <net-snmp/library/snmp_debug.h>
#include <net-snmp/library/cert_util.h>
#include <net-snmp/library/snmp_openssl.h>

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
_cert_get_name(X509 *ocert, int which, char **buf, int *len, int flags)
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

/** netsnmp_openssl_cert_get_commonName: get commonName for cert.
 * if a pointer to a buffer and its length are specified, they will be
 * used. otherwise, a new buffer will be allocated, which the caller will
 * be responsbile for releasing.
 */
char *
netsnmp_openssl_cert_get_commonName(X509 *ocert, char **buf, int *len)
{
    return _cert_get_name(ocert, NID_commonName, buf, len, 0);
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

static char *
_cert_get_extension(X509_EXTENSION  *oext, char **buf, int *len, int flags)
{
    int              space;
    char            *buf_ptr = NULL;
    u_char          *data;
    BIO             *bio;
    
    if ((NULL == oext) || ((buf && !len) || (len && !buf)))
        return NULL;

    bio = BIO_new(BIO_s_mem());
    if (NULL == bio) {
        snmp_log(LOG_ERR, "could not get bio for extension\n");
        return NULL;
    }
    if (X509V3_EXT_print(bio, oext, 0, 0) != 1) {
        snmp_log(LOG_ERR, "could not print extension!\n");
        BIO_vfree(bio);
        return NULL;
    }

    space = BIO_get_mem_data(bio, &data);
    if (buf && *buf) {
        if (*len < space) 
            buf_ptr = NULL;
        else
            buf_ptr = *buf;
    }
    else
        buf_ptr = calloc(1,space);
    
    if (!buf_ptr) {
        snmp_log(LOG_ERR,
                 "not enough space or error in allocation for extenstion\n");
        BIO_vfree(bio);
        return NULL;
    }
    memcpy(buf_ptr, data, space);
    buf_ptr[space] = 0;
    if (len)
        *len = space;

    BIO_vfree(bio);

    return buf_ptr;
}

/** netsnmp_openssl_cert_get_extension: get extension field from cert
 * @internal
 */
/** instead of exposing this function, make helper functions for each
 * field, like netsnmp_openssl_cert_get_subjectAltName, below */
static char *
_cert_get_extension_at(X509 *ocert, int pos, char **buf, int *len, int flags)
{
    X509_EXTENSION  *oext;

    if ((NULL == ocert) || ((buf && !len) || (len && !buf)))
        return NULL;

    oext = X509_get_ext(ocert,pos);
    if (NULL == oext) {
        snmp_log(LOG_ERR, "extension number %d not found!\n", pos);
        netsnmp_openssl_cert_dump_extensions(ocert);
        return NULL;
    }

    return _cert_get_extension(oext, buf, len, flags);
}

/** netsnmp_openssl_cert_get_extension: get extension field from cert
 * @internal
 */
/** instead of exposing this function, make helper functions for each
 * field, like netsnmp_openssl_cert_get_subjectAltName, below */
static char *
_cert_get_extension_id(X509 *ocert, int which, char **buf, int *len, int flags)
{
    int pos;

    if ((NULL == ocert) || ((buf && !len) || (len && !buf)))
        return NULL;

    pos = X509_get_ext_by_NID(ocert,which,-1);
    if (pos < 0) {
        DEBUGMSGT(("openssl:cert:name", "no extension %d\n", which));
        return NULL;
    }

    return _cert_get_extension_at(ocert, pos, buf, len, flags);
}

/** netsnmp_openssl_cert_get_subjectAltName: get subjectAltName for cert.
 * if a pointer to a buffer and its length are specified, they will be
 * used. otherwise, a new buffer will be allocated, which the caller will
 * be responsbile for releasing.
 */
char *
netsnmp_openssl_cert_get_subjectAltName(X509 *ocert, char **buf, int *len)
{
    return _cert_get_extension_id(ocert, NID_subject_alt_name, buf, len, 0);
}

void
netsnmp_openssl_cert_dump_extensions(X509 *ocert)
{
    X509_EXTENSION  *extension;
    const char      *extension_name;
    char             buf[SNMP_MAXBUF_SMALL], *buf_ptr = buf, *str;
    int              i, num_extensions, buf_len;

    if (NULL == ocert)
        return;

    num_extensions = X509_get_ext_count(ocert);
    DEBUGMSGT(("openssl:dump:extension", "%02d extensions\n", num_extensions));
    for(i = 0; i < num_extensions; i++) {
        extension = X509_get_ext(ocert, i);
        extension_name =
            OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(extension)));
        buf_len = sizeof(buf);
        str = _cert_get_extension_at(ocert, i, &buf_ptr, &buf_len, 0);
        DEBUGMSGT(("openssl:dump:extension",
                   "    %2d: %s = %s\n", i, extension_name, str));
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
        if (NULL == result)
            snmp_log(LOG_ERR, "failed to hexify fingerprint\n");
        else
            DEBUGMSGT(("openssl:fingerprint", "fingerprint %s\n", result));
    }
    else
        snmp_log(LOG_ERR,"failed to compute fingerprint\n");

    return result;
}

/**
 * get container of netsnmp_cert_map structures from an ssl connection
 * certificate chain.
 */
netsnmp_container *
netsnmp_openssl_get_cert_chain(SSL *ssl)
{
    X509                  *ocert, *ocert_tmp;
    STACK_OF(X509)        *ochain;
    char                  *fingerprint;
    netsnmp_container     *chain_map;
    netsnmp_cert_map      *cert_map;
    int                    i;

    netsnmp_assert_or_return(ssl != NULL, NULL);
    
    if (NULL == (ocert = SSL_get_peer_certificate(ssl))) {
        /** no peer cert */
        snmp_log(LOG_ERR, "SSL peer has no certificate\n");
        return NULL;
    }
    DEBUGIF("openss:dump:extensions") {
        netsnmp_openssl_cert_dump_extensions(ocert);
    }

    /*
     * get fingerprint and save it
     */
    fingerprint = netsnmp_openssl_cert_get_fingerprint(ocert, NS_HASH_SHA1);
    if (NULL == fingerprint)
        return NULL;

    /*
     * allocate cert map. Don't pass in fingerprint, since it would strdup
     * it and we've already got a copy.
     */
    cert_map = netsnmp_cert_map_alloc(NULL, ocert);
    if (NULL == cert_map) {
        free(fingerprint);
        return NULL;
    }
    cert_map->fingerprint = fingerprint;

    chain_map = netsnmp_cert_map_container_create(0); /* no fp subcontainer */
    if (NULL == chain_map) {
        netsnmp_cert_map_free(cert_map);
        return NULL;
    }
    
    CONTAINER_INSERT(chain_map, cert_map);

    /** check for a chain to a CA */
    ochain = SSL_get_peer_cert_chain(ssl);
    if ((NULL == ochain) || (0 == ochain->num)) {
        DEBUGMSGT(("ssl:cert:chain", "peer has no cert chain\n"));
    }
    else {
        /*
         * loop over chain, adding fingerprint / cert for each
         */
        DEBUGMSGT(("ssl:cert:chain", "examining cert chain\n"));
        for(i = 0; i < ochain->num; ++i) {
            ocert_tmp = (X509*)ochain->data[i];
            fingerprint = netsnmp_openssl_cert_get_fingerprint(ocert_tmp,
                                                               NS_HASH_SHA1);
            if (NULL == fingerprint)
                break;
            cert_map = netsnmp_cert_map_alloc(NULL, ocert);
            if (NULL == cert_map) {
                free(fingerprint);
                break;
            }
            cert_map->fingerprint = fingerprint;
            CONTAINER_INSERT(chain_map, cert_map);
        } /* chain loop */
        /*
         * if we broke out of loop before finishing, clean up
         */
        if (i < ochain->num) 
            CONTAINER_FREE_ALL(chain_map, NULL);
    } /* got peer chain */

    DEBUGMSGT(("ssl:cert:chain", "found %" NETSNMP_PRIz "u certs in chain\n",
               CONTAINER_SIZE(chain_map)));
    if (CONTAINER_SIZE(chain_map) == 0) {
        CONTAINER_FREE(chain_map);
        chain_map = NULL;
    }

    return chain_map;
}

/*
tlstmCertSANRFC822Name "Maps a subjectAltName's rfc822Name to a
                  tmSecurityName.  The local part of the rfc822Name is
                  passed unaltered but the host-part of the name must
                  be passed in lower case.
                  Example rfc822Name Field:  FooBar@Example.COM
                  is mapped to tmSecurityName: FooBar@example.com"

tlstmCertSANDNSName "Maps a subjectAltName's dNSName to a
                  tmSecurityName after first converting it to all
                  lower case."

tlstmCertSANIpAddress "Maps a subjectAltName's iPAddress to a
                  tmSecurityName by transforming the binary encoded
                  address as follows:
                  1) for IPv4 the value is converted into a decimal
                     dotted quad address (e.g. '192.0.2.1')
                  2) for IPv6 addresses the value is converted into a
                     32-character all lowercase hexadecimal string
                     without any colon separators.

                     Note that the resulting length is the maximum
                     length supported by the View-Based Access Control
                     Model (VACM).  Note that using both the Transport
                     Security Model's support for transport prefixes
                     (see the SNMP-TSM-MIB's
                     snmpTsmConfigurationUsePrefix object for details)
                     will result in securityName lengths that exceed
                     what VACM can handle."

tlstmCertSANAny "Maps any of the following fields using the
                  corresponding mapping algorithms:
                  | rfc822Name | tlstmCertSANRFC822Name |
                  | dNSName    | tlstmCertSANDNSName    |
                  | iPAddress  | tlstmCertSANIpAddress  |
                  The first matching subjectAltName value found in the
                  certificate of the above types MUST be used when
                  deriving the tmSecurityName."
*/
static int
_san_reduce(char *san, int mapType)
{
    char *pos = san, *data, *lower;
    size_t segment_len;

    while(pos && *pos) {
        data = strchr(pos, ':');
        if (NULL == data) {
            snmp_log(LOG_ERR,"cant find ':' in SAN '%s'\n", pos);
            return -1;
        }
        ++data;
        segment_len = strcspn(data, ", ");
        if (segment_len)
            data[segment_len] = '\0';
        lower = NULL;

        if (strncmp(pos,"DNS:",4) == 0) {
            if ((TSNM_tlstmCertSANDNSName == mapType) ||
                (TSNM_tlstmCertSANAny == mapType)) {
                lower = data;
                break;
            }
        }
        else if ((strncmp(pos,"IP:",3) == 0) ||
                 (strncmp(pos,"IP Address:",11) == 0)) {
            if ((TSNM_tlstmCertSANIpAddress == mapType) ||
                (TSNM_tlstmCertSANAny == mapType))
                break;
        }
        else if (strncmp(pos,"email:",4) == 0) {
            if ((TSNM_tlstmCertSANRFC822Name == mapType) ||
                (TSNM_tlstmCertSANAny == mapType)) {
                lower = strchr(data, '@');
                if (NULL == lower) {
                    DEBUGMSGT(("openssl:secname:extract",
                               "host name %s has no '@'!\n", data));
                }
                else {
                    ++lower;
                    break;
                }
            }
        }
        else
            DEBUGMSGT(("openssl:secname:extract", "unknown SAN\n"));
        pos = data + segment_len + 1;
        while( *pos && ((' ' == *pos) || (',' == *pos)))
            ++pos;
    }

    if (*pos) {
        if (lower)
            for ( ; *lower; ++lower )
                if (isascii(*lower))
                    *lower = tolower(*lower);
        memmove(san, data, segment_len);
        san[segment_len] = 0;

        return 0;
    }

    return -1;
}

char *
netsnmp_openssl_extract_secname(netsnmp_cert_map *cert_map,
                                netsnmp_cert_map *peer_cert)
{
    char       *san;

    if (NULL == cert_map)
        return NULL;

    switch(cert_map->mapType) {
        case TSNM_tlstmCertSpecified:
            return strdup(cert_map->data);

        case TSNM_tlstmCertSANRFC822Name:
        case TSNM_tlstmCertSANDNSName:
        case TSNM_tlstmCertSANIpAddress:
        case TSNM_tlstmCertSANAny:
            if (NULL == peer_cert) {
                DEBUGMSGT(("openssl:secname:extract", "no peer cert for %s\n",
                           cert_map->fingerprint));
                return NULL;
            }
            san = netsnmp_openssl_cert_get_subjectAltName(peer_cert->ocert,
                                                          NULL, 0);
            if (NULL == san) {
                DEBUGMSGT(("openssl:secname:extract", "no san for %s\n",
                           peer_cert->fingerprint));
                return NULL;
            }
            if (_san_reduce(san, cert_map->mapType)) {
                free(san);
                DEBUGMSGT(("openssl:secname:extract",
                           "no san of type %d for %s\n",
                           cert_map->mapType, peer_cert->fingerprint));
                return NULL;
            }
            return san;
            break;

        case TSNM_tlstmCertCommonName:
            return netsnmp_openssl_cert_get_commonName(cert_map->ocert, NULL,
                                                       NULL);
        default:
            snmp_log(LOG_ERR, "cant extract secname for unknown map type %d\n",
                     cert_map->mapType);
            break;
    } /* switch mapType */

    return NULL;
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
