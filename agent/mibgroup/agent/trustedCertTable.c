/*
 * Read-only access to OpenSSL trust locations on Linux.
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <time.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "trustedCertTable.h"

#define COLUMN_SUBJECT       2
#define COLUMN_ISSUER        3
#define COLUMN_SERIAL        4
#define COLUMN_FINGERPRINT   5
#define COLUMN_NOT_BEFORE    6
#define COLUMN_NOT_AFTER     7
#define COLUMN_SIGNATURE     8
#define COLUMN_SOURCE        9

struct trusted_cert_entry {
    struct trusted_cert_entry *next;
    unsigned char fingerprint[EVP_MAX_MD_SIZE];
    unsigned int fingerprint_len;
    char *subject;
    char *issuer;
    char *serial;
    char *not_before;
    char *not_after;
    char *signature;
    char *source;
};

static struct trusted_cert_entry *certs;
static time_t certs_loaded;

static netsnmp_variable_list *trusted_cert_next(
    void **loop_context, void **data_context, netsnmp_variable_list *index,
    netsnmp_iterator_info *iinfo);

static char *
bio_to_string(BIO *bio)
{
    char *data;
    long len = BIO_get_mem_data(bio, &data);
    char *result;

    if (len < 0)
        return NULL;
    result = malloc((size_t)len + 1);
    if (result) {
        memcpy(result, data, (size_t)len);
        result[len] = '\0';
    }
    return result;
}

static char *
name_string(const X509_NAME *name)
{
    BIO *bio = BIO_new(BIO_s_mem());
    char *result = NULL;

    if (bio && X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253) >= 0)
        result = bio_to_string(bio);
    BIO_free(bio);
    return result;
}

static char *
time_string(const ASN1_TIME *time)
{
    BIO *bio = BIO_new(BIO_s_mem());
    char *result = NULL;

    if (bio && ASN1_TIME_print(bio, time) == 1)
        result = bio_to_string(bio);
    BIO_free(bio);
    return result;
}

static int
fingerprint_seen(const unsigned char *fingerprint, unsigned int len)
{
    struct trusted_cert_entry *entry;

    for (entry = certs; entry; entry = entry->next) {
        if (entry->fingerprint_len == len &&
            memcmp(entry->fingerprint, fingerprint, len) == 0)
            return 1;
    }
    return 0;
}

static void
add_certificate(X509 *cert, const char *source)
{
    struct trusted_cert_entry *entry;
    ASN1_INTEGER *serial;
    BIGNUM *bn = NULL;
    char *hex = NULL;
    const char *signature;
    unsigned char fingerprint[EVP_MAX_MD_SIZE];
    unsigned int fingerprint_len;

    if (!X509_digest(cert, EVP_sha256(), fingerprint, &fingerprint_len) ||
        fingerprint_seen(fingerprint, fingerprint_len))
        return;

    entry = calloc(1, sizeof(*entry));
    if (!entry)
        return;
    memcpy(entry->fingerprint, fingerprint, fingerprint_len);
    entry->fingerprint_len = fingerprint_len;
    entry->subject = name_string(X509_get_subject_name(cert));
    entry->issuer = name_string(X509_get_issuer_name(cert));
    entry->not_before = time_string(X509_get0_notBefore(cert));
    entry->not_after = time_string(X509_get0_notAfter(cert));
    entry->source = strdup(source);

    serial = X509_get_serialNumber(cert);
    bn = ASN1_INTEGER_to_BN(serial, NULL);
    if (bn)
        hex = BN_bn2hex(bn);
    entry->serial = hex ? strdup(hex) : NULL;
    OPENSSL_free(hex);
    BN_free(bn);

    signature = OBJ_nid2ln(X509_get_signature_nid(cert));
    entry->signature = strdup(signature ? signature : "unknown");
    if (!entry->subject || !entry->issuer || !entry->serial ||
        !entry->not_before || !entry->not_after || !entry->source ||
        !entry->signature) {
        free(entry->subject);
        free(entry->issuer);
        free(entry->serial);
        free(entry->not_before);
        free(entry->not_after);
        free(entry->signature);
        free(entry->source);
        free(entry);
        return;
    }
    {
        struct trusted_cert_entry **position = &certs;

        while (*position &&
               memcmp((*position)->fingerprint, entry->fingerprint,
                      fingerprint_len) < 0)
            position = &(*position)->next;
        entry->next = *position;
        *position = entry;
    }
}

static void
read_certificate_file(const char *path)
{
    BIO *bio;
    X509 *cert;

    bio = BIO_new_file(path, "rb");
    if (!bio)
        return;
    while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        add_certificate(cert, path);
        X509_free(cert);
    }
    ERR_clear_error();
    BIO_free(bio);
}

static void
read_certificate_directory(const char *path)
{
    DIR *dir;
    struct dirent *dent;

    dir = opendir(path);
    if (!dir)
        return;
    while ((dent = readdir(dir)) != NULL) {
        char file[PATH_MAX];
        struct stat st;

        if (dent->d_name[0] == '.' ||
            snprintf(file, sizeof(file), "%s/%s", path, dent->d_name) >=
                (int)sizeof(file) ||
            stat(file, &st) != 0 || !S_ISREG(st.st_mode))
            continue;
        read_certificate_file(file);
    }
    closedir(dir);
}

static void
load_certificates(void)
{
    const char *file = getenv("SSL_CERT_FILE");
    const char *dirs = getenv("SSL_CERT_DIR");
    char *copy, *dir, *saveptr = NULL;

    if (!file || !*file)
        file = X509_get_default_cert_file();
    if (!dirs || !*dirs)
        dirs = X509_get_default_cert_dir();
    if (file && *file)
        read_certificate_file(file);
    if (!dirs || !*dirs)
        return;

    copy = strdup(dirs);
    if (!copy)
        return;
    for (dir = strtok_r(copy, ":", &saveptr); dir;
         dir = strtok_r(NULL, ":", &saveptr))
        read_certificate_directory(dir);
    free(copy);
}

static void
free_certificates(void)
{
    while (certs) {
        struct trusted_cert_entry *entry = certs;

        certs = entry->next;
        free(entry->subject);
        free(entry->issuer);
        free(entry->serial);
        free(entry->not_before);
        free(entry->not_after);
        free(entry->signature);
        free(entry->source);
        free(entry);
    }
}

static void
refresh_certificates(void)
{
    time_t now = time(NULL);

    if (certs_loaded && now != (time_t)-1 && now - certs_loaded < 300)
        return;
    free_certificates();
    load_certificates();
    certs_loaded = now;
}

static netsnmp_variable_list *
trusted_cert_first(void **loop_context, void **data_context,
                   netsnmp_variable_list *index, netsnmp_iterator_info *iinfo)
{
    refresh_certificates();
    *loop_context = certs;
    return trusted_cert_next(loop_context, data_context, index, iinfo);
}

static netsnmp_variable_list *
trusted_cert_next(void **loop_context, void **data_context,
                  netsnmp_variable_list *index, netsnmp_iterator_info *iinfo)
{
    struct trusted_cert_entry *entry = *loop_context;
    struct trusted_cert_entry *cursor;
    long number = 1;

    if (!entry)
        return NULL;
    for (cursor = certs; cursor != entry; cursor = cursor->next)
        number++;
    snmp_set_var_typed_integer(index, ASN_UNSIGNED, number);
    *data_context = entry;
    *loop_context = entry->next;
    return index;
}

static int
trusted_cert_handler(netsnmp_mib_handler *handler,
                     netsnmp_handler_registration *reginfo,
                     netsnmp_agent_request_info *reqinfo,
                     netsnmp_request_info *requests)
{
    netsnmp_request_info *request;

    for (request = requests; request; request = request->next) {
        struct trusted_cert_entry *entry =
            netsnmp_extract_iterator_context(request);
        netsnmp_table_request_info *table = netsnmp_extract_table_info(request);
        const char *value = NULL;

        if (!entry || !table) {
            netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHINSTANCE);
            continue;
        }
        switch (table->colnum) {
        case COLUMN_SUBJECT: value = entry->subject; break;
        case COLUMN_ISSUER: value = entry->issuer; break;
        case COLUMN_SERIAL: value = entry->serial; break;
        case COLUMN_FINGERPRINT:
            snmp_set_var_typed_value(request->requestvb, ASN_OCTET_STR,
                                     entry->fingerprint,
                                     entry->fingerprint_len);
            continue;
        case COLUMN_NOT_BEFORE: value = entry->not_before; break;
        case COLUMN_NOT_AFTER: value = entry->not_after; break;
        case COLUMN_SIGNATURE: value = entry->signature; break;
        case COLUMN_SOURCE: value = entry->source; break;
        default:
            netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHOBJECT);
            continue;
        }
        snmp_set_var_typed_value(request->requestvb, ASN_OCTET_STR,
                                 (const u_char *)value, strlen(value));
    }
    return SNMP_ERR_NOERROR;
}

void
init_trustedCertTable(void)
{
    static oid table_oid[] = { 1, 3, 6, 1, 4, 1, 8072, 1, 10, 1 };
    netsnmp_table_registration_info *table;
    netsnmp_iterator_info *iterator;
    netsnmp_handler_registration *registration;

    refresh_certificates();
    table = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);
    iterator = SNMP_MALLOC_TYPEDEF(netsnmp_iterator_info);
    registration = netsnmp_create_handler_registration(
        "nsTrustedCertificateTable", trusted_cert_handler, table_oid,
        OID_LENGTH(table_oid), HANDLER_CAN_RONLY);
    if (!table || !iterator || !registration) {
        free(table);
        free(iterator);
        netsnmp_handler_registration_free(registration);
        return;
    }
    netsnmp_table_helper_add_indexes(table, ASN_UNSIGNED, 0);
    table->min_column = COLUMN_SUBJECT;
    table->max_column = COLUMN_SOURCE;
    iterator->get_first_data_point = trusted_cert_first;
    iterator->get_next_data_point = trusted_cert_next;
    iterator->table_reginfo = table;
    netsnmp_register_table_iterator2(registration, iterator);
}
