#include <net-snmp/net-snmp-config.h>

#if defined(NETSNMP_USE_OPENSSL) && defined(HAVE_LIBSSL)

#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#if HAVE_SYS_STAT_H
#   include <sys/stat.h>
#endif
#if HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include <net-snmp/types.h>
#include <net-snmp/output_api.h>
#include <net-snmp/config_api.h>

#include <net-snmp/library/snmp_assert.h>
#include <net-snmp/library/snmp_transport.h>
#include <net-snmp/library/system.h>
#include <net-snmp/library/tools.h>
#include <net-snmp/library/callback.h>
#include <net-snmp/library/container.h>
#include <net-snmp/library/data_list.h>
#include <net-snmp/library/file_utils.h>
#include <net-snmp/library/dir_utils.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <net-snmp/library/snmp_openssl.h>
#include <net-snmp/library/cert_util.h>

static netsnmp_container *_certs = NULL;
static netsnmp_container *_keys = NULL;
static struct snmp_enum_list *_certindexes = NULL;

static void _cert_indexes_load(void);
static void _cert_free(netsnmp_cert *cert, void *context);
static void _key_free(netsnmp_key *key, void *context);
static int  _cert_compare(netsnmp_cert *lhs, netsnmp_cert *rhs);
static int  _cert_cn_compare(netsnmp_cert *lhs, netsnmp_cert *rhs);
static int  _cert_fn_compare(netsnmp_cert_common *lhs,
                             netsnmp_cert_common *rhs);
static int  _cert_fn_ncompare(netsnmp_cert_common *lhs,
                              netsnmp_cert_common *rhs);
static void _find_partner(netsnmp_cert *cert, netsnmp_key *key);
static netsnmp_cert *_cert_find_fp(const char *fingerprint);
static const char *_mode_str(u_char mode);
static const char *_where_str(u_int what);

void netsnmp_cert_free(netsnmp_cert *cert);
void netsnmp_key_free(netsnmp_key *key);

static int _certindex_add( const char *dirname, int i );

static int _time_filter(netsnmp_file *f, struct stat *idx);

/** mode descriptions should match up with header */
static const char _modes[][256] =
        {
            "none", "identity", "remote_peer",
            "identity+remote_peer", "reserved1",
            "reserved1+identity", "reserved1+remote_peer",
            "reserved1+identity+remote_peer", "reserved2"
        };

/* #####################################################################
 *
 * init and shutdown functions
 *
 */
void
netsnmp_certs_init(void)
{
    netsnmp_container *additional_keys;
    netsnmp_iterator  *itr;
    netsnmp_key        *key;

    DEBUGMSGT(("cert:util:init","init\n"));

    if (NULL != _certs) {
        DEBUGMSGT(("cert:util:init", "ignoring duplicate init\n"));
        return;
    }

    netsnmp_init_openssl();

    _certs = netsnmp_container_find("certs:binary_array");
    if (NULL == _certs) {
        snmp_log(LOG_ERR, "could not create container for certificates\n");
        return;
    }
    _certs->container_name = strdup("netsnmp certificates");
    _certs->free_item = (netsnmp_container_obj_func*)_cert_free;
    _certs->compare = (netsnmp_container_compare*)_cert_compare;

    /** additional keys: common name */
    additional_keys = netsnmp_container_find("certs_cn:binary_array");
    if (NULL == additional_keys) {
        snmp_log(LOG_ERR, "could not create CN container for certificates\n");
        netsnmp_certs_shutdown();
        CONTAINER_FREE_ALL(_certs, NULL);
        return;
    }
    additional_keys->container_name = strdup("certs_cn");
    additional_keys->free_item = NULL;
    additional_keys->compare = (netsnmp_container_compare*)_cert_cn_compare;
    netsnmp_container_add_index(_certs, additional_keys);

    /** additional keys: file name */
    additional_keys = netsnmp_container_find("certs_fn:binary_array");
    if (NULL == additional_keys) {
        snmp_log(LOG_ERR, "could not create FN container for certificates\n");
        netsnmp_certs_shutdown();
        CONTAINER_FREE_ALL(_certs, NULL);
        return;
    }
    additional_keys->container_name = strdup("certs_fn");
    additional_keys->free_item = NULL;
    additional_keys->compare = (netsnmp_container_compare*)_cert_fn_compare;
    additional_keys->ncompare = (netsnmp_container_compare*)_cert_fn_ncompare;
    netsnmp_container_add_index(_certs, additional_keys);

    _keys = netsnmp_container_find("cert_keys:binary_array");
    if (NULL == _keys) {
        snmp_log(LOG_ERR, "could not create container for certificate keys\n");
        CONTAINER_FREE_ALL(_certs, NULL);
        return;
    }
    _keys->container_name = strdup("netsnmp certificate keys");
    _keys->free_item = (netsnmp_container_obj_func*)_key_free;
    _keys->compare = (netsnmp_container_compare*)_cert_fn_compare;


    /** scan config dirs for certs */
    _cert_indexes_load();

    /** match up keys w/certs */
    itr = CONTAINER_ITERATOR(_keys);
    if (NULL == itr) {
        snmp_log(LOG_ERR, "could not get iterator for keys\n");
        CONTAINER_FREE_ALL(_certs, NULL);
        CONTAINER_FREE_ALL(_keys, NULL);
        CONTAINER_FREE(_certs);
        CONTAINER_FREE_ALL(_keys, NULL);
        CONTAINER_FREE(_keys);
        _certs = _keys = NULL;
        return;
    }
    key = ITERATOR_FIRST(itr);
    for( ; key; key = ITERATOR_NEXT(itr))
        _find_partner(NULL, key);
    ITERATOR_RELEASE(itr);
}

void
netsnmp_certs_shutdown(void)
{
    DEBUGMSGT(("cert:util:shutdown","shutdown\n"));
    CONTAINER_FREE_ALL(_certs, NULL);
    CONTAINER_FREE(_certs);
    CONTAINER_FREE_ALL(_keys, NULL);
    CONTAINER_FREE(_keys);
    _certs = _keys = NULL;
}

/* #####################################################################
 *
 * cert container functions
 */

static netsnmp_cert *
_new_cert(const char *dirname, const char *filename, int type,
          const char *fingerprint, const char *common_name)
{
    netsnmp_cert    *cert;

    if ((NULL == dirname) || (NULL == filename)) {
        snmp_log(LOG_ERR, "bad parameters to _new_cert\n");
        return NULL;
    }

    cert = SNMP_MALLOC_TYPEDEF(netsnmp_cert);
    if (NULL == cert) {
        snmp_log(LOG_ERR,"could not allocate memory for certificate at %s/%s\n",
                 dirname, filename);
        return NULL;
    }

    DEBUGMSGT(("cert:struct:new","new cert 0x%#lx for %s\n", (u_long)cert,
                  filename));

    cert->info.dir = strdup(dirname);
    cert->info.filename = strdup(filename);
    cert->info.allowed_uses = NS_CERT_REMOTE_PEER;
    cert->info.type = type;
    if (fingerprint)
        cert->fingerprint = strdup(fingerprint);
    if (common_name)
        cert->common_name = strdup(common_name);

    return cert;
    }

static netsnmp_key *
_new_key(const char *dirname, const char *filename)
{
    netsnmp_key    *key;

    if ((NULL == dirname) || (NULL == filename)) {
        snmp_log(LOG_ERR, "bad parameters to _new_key\n");
        return NULL;
    }

    key = SNMP_MALLOC_TYPEDEF(netsnmp_key);
    if (NULL == key) {
        snmp_log(LOG_ERR,"could not allocate memory for keyificate at %s/%s\n",
                 dirname, filename);
        return NULL;
    }

    DEBUGMSGT(("cert:key:struct:new","new key 0x%#lx for %s\n", (u_long)key,
                  filename));

    key->info.dir = strdup(dirname);
    key->info.filename = strdup(filename);
    key->info.allowed_uses = NS_CERT_IDENTITY;

    return key;
}

void
netsnmp_cert_free(netsnmp_cert *cert)
{
    if (NULL == cert)
        return;

    DEBUGMSGT(("cert:struct:free","freeing cert 0x%#lx, %s (fp %s; CN %s)\n",
               (u_long)cert, cert->info.filename ? cert->info.filename : "UNK",
               cert->fingerprint ? cert->fingerprint : "UNK",
               cert->common_name ? cert->common_name : "UNK"));

    SNMP_FREE(cert->info.dir);
    SNMP_FREE(cert->info.filename);
    SNMP_FREE(cert->fingerprint);
    SNMP_FREE(cert->common_name);
    SNMP_FREE(cert->san_rfc822);
    SNMP_FREE(cert->san_ipaddr);
    SNMP_FREE(cert->san_dnsname);
    X509_free(cert->ocert);
    if (cert->key && cert->key->cert == cert)
        cert->key->cert = NULL;

    free(cert); /* SNMP_FREE not needed on parameters */
}

void
netsnmp_key_free(netsnmp_key *key)
{
    if (NULL == key)
        return;

    DEBUGMSGT(("cert:key:struct:free","freeing key 0x%#lx, %s\n",
               (u_long)key, key->info.filename ? key->info.filename : "UNK"));

    SNMP_FREE(key->info.dir);
    SNMP_FREE(key->info.filename);
    EVP_PKEY_free(key->okey);
    if (key->cert && key->cert->key == key)
        key->cert->key = NULL;

    free(key); /* SNMP_FREE not needed on parameters */
}

static void
_cert_free(netsnmp_cert *cert, void *context)
{
    netsnmp_cert_free(cert);
}

static void
_key_free(netsnmp_key *key, void *context)
{
    netsnmp_key_free(key);
}

static int
_cert_compare(netsnmp_cert *lhs, netsnmp_cert *rhs)
{
    netsnmp_assert((lhs != NULL) && (rhs != NULL));
    netsnmp_assert((lhs->fingerprint != NULL) &&
                   (rhs->fingerprint != NULL));

    return strcmp(lhs->fingerprint, rhs->fingerprint);
}

static int
_cert_path_compare(netsnmp_cert_common *lhs, netsnmp_cert_common *rhs)
{
    int rc;

    netsnmp_assert((lhs != NULL) && (rhs != NULL));
    
    /** dir name first */
    rc = strcmp(lhs->dir, rhs->dir);
    if (rc)
        return rc;

    /** filename */
    return strcmp(lhs->filename, rhs->filename);
}

static int
_cert_cn_compare(netsnmp_cert *lhs, netsnmp_cert *rhs)
{
    int rc;
    const char *lhcn, *rhcn;

    netsnmp_assert((lhs != NULL) && (rhs != NULL));

    if (NULL == lhs->common_name)
        lhcn = "";
    else
        lhcn = lhs->common_name;
    if (NULL == rhs->common_name)
        rhcn = "";
    else
        rhcn = rhs->common_name;

    rc = strcmp(lhcn, rhcn);
    if (rc)
        return rc;

    /** in case of equal common names, sub-sort by path */
    return _cert_path_compare((netsnmp_cert_common*)lhs,
                              (netsnmp_cert_common*)rhs);
}

static int
_cert_fn_compare(netsnmp_cert_common *lhs, netsnmp_cert_common *rhs)
{
    int rc;

    netsnmp_assert((lhs != NULL) && (rhs != NULL));

    rc = strcmp(lhs->filename, rhs->filename);
    if (rc)
        return rc;

    /** in case of equal common names, sub-sort by dir */
    return strcmp(lhs->dir, rhs->dir);
}

static int
_cert_fn_ncompare(netsnmp_cert_common *lhs, netsnmp_cert_common *rhs)
{
    netsnmp_assert((lhs != NULL) && (rhs != NULL));
    netsnmp_assert((lhs->filename != NULL) && (rhs->filename != NULL));

    return strncmp(lhs->filename, rhs->filename, strlen(rhs->filename));
}


/*
 * filter functions; return 1 to include file, 0 to exclude
 */

static int
_cert_ext_type(const char *ext)
{
    if ('p' == *ext) {
        if (strcmp(ext,"pem") == 0)
            return NS_CERT_TYPE_PEM;
        if (strcmp(ext,"p12") == 0)
            return NS_CERT_TYPE_PKCS12;
    }
    else if (('d' == *ext) && (strcmp(ext,"der") == 0))
        return NS_CERT_TYPE_DER;
    else if ('c' == *ext) {
        if (strcmp(ext,"crt") == 0)
            return NS_CERT_TYPE_DER;
        if (strcmp(ext,"cer") == 0)
            return NS_CERT_TYPE_DER;
    }
    else if ('k' == *ext) {
        if (strcmp(ext,"key") == 0)
            return NS_CERT_TYPE_KEY;
    }

    return NS_CERT_TYPE_UNKNOWN;
}

static int
_cert_cert_filter(const char *filename)
{
    int  len = strlen(filename);
    const char *pos;

    if (len < 5) /* shortest name: x.YYY */
        return 0;

    pos = &filename[len-4];
    if (*pos++ != '.')
        return 0;

    if (_cert_ext_type(pos) != NS_CERT_TYPE_UNKNOWN)
        return 1;

    return 0;
}

/* #####################################################################
 *
 * cert index functions
 *
 * This code mimics what the mib index code does. The persistent
 * directory will have a subdirectory named 'cert_indexes'. Inside
 * this directory will be some number of files with ascii numeric
 * names (0, 1, 2, etc). Each of these files will start with a line
 * with the text "DIR ", followed by a directory name. The rest of the
 * file will be certificate fields and the certificate file name, one
 * certificate per line. The numeric file name is the integer 'directory
 * index'.
 */

/**
 * _certindex_add
 *
 * add a directory name to the indexes
 */
static int
_certindex_add( const char *dirname, int i )
{
    int rc;
    char *dirname_copy = strdup(dirname);

    if ( i == -1 ) {
        int max = se_find_free_value_in_list(_certindexes);
        if (SE_DNE == max)
            i = 0;
        else
            i = max;
    }

    DEBUGMSGT(("cert:index:add","dir %s at index %d\n", dirname, i ));
    rc = se_add_pair_to_list(&_certindexes, dirname_copy, i);
    if (SE_OK != rc) {
        snmp_log(LOG_ERR, "adding certindex dirname failed; "
                 "%d (%s) not added\n", i, dirname);
        free(dirname_copy);
        return -1;
    }

    return i;
}

/**
 * _certindex_load
 *
 * read in the existing indexes
 */
static void
_certindexes_load( void )
{
    DIR *dir;
    struct dirent *file;
    FILE *fp;
    char filename[SNMP_MAXPATH];
    char line[300];
    int  i;
    char *cp;

    /*
     * Open the CERT index directory, or create it (empty)
     */
    snprintf( filename, sizeof(filename), "%s/cert_indexes",
              get_persistent_directory());
    filename[sizeof(filename)-1] = 0;
    dir = opendir( filename );
    if ( dir == NULL ) {
        DEBUGMSGT(("cert:index:load", "creating new cert_indexes directory\n"));
        mkdirhier( filename, NETSNMP_AGENT_DIRECTORY_MODE, 0);
        return;
    }

    /*
     * Create a list of which directory each file refers to
     */
    while ((file = readdir( dir ))) {
        if ( !isdigit(file->d_name[0]))
            continue;
        i = atoi( file->d_name );

        snprintf( filename, sizeof(filename), "%s/cert_indexes/%d",
              get_persistent_directory(), i );
        filename[sizeof(filename)-1] = 0;
        fp = fopen( filename, "r" );
        if ( !fp ) {
            DEBUGMSGT(("cert:index:load", "error opening index (%d)\n", i));
            fclose(fp);
            continue;
        }
        cp = fgets( line, sizeof(line), fp );
        if ( cp ) {
            line[strlen(line)-1] = 0;
            DEBUGMSGT(("cert:index:load","adding (%d) %s\n", i, line));
            (void)_certindex_add( line+4, i );  /* Skip 'DIR ' */
        } else {
            DEBUGMSGT(("cert:index:load", "Empty index (%d)\n", i));
        }
        fclose( fp );
    }
    closedir( dir );
}

/**
 * _certindex_lookup
 *
 * find index for a directory
 */
static char *
_certindex_lookup( const char *dirname )
{
    int i;
    char filename[SNMP_MAXPATH];

    i = se_find_value_in_list(_certindexes, dirname);
    if (SE_DNE == i) {
        DEBUGMSGT(("cert:index:lookup","%s : (none)\n", dirname));
        return NULL;
    }

    snprintf(filename, sizeof(filename), "%s/cert_indexes/%d",
             get_persistent_directory(), i);
    filename[sizeof(filename)-1] = 0;
    DEBUGMSGT(("cert:index:lookup", "%s (%d) %s\n", dirname, i, filename ));
    return strdup(filename);
}

static FILE *
_certindex_new( const char *dirname )
{
    FILE *fp;
    char  filename[SNMP_MAXPATH], *cp;
    int   i;

    cp = _certindex_lookup( dirname );
    if (!cp) {
        i  = _certindex_add( dirname, -1 );
        if (-1 == i)
            return NULL; /* msg already logged */
        snprintf( filename, sizeof(filename), "%s/cert_indexes/%d",
                  get_persistent_directory(), i );
        filename[sizeof(filename)-1] = 0;
        cp = filename;
    }
    DEBUGMSGT(("cert:index:new", "%s (%s)\n", dirname, cp ));
    fp = fopen( cp, "w" );
    if (fp)
        fprintf( fp, "DIR %s\n", dirname );
    else
        snmp_log(LOG_ERR, "error opening new index file %s\n", dirname);

    if (cp != filename)
        free(cp);

    return fp;
}

/* #####################################################################
 *
 * certificate utility functions
 *
 */
static X509 *
netsnmp_ocert_get(netsnmp_cert *cert)
{
    BIO            *certbio;
    X509           *ocert = NULL;
    char            file[SNMP_MAXPATH];

    if (NULL == cert)
        return NULL;

    if (cert->ocert)
        return cert->ocert;

    snprintf(file, sizeof(file),"%s/%s", cert->info.dir, cert->info.filename);
    DEBUGMSGT(("cert:read", "Checking file %s\n", cert->info.filename));

    certbio = BIO_new(BIO_s_file());
    if (NULL == certbio) {
        snmp_log(LOG_ERR, "error creating BIO\n");
        return NULL;
    }

    if (BIO_read_filename(certbio, file) <=0) {
        snmp_log(LOG_ERR, "error reading certificate %s into BIO\n", file);
        BIO_vfree(certbio);
        return NULL;
    }

    if (NS_CERT_TYPE_UNKNOWN == cert->info.type) {
        int len = strlen(cert->info.filename);
        netsnmp_assert(cert->info.filename[len-4] == '.');
        cert->info.type = _cert_ext_type(&cert->info.filename[len-3]);
        netsnmp_assert(cert->info.type != NS_CERT_TYPE_UNKNOWN);
    }

    if (NS_CERT_TYPE_PEM == cert->info.type)
        ocert = PEM_read_bio_X509_AUX(certbio, NULL, NULL, NULL); /* PEM */
    else if (NS_CERT_TYPE_DER == cert->info.type)
        ocert = d2i_X509_bio(certbio,NULL); /* DER/ASN1 */
#ifdef CERT_PKCS12_SUPPORT_MAYBE_LATER
    else if (NS_CERT_TYPE_PKCS12 == cert->info.type) {
        (void)BIO_reset(certbio);
        PKCS12 *p12 = d2i_PKCS12_bio(certbio, NULL);
        if ( (NULL != p12) && (PKCS12_verify_mac(p12, "", 0) ||
                               PKCS12_verify_mac(p12, NULL, 0)))
            PKCS12_parse(p12, "", NULL, &cert, NULL);
    }
#endif

    else
        snmp_log(LOG_ERR, "unknown certificate type %d for %s\n",
                 cert->info.type, cert->info.filename);
 
    BIO_vfree(certbio);

    if (NULL == ocert) {
        snmp_log(LOG_ERR, "error parsing certificate file %s\n",
                 cert->info.filename);
        return NULL;
    }

    cert->ocert = ocert;

    if (NULL == cert->fingerprint) {
        cert->fingerprint = netsnmp_openssl_cert_get_fingerprint(ocert,
                                                                 NS_HASH_SHA1);
        cert->hash_type = NS_HASH_SHA1;
    }
    
    if (NULL == cert->common_name) {
        cert->common_name =netsnmp_openssl_cert_get_commonName(ocert, NULL,
                                                               NULL);
        DEBUGMSGT(("cert:add:name","%s\n", cert->common_name));
    }
    /* X509_NAME_oneline(X509_get_subject_name(x),buf,sizeof buf); */
/*
  STACK *emlst;
  if (email == i)
  emlst = X509_get1_email(x);
  else
  emlst = X509_get1_ocsp(x);
  for (j = 0; j < sk_num(emlst); j++)
  BIO_printf(STDout, "%s\n", sk_value(emlst, j));
  X509_email_free(emlst);
*/

    return ocert;
}

EVP_PKEY *
netsnmp_okey_get(netsnmp_key  *key)
{
    BIO            *keybio;
    EVP_PKEY       *okey;
    char            file[SNMP_MAXPATH];

    if (NULL == key)
        return NULL;

    if (key->okey)
        return key->okey;

    snprintf(file, sizeof(file),"%s/%s", key->info.dir, key->info.filename);
    DEBUGMSGT(("cert:key:read", "Checking file %s\n", key->info.filename));

    keybio = BIO_new(BIO_s_file());
    if (NULL == keybio) {
        snmp_log(LOG_ERR, "error creating BIO\n");
        return NULL;
    }

    if (BIO_read_filename(keybio, file) <=0) {
        snmp_log(LOG_ERR, "error reading certificate %s into BIO\n",
                 key->info.filename);
        BIO_vfree(keybio);
        return NULL;
    }

    okey = PEM_read_bio_PrivateKey(keybio, NULL, NULL, NULL);
    if (NULL == okey)
        snmp_log(LOG_ERR, "error parsing certificate file %s\n",
                 key->info.filename);
    else
        key->okey = okey;

    BIO_vfree(keybio);

    return okey;
}

static void
_find_partner(netsnmp_cert *cert, netsnmp_key *key)
{
    netsnmp_container  *fn_container;
;
    netsnmp_void_array *matching;
    netsnmp_cert_common search;
    char                filename[NAME_MAX];
    int                 len;


    if ((cert && key) || (!cert && ! key)) {
        DEBUGMSGT(("cert:partner", "bad parameters searching for partner\n"));
        return;
    }

    if(key) {
        fn_container = SUBCONTAINER_FIND(_certs, "certs_fn");
        netsnmp_assert(fn_container);
        if (key->cert) {
            DEBUGMSGT(("cert:partner", "key already has partner\n"));
            return;
        }
        DEBUGMSGT(("cert:partner", "looking for key partner for %s\n",
                   key->info.filename));
        len = snprintf(filename, sizeof(filename), "%s", key->info.filename);
        if ('.' != filename[len-4])
            return;
        filename[len-3] = 0;
        search.filename = filename;
        matching = CONTAINER_GET_SUBSET(fn_container, &search);
        if (!matching)
            return;
        if (1 == matching->size) {
            cert = (netsnmp_cert*)matching->array[0];
            if (NULL == cert->key) {
                DEBUGMSGT(("cert:partner", "matched partner!\n"));
                key->cert = cert;
                cert->key = key;
                cert->info.allowed_uses |= NS_CERT_IDENTITY;
            }
            else if (cert->key != key)
                snmp_log(LOG_ERR, "key's matching cert already has partner\n");
        }
        else
            DEBUGMSGT(("cert:partner", "key matches multiple certs\n"));
    }
    else if(cert) {
        if (cert->key) {
            DEBUGMSGT(("cert:partner", "cert already has partner\n"));
            return;
        }
        DEBUGMSGT(("cert:partner", "looking for cert partner for %s\n",
                   cert->info.filename));
        len = snprintf(filename, sizeof(filename), "%s", cert->info.filename);
        if ('.' != filename[len-4])
            return;
        filename[len-3] = 0;
        search.filename = filename;
        matching = CONTAINER_GET_SUBSET(_keys, &search);
        if (!matching)
            return;
        if (1 == matching->size) {
            key = (netsnmp_key*)matching->array[0];
            if (NULL == key->cert) {
                DEBUGMSGT(("cert:partner", "matched partner!\n"));
                key->cert = cert;
                cert->key = key;
            }
            else if (cert->key != key)
                snmp_log(LOG_ERR, "cert's matching key already has partner\n");
        }
        else
            DEBUGMSGT(("cert:partner", "key matches multiple certs\n"));
    }
    
    if (matching) {
        free(matching->array);
        free(matching);
}
}

        

static int
_add_certfile(const char* dirname, const char* filename, FILE *index)
{
    X509         *ocert;
    EVP_PKEY     *okey;
    netsnmp_cert *cert = NULL;
    netsnmp_key  *key = NULL;
    char          certfile[SNMP_MAXPATH];
    int           len, type;

    if (((const void*)NULL == dirname) || (NULL == filename))
        return -1;

    len = strlen(filename);
    if (len < 5 ) /* x.ext */
        return -1;

        snprintf(certfile, sizeof(certfile),"%s/%s", dirname, filename);

    netsnmp_assert(filename[len-4] == '.'); /* should be enforced by filter */
    type = _cert_ext_type(&filename[len-3]);
    netsnmp_assert(type != NS_CERT_TYPE_UNKNOWN);

    DEBUGMSGT(("cert:file:add", "Checking file: %s (type %d)\n", filename,
               type));

    if (NS_CERT_TYPE_KEY == type) {
        key = _new_key(dirname, filename);
        if (NULL == key)
            return -1;
        okey = netsnmp_okey_get(key);
        if (NULL == okey) {
            netsnmp_key_free(key);
            return -1;
        }
        key->okey = okey;
        if (-1 == CONTAINER_INSERT(_keys, key)) {
            DEBUGMSGT(("cert:key:file:add:err",
                       "error inserting key into container\n"));
            netsnmp_key_free(key);
            key = NULL;
        }
    }
    else {
        cert = _new_cert(dirname, filename, type, NULL, NULL);
        if (NULL == cert)
            return -1;
        ocert = netsnmp_ocert_get(cert);
        if (NULL == ocert) {
            netsnmp_cert_free(cert);
            return -1;
        }
        cert->ocert = ocert;
        if (-1 == CONTAINER_INSERT(_certs, cert)) {
            DEBUGMSGT(("cert:file:add:err",
                       "error inserting cert into container\n"));
            netsnmp_cert_free(cert);
            cert = NULL;
        }
    }
    if ((NULL == cert) && (NULL == key)) {
        DEBUGMSGT(("cert:file:add:failure", "for %s\n", certfile));
        return -1;
    }

    if (index) {
        /** filename = NAME_MAX = 255 */
        /** fingerprint = 60 */
        /** common name / CN  = 64 */
        if (cert)
            fprintf(index, "c:%s %s '%s'\n", filename, cert->fingerprint,
                    cert->common_name);
        else if (key)
            fprintf(index, "k:%s\n", filename);
    }

    return 0;
}

static int
_cert_read_index(const char *dirname, struct stat *dirstat)
{
#if (defined(WIN32) || defined(cygwin))
    /* For Win32 platforms, the directory does not maintain a last modification
     * date that we can compare with the modification date of the .index file.
     * Therefore there is no way to know whether any .index file is valid.
     */
    return -1;
#else
    FILE           *index;
    char           *idxname, *pos;
    struct stat     idx_stat;
    char            tmpstr[SNMP_MAXPATH + 5], filename[NAME_MAX];
    char            fingerprint[60+1], common_name[64+1];
    int             count = 0;
    netsnmp_cert    *cert;
    netsnmp_key     *key;
    netsnmp_container *newer; 

    netsnmp_assert(NULL != dirstat);
    netsnmp_assert(NULL != dirname);

    idxname = _certindex_lookup( dirname );
    if (NULL == idxname) {
        DEBUGMSGT(("cert:index:parse", "no index for cert directory\n"));
        return -1;
    }

    /*
     * see if directory has been modified more recently than the index
     */
    if (stat(idxname, &idx_stat) != 0) {
        DEBUGMSGT(("cert:index:parse", "error getting index file stats\n"));
        SNMP_FREE(idxname);
        return -1;
    }

    if (dirstat->st_mtime >= idx_stat.st_mtime) {
        DEBUGMSGT(("cert:index:parse", "Index outdated; dir modified\n"));
        SNMP_FREE(idxname);
        return -1;
    }

    /*
     * dir mtime doesn't change when files are touched, so we need to check
     * each file against the index in case a file has been modified.
     */
    newer =
        netsnmp_directory_container_read_some(NULL, dirname,
                                              (netsnmp_directory_filter*)
                                              _time_filter,(void*)&idx_stat,
                                              NETSNMP_DIR_NSFILE |
                                              NETSNMP_DIR_NSFILE_STATS);
    if (newer) {
        DEBUGMSGT(("cert:index:parse", "Index outdated; files modified\n"));
        CONTAINER_FREE_ALL(newer, NULL);
        CONTAINER_FREE(newer);
        SNMP_FREE(idxname);
        return -1;
    }

    DEBUGMSGT(("cert:index:parse", "The index for %s looks good\n", dirname));

    index = fopen(idxname, "r");
    if (NULL == index) {
        snmp_log(LOG_ERR, "cert:index:parse can't open index for %s\n",
            dirname);
        SNMP_FREE(idxname);
        return -1;
    }

    fgets(tmpstr, sizeof(tmpstr), index); /* Skip dir line */
    while (1) {
        if (NULL == fgets(tmpstr, sizeof(tmpstr), index))
            break;

        if ('c' == tmpstr[0]) {
            pos = &tmpstr[2];
            if ((NULL == (pos = copy_nword(pos, filename, sizeof(filename)))) ||
                (NULL == (pos = copy_nword(pos, fingerprint, sizeof(fingerprint)))) ||
                (NULL != copy_nword(pos, common_name, sizeof(common_name)))) {
                snmp_log(LOG_ERR, "_cert_read_index: error parsing line: %s\n",
                         tmpstr);
                continue;
            }
            cert = (void*)_new_cert(dirname, filename, 0, fingerprint,
                                    common_name);
            if (cert && 0 == CONTAINER_INSERT(_certs, cert))
            ++count;
            else {
                DEBUGMSGT(("cert:index:add",
                           "error inserting cert into container\n"));
                netsnmp_cert_free(cert);
                cert = NULL;
            }
        }
        else if ('k' == tmpstr[0]) {
            if (NULL != copy_nword(&tmpstr[2], filename, sizeof(filename))) {
                snmp_log(LOG_ERR, "_cert_read_index: error parsing line %s\n",
                    tmpstr);
                continue;
            }
            key = _new_key(dirname, filename);
            if (key && 0 == CONTAINER_INSERT(_keys, key))
                ++count;
            else {
                DEBUGMSGT(("cert:index:add:key",
                           "error inserting key into container\n"));
                netsnmp_key_free(key);
            }
        }
        else {
            snmp_log(LOG_ERR, "unknown line in cert index for %s\n", dirname);
            continue;
    }
    } /* while */
    fclose(index);
    SNMP_FREE(idxname);

    DEBUGMSGT(("cert:index:parse","added %d certs from index\n", count));

    return count;
#endif /* ! windows */
}

static int
_add_certdir(const char *dirname)
{
    FILE           *index;
    char           *file;
    int             count = 0;
    netsnmp_container *cert_container;
    netsnmp_iterator  *it;
    struct stat     statbuf;

    netsnmp_assert(NULL != dirname);

    DEBUGMSGT(("9:cert:dir:add", " config dir: %s\n", dirname ));
    if (stat(dirname, &statbuf) != 0) {
        DEBUGMSGT(("9:cert:dir:add", " dir not present: %s\n",
                   dirname ));
        return -1;
    }
#ifdef S_ISDIR
    if (!S_ISDIR(statbuf.st_mode)) {
        DEBUGMSGT(("9:cert:dir:add", " not a dir: %s\n", dirname ));
        return -1;
    }
#endif

    DEBUGMSGT(("cert:index:dir", "Scanning directory %s\n", dirname));

    /*
     * look for existing index
     */
    count = _cert_read_index(dirname, &statbuf);
    if (count >= 0)
        return count;

    index = _certindex_new( dirname );
    if (NULL == index) {
        DEBUGMSGT(("cert:index:dir",
                    "error opening index for cert directory\n"));
        return -1;
    }

    /*
     * index was missing, out of date or bad. rescan directory.
     */
    cert_container =
        netsnmp_directory_container_read_some(NULL, dirname,
                                              (netsnmp_directory_filter*)
                                              &_cert_cert_filter, NULL,
                                              NETSNMP_DIR_RELATIVE_PATH |
                                              NETSNMP_DIR_EMPTY_OK );
    if (NULL == cert_container) {
        DEBUGMSGT(("cert:index:dir",
                    "error creating container for cert files\n"));
        goto err_index;
    }

    /*
     * iterate through the found files and add them to index
     */
    it = CONTAINER_ITERATOR(cert_container);
    if (NULL == it) {
        DEBUGMSGT(("cert:index:dir",
                    "error creating iterator for cert files\n"));
        goto err_container;
    }

    for (file = ITERATOR_FIRST(it); file; file = ITERATOR_NEXT(it)) {
        DEBUGMSGT(("cert:index:dir", "adding %s to index\n", file));
        if ( 0 == _add_certfile( dirname, file, index ))
            count++;
        else
            DEBUGMSGT(("cert:index:dir", "error adding %s to index\n",
                        file));
    }

    /*
     * clean up and return
     */
    ITERATOR_RELEASE(it);

  err_container:
    netsnmp_directory_container_free(cert_container);

  err_index:
    fclose(index);

    return count;
}

static void
_cert_indexes_load(void)
{
    const char     *confpath;
    char           *confpath_copy, *dir, *subdir, *st = NULL;
    char            certdir[SNMP_MAXPATH];

    /*
     * load indexes from persistent dir
     */
    _certindexes_load();

    /*
     * duplicate path building from read_config_files_of_type() in
     * read_config.c. That is, use SNMPCONFPATH environment variable if
     * it is defined, otherwise use configuration directory.
     */
    confpath = netsnmp_getenv("SNMPCONFPATH");
    if (NULL == confpath)
        confpath = get_configuration_directory();

    confpath_copy = strdup(confpath);
    for ( dir = strtok_r(confpath_copy, ENV_SEPARATOR, &st);
          dir; dir = strtok_r(NULL, ENV_SEPARATOR, &st)) {

        /** check for default certs subdir */
        snprintf(certdir, sizeof(certdir), "%s/%s", dir, "certs");
        _add_certdir(certdir);

        /** check for configured extra subdir */
        subdir = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                                       NETSNMP_DS_LIB_CERT_EXTRA_SUBDIR);
        if (NULL != subdir) {
            snprintf(certdir, sizeof(certdir), "%s/%s", dir, subdir);
            _add_certdir(certdir);
        }

        /** xxx-rks: read base dirs too? or only read them if configured? */
        /** _add_certdir(dir); */

    }
    SNMP_FREE(confpath_copy);
}

static void
_cert_print(netsnmp_cert *c, void *context)
{
    if (NULL == c)
        return;

    snmp_log(LOG_INFO, "found in %s %s\n", c->info.dir, c->info.filename);
    snmp_log(LOG_INFO, " type %d flags 0x%x (%s)\n",
             c->info.type, c->info.allowed_uses,
             _mode_str(c->info.allowed_uses));
    if (NS_CERT_TYPE_KEY == c->info.type) {
    }
    else {
        if(c->fingerprint)
            snmp_log(LOG_INFO, "Cert fingerprint: %s\n", c->fingerprint);
        if (c->common_name)
            snmp_log(LOG_INFO, " common_name %s\n", c->common_name);
        if (c->san_rfc822)
            snmp_log(LOG_INFO, " san_rfc822 %s\n", c->san_rfc822);
        if (c->san_ipaddr)
            snmp_log(LOG_INFO, " san_ipaddr %s\n", c->san_ipaddr);
        if (c->san_dnsname)
            snmp_log(LOG_INFO, " san_dnsname %s\n", c->san_dnsname);
    }

    /** netsnmp_openssl_cert_dump_names(c->ocert); */

}

static void
_key_print(netsnmp_key *k, void *context)
{
    if (NULL == k)
        return;

    snmp_log(LOG_INFO, "found in %s %s\n", k->info.dir, k->info.filename);
    snmp_log(LOG_INFO, " type %d flags 0x%x (%sc)\n", k->info.type,
             k->info.allowed_uses, _mode_str(k->info.allowed_uses));
}

void
netsnmp_cert_dump_all(void)
{
    CONTAINER_FOR_EACH(_certs, (netsnmp_container_obj_func*)_cert_print, NULL);
    CONTAINER_FOR_EACH(_keys, (netsnmp_container_obj_func*)_key_print, NULL);
}

#ifdef CERT_MAIN
/*
 * export BLD=~/net-snmp/build/ SRC=~/net-snmp/src 
 * cc -DCERT_MAIN `$BLD/net-snmp-config --cflags` `$BLD/net-snmp-config --build-includes $BLD/`  $SRC/snmplib/cert_util.c   -o cert_util `$BLD/net-snmp-config --build-lib-dirs $BLD` `$BLD/net-snmp-config --libs` -lcrypto -lssl
 *
 */
int
main(int argc, char** argv)
{
    int          ch;
    extern char *optarg;

    while ((ch = getopt(argc, argv, "D:fHLMx:")) != EOF)
        switch(ch) {
            case 'D':
                debug_register_tokens(optarg);
                snmp_set_do_debugging(1);
                break;
            default:
                fprintf(stderr,"unknown option %c\n", ch);
        }

    init_snmp("dtlsapp");

    netsnmp_cert_dump_all();

    return 0;
}

#endif /* CERT_MAIN */

static netsnmp_cert *_cert_find_fp(const char *fingerprint);

static void
_fp_lowercase_and_strip_colon(char *fp)
{
    char *pos, *dest=NULL;
    
    if(!fp)
        return;

    /** skip to first : */
    for (pos = fp; *pos; ++pos ) {
        if (':' == *pos) {
            dest = pos;
            break;
        }
        else
            *pos = isalpha(*pos) ? tolower(*pos) : *pos;
    }
    if (!*pos)
        return;

    /** copy, skipping any ':' */
    for (++pos; *pos; ++pos) {
        if (':' == *pos)
            continue;
        *dest++ = isalpha(*pos) ? tolower(*pos) : *pos;
    }
    *dest = *pos; /* nul termination */
}

netsnmp_cert *
netsnmp_cert_find(int what, int where, void *hint)
{
    netsnmp_cert *result = NULL;
    int           tmp;
    char         *fp;

    DEBUGMSGT(("cert:find:params", "looking for %s(%d) in %s(0x%x), hint %lu\n",
               _mode_str(what), what, _where_str(where), where, (u_long)hint));

    if (NS_CERTKEY_DEFAULT == where) {
            
        switch (what) {
            case NS_CERT_IDENTITY: /* want my ID */
                tmp = (int)hint;
                fp =
                    netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                                          tmp ? NETSNMP_DS_LIB_X509_SERVER_PUB :
                                          NETSNMP_DS_LIB_X509_CLIENT_PUB );
                break;
            case NS_CERT_REMOTE_PEER:
                fp = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                                           NETSNMP_DS_LIB_X509_SERVER_PUB);
                break;
            default:
                DEBUGMSGT(("cert:find:err", "unhandled type %d for %d\n", what,
                           where));
                return NULL;
        }
        _fp_lowercase_and_strip_colon(fp);
        result = _cert_find_fp(fp);

    } /* where = ds store */
    else if (NS_CERTKEY_FINGERPRINT == where) {
        result = _cert_find_fp((char *)hint);
    }
    else if (NS_CERTKEY_TARGET_ADDR == where) {
        
        /** hint == target mib data */
        switch (what) {
            case NS_CERT_IDENTITY:
            case NS_CERT_REMOTE_PEER:
            default:
                DEBUGMSGT(("cert:find:err", "unhandled type %d for %d\n", what,
                           where));
                return NULL;
        }
    } /* where = target mib */
    else { /* unknown location */
        
        DEBUGMSGT(("cert:find:err", "unhandled location %d for %d\n", where,
                   what));
        return NULL;
    }
    
    if (NULL == result)
        return NULL;

    /** make sure result found can be used for specified type */
    if (!(result->info.allowed_uses & what)) {
        DEBUGMSGT(("cert:find:err", "cert %s not allowed for %s(%d) (uses=%s (%d))\n",
                   result->info.filename, _mode_str(what),
                   what , _mode_str(result->info.allowed_uses),
                   result->info.allowed_uses));
        return NULL;
    }
    
    /** make sure we have the cert data */
    if (NULL == result->ocert) {
        netsnmp_ocert_get(result);
        if (NULL == result->ocert) {
            DEBUGMSGT(("result:find:err", "couldn't load cert for %s\n",
                       result->info.filename));
            return NULL;
        }
    }

    /** load cert and key if needed */
    if (NS_CERT_IDENTITY == what) {
        netsnmp_assert(result->key);

        /** make sure we have the key data */
        if (NULL == result->key->okey) {
            netsnmp_okey_get(result->key);
            if (NULL == result->key->okey) {
                DEBUGMSGT(("result:find:err", "couldn't load key for cert %s\n",
                           result->info.filename));
                return NULL;
            }
        }
    }
            
    return result;
}

int
netsnmp_cert_validate(int who, int how, X509 *cert)
{
    return -1;
}

static const char *_mode_str(u_char mode)
{
    return _modes[mode];
}

static const char *_where_str(u_int what)
{
    switch (what) {
        case NS_CERTKEY_DEFAULT: return "DEFAULT";
        case NS_CERTKEY_FILE: return "FILE";
        case NS_CERTKEY_FINGERPRINT: return "FINGERPRINT";
        case NS_CERTKEY_CA: return "CA";
        case NS_CERTKEY_SAN_RFC822: return "SAN_RFC822";
        case NS_CERTKEY_SAN_DNS: return "SAN_DNS";
        case NS_CERTKEY_SAN_IPADDR: return "SAN_IPADDR";
        case NS_CERTKEY_COMMON_NAME: return "COMMON_NAME";
        case NS_CERTKEY_TARGET_PARAM: return "TARGET_PARAM";
        case NS_CERTKEY_TARGET_ADDR: return "TARGET_ADDR";
    }

    return "UNKNOWN";
}

static netsnmp_cert *
_cert_find_fp(const char *fingerprint)
{
    netsnmp_cert cert, *result = NULL;

    if (NULL == fingerprint)
        return NULL;

    /** clear search key */
    memset(&cert, 0x00, sizeof(cert));
    cert.info.type = NS_CERT_TYPE_UNKNOWN; /* don't really know type */
    cert.fingerprint = NETSNMP_REMOVE_CONST(char*,fingerprint);
    result = CONTAINER_FIND(_certs,&cert);
    return result;
}

static netsnmp_cert *
_key_find_fn(const char *filename)
{
    char tmp[NAME_MAX];

    netsnmp_cert key, *result = NULL;

    if (NULL == filename)
        return NULL;

    /** clear search key */
    memset(&key, 0x00, sizeof(key));
    key.info.filename = NETSNMP_REMOVE_CONST(char*,filename);
    result = CONTAINER_FIND(_keys,&key);
    return result;
}

static int
_time_filter(netsnmp_file *f, struct stat *idx)
{
    if (f && idx && f->stats && (f->stats->st_mtime >= idx->st_mtime))
        return NETSNMP_DIR_INCLUDE;

    return NETSNMP_DIR_EXCLUDE;
}


#endif /* defined(NETSNMP_USE_OPENSSL) && defined(HAVE_LIBSSL) */
