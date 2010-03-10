#include <net-snmp/net-snmp-config.h>

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
#include <net-snmp/library/snmpTLSBaseDomain.h>
#include <net-snmp/library/snmpDTLSUDPDomain.h>
#include <net-snmp/library/snmpUDPDomain.h>
#include <net-snmp/library/system.h>
#include <net-snmp/library/tools.h>
#include <net-snmp/library/snmp_openssl.h>
#include <net-snmp/library/callback.h>
#include <net-snmp/library/container.h>
#include <net-snmp/library/dir_utils.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>

typedef struct netsnmp_cert_s {
    X509 *xcert;
    char *dir;
    char *file;
    char *fingerprint;
    char *common_name;
    char *san_rfc822;
    char *san_ipaddr;
    char *san_dnsname;
 
    uint16_t dir_index;

} netsnmp_cert;

static netsnmp_container *_certs = NULL;

static void _cert_indexes_load(void);
static void _cert_free(netsnmp_cert *cert, void *context);
static int  _cert_compare(netsnmp_cert *lhs, netsnmp_cert *rhs);
static X509 *_xcertfile_read(const char *file);

void netsnmp_cert_free(netsnmp_cert *cert);

/*
 * Handle CERT indexes centrally
 */
static int _certindex     = 0;   /* Last index in use */
static int _certindex_max = 0;   /* Size of index array */
static char **_certindexes   = NULL;

static int _certindex_add( const char *dirname, int i );

/* #####################################################################
 *
 * init and shutdown functions
 *
 */
void
init_cert_util(void)
{
    DEBUGMSGT(("cert:util:init","init\n"));

    if (NULL != _certs) {
        DEBUGMSGT(("cert:util:init", "ignoring duplicate init\n"));
        return;
    }

    netsnmp_init_tlsbase(); /* will init openssl */

    _certs = netsnmp_container_find("certs:binary_array");
    if (NULL == _certs) {
        snmp_log(LOG_ERR, "could not create container for certificates\n");
        return;
    }
    _certs->free_item = (netsnmp_container_obj_func*)_cert_free;
    _certs->compare = (netsnmp_container_compare*)_cert_compare;

    /** scan config dirs for certs */
    _cert_indexes_load();
}

void
shutdown_certs(void)
{
    DEBUGMSGT(("cert:util:shutdown","shutdown\n"));
    CONTAINER_FREE_ALL(_certs, NULL);
    CONTAINER_FREE(_certs);
}

/* #####################################################################
 *
 * cert container functions
 */

static netsnmp_cert *
_new_cert(const char *dirname, const char *filename, X509 *xcert)
{
    netsnmp_cert    *cert;
    u_char          fingerprint[EVP_MAX_MD_SIZE];
    u_int           fingerprint_len;
    const EVP_MD   *digest = EVP_sha1(); /* make configurable? */

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

    DEBUGMSGT(("cert:struct:new","new cert 0x%#lx\n", (u_long)cert));

    if (!X509_digest(xcert,digest,fingerprint,&fingerprint_len)) {
        snmp_log(LOG_ERR,"failed to compute fingerprint for %s\n", filename);
        netsnmp_cert_free(cert);
        return NULL;
    }
    binary_to_hex(fingerprint, fingerprint_len, &cert->fingerprint);

    DEBUGMSGT(("cert:file:add:fingerprint", "fingerprint %s\n",
               cert->fingerprint));

    /*
     *##################################################################
     * xxx-rks: get other fields for index
     * e.g. subject alt names, common name, filename, etc
     *##################################################################
     */
    char namebuf[128];
    char *tmp = X509_NAME_oneline(X509_get_subject_name(xcert),
                                  namebuf, sizeof(namebuf));
    DEBUGMSGT(("cert:file:add:name","%s\n", tmp));
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

    cert->xcert = xcert;

    /** xxx-rks: add cert to container */

    return cert;
}

void
netsnmp_cert_free(netsnmp_cert *cert)
{
    if (NULL == cert)
        return;

    DEBUGMSGT(("cert:struct:free","freeing cert 0x%#lx, %s (fp %s; CN %s)\n",
               (u_long)cert, cert->file ? cert->file : "UNK",
               cert->fingerprint ? cert->fingerprint : "UNK",
               cert->common_name ? cert->common_name : "UNK"));

    SNMP_FREE(cert->dir);
    SNMP_FREE(cert->file);
    SNMP_FREE(cert->fingerprint);
    SNMP_FREE(cert->common_name);
    SNMP_FREE(cert->san_rfc822);
    SNMP_FREE(cert->san_ipaddr);
    SNMP_FREE(cert->san_dnsname);

    free(cert); /* SNMP_FREE not needed on parameters */
}

static void
_cert_free(netsnmp_cert *cert, void *context)
{
    netsnmp_cert_free(cert);
}

static int
_cert_compare(netsnmp_cert *lhs, netsnmp_cert *rhs)
{
    netsnmp_assert((lhs != NULL) && (rhs != NULL));

    return strcmp(lhs->fingerprint, rhs->fingerprint);
}


/*
 * filter functions; return 1 to include file, 0 to exclude
 */
enum { CERT_UNKNOWN = 0, CERT_PEM, CERT_DER, CERT_PKCS12 };

static int
_cert_ext_type(const char *ext)
{
    if ('p' == *ext) {
        if (strcmp(ext,"pem") == 0)
            return CERT_PEM;
        if (strcmp(ext,"p12") == 0)
            return CERT_PKCS12;
    }
    else if (('d' == *ext) && (strcmp(ext,"der") == 0))
        return CERT_DER;
    else if ('c' == *ext) {
        if (strcmp(ext,"crt") == 0)
            return CERT_DER;
        if (strcmp(ext,"cer") == 0)
            return CERT_DER;
    }

    return CERT_UNKNOWN;
}

static int
_cert_cert_filter(const char *filename)
{
    int  len = strlen(filename);
    char *pos;

    if (len < 5) /* shortest name: x.YYY */
        return 0;

    pos = &filename[len-4];
    if (*pos++ != '.')
        return 0;

    if (_cert_ext_type(pos) != CERT_UNKNOWN)
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
 *
 * xxx-rks: make this a container?
 * xxx-rks: handle renumbering somewhere. As is, this will blindly allocate
 *          memory based on the filename indexes, so if they start at 100
 *          then the lower indexes will never be used.
 */
static int
_certindex_add( const char *dirname, int i )
{
    char **cpp;

    if ( i == -1 )
        i = _certindex++;

    /*
     * If the index array is full (or non-existent) then expand (or create) it
     */
    if ( i >= _certindex_max ) {
        DEBUGMSGT(("cert:index:add", "expanding indexes size to %d\n",
                   i + 10 ));
        cpp = (char **)realloc( _certindexes, (10+i) * sizeof(char*));
        if (NULL == cpp) {
            snmp_log(LOG_ERR, "cert index realloc failed; %d (%s) not added\n",
                     i, dirname);
            return -1;
        }
        _certindexes   = cpp;
        _certindex_max = i+10;
    }
    DEBUGMSGT(("cert:index:add","%d/%d/%d\n", i, _certindex, _certindex_max ));

    _certindexes[ i ] = strdup( dirname );
    if (NULL == _certindexes[i]) {
        snmp_log(LOG_ERR, "strdup of certindex dirname failed; "
                 "%d (%s) not added\n", i, dirname);
        return -1;
    }
    if ( i >= _certindex )
        _certindex = ++i;

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
    static char filename[SNMP_MAXPATH];

    for (i=0; i<_certindex; i++) {
        if ( ! _certindexes[i] || strcmp( _certindexes[i], dirname ) != 0)
            continue;

        snprintf(filename, sizeof(filename), "%s/cert_indexes/%d",
                 get_persistent_directory(), i);
        filename[sizeof(filename)-1] = 0;
        DEBUGMSGT(("cert:index:lookup", "%s (%d) %s\n", dirname, i, filename ));
        return filename;
    }
    DEBUGMSGT(("cert:index:lookup","%s : (none)\n", dirname));
    return NULL;
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

    return fp;
}

/* #####################################################################
 *
 * certificate utility functions
 *
 * xxx-rks: password protected files?
 */
static X509 *
_xcertfile_read(const char *file)
{
    BIO            *certbio;
    X509           *cert;
    int             len, type;

    netsnmp_assert(file != NULL);

    len = strlen(file);
    netsnmp_assert(file[len-4] == '.');
    type = _cert_ext_type(&file[len-3]);
    netsnmp_assert(type != CERT_UNKNOWN);

    DEBUGMSGT(("cert:file:read", "Checking file %s\n", file));

    certbio = BIO_new(BIO_s_file());
    if (NULL == certbio) {
        snmp_log(LOG_ERR, "error creating BIO");
        return NULL;
    }

    if (BIO_read_filename(certbio, file) <=0) {
        snmp_log(LOG_ERR, "error reading certificate %s into BIO\n", file);
        BIO_vfree(certbio);
        return NULL;
    }

    if (CERT_PEM == type)
        cert = PEM_read_bio_X509_AUX(certbio, NULL, NULL, NULL); /* PEM */
    else if (CERT_DER == type)
        cert = d2i_X509_bio(certbio,NULL); /* DER/ASN1 */
    else if (CERT_PKCS12 == type) {
        BIO_reset(certbio);
        PKCS12 *p12 = d2i_PKCS12_bio(certbio, NULL);
        if ( (NULL != p12) && (PKCS12_verify_mac(p12, "", 0) ||
                               PKCS12_verify_mac(p12, NULL, 0)))
            PKCS12_parse(p12, "", NULL, &cert, NULL);
    }
    else {
        snmp_log(LOG_ERR, "unknown certificate type %d for %s\n", type, file);
        type = -1;
    }

    if ((NULL == cert) && (type != -1))
        snmp_log(LOG_ERR, "error parsing certificate file %s\n", file);
 
    BIO_vfree(certbio);

    return cert;
}

static int
_add_certfile(const char* dirname, const char* filename, FILE *index)
{
    X509         *xcert;
    netsnmp_cert *cert;
    char          certfile[SNMP_MAXPATH], *thefile;

    if ((const void*)NULL == dirname)
        thefile = filename;
    else {
        snprintf(certfile, sizeof(certfile),"%s/%s", dirname, filename);
        thefile = certfile;
    }

    DEBUGMSGT(("cert:file:add", "Checking file: %s\n", certfile));

    xcert = _xcertfile_read(certfile);
    if (NULL == xcert) {
        DEBUGMSGT(("cert:file:add:failure", "for %s\n", certfile));
        return -1;
    }

    cert =_new_cert(certfile, filename, xcert);
    if (index && cert)
        fprintf(index, "%s %s\n", cert->fingerprint, filename);

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
    char           *idxname;
    char            space, newline;
    struct stat     idx_stat;
    char            tmpstr[SNMP_MAXPATH],filename[300],fingerprint[300];
    int             count = 0;

    netsnmp_assert(NULL != dirstat);
    netsnmp_assert(NULL != dirname);

    idxname = _certindex_lookup( dirname );
    if (NULL == idxname) {
        DEBUGMSGT(("cert:index:parse", "no index for cert directory\n"));
        return -1;
    }

    if (stat(idxname, &idx_stat) != 0) {
        DEBUGMSGT(("cert:index:parse", "error getting index file stats\n"));
        return -1;
    }

    if (dirstat->st_mtime >= idx_stat.st_mtime) {
        DEBUGMSGT(("cert:index:parse", "Index outdated\n"));
        return -1;
    }

    DEBUGMSGT(("cert:index:parse", "The index for %s looks good\n", dirname));

    index = fopen(idxname, "r");
    if (NULL == index) {
        snmp_log(LOG_ERR, "cert:index:parse can't open index for %s\n",
            dirname);
        return -1;
    }

    fgets(tmpstr, sizeof(tmpstr), index); /* Skip dir line */
    while (fscanf(index, "%299s%c%299s%c", fingerprint, &space, filename, &newline) == 4) {
        /*
         * If an overflow of the token or tmpstr buffers has been
         * found log a message and break out of the while loop,
         * thus the rest of the file tokens will be ignored.
         */
        if (space != ' ' || newline != '\n') {
            snmp_log(LOG_ERR, "_cert_read_index: strings scanned in "
                     "from %s index are too large.  count = %d\n ",
                     dirname, count);
            break;
        }

        if (0 == _add_certfile(dirname, filename, NULL))
            ++count;
        else
            DEBUGMSGT(("cert:index:parse","error adding %s/%s\n", dirname,
                       filename));
    }
    fclose(index);

    DEBUGMSGT(("cert:index:parse","added %d certs from index\n", count));

    return count;
#endif /* ! windows */
}

static int
_add_certdir(const char *dirname, struct stat *dirstat)
{
    FILE           *index;
    char           *file;
    int             count = 0;
    netsnmp_container *cert_container;
    netsnmp_iterator  *it;

    netsnmp_assert(NULL != dirstat);
    netsnmp_assert(NULL != dirname);

    DEBUGMSGT(("cert:index:dir", "Scanning directory %s\n", dirname));

    /*
     * look for existing index
     */
    count = _cert_read_index(dirname, dirstat);
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
    cert_container = netsnmp_directory_container_read_some(NULL,
                                                           dirname,
                                                           &_cert_cert_filter,
                                                           NETSNMP_DIR_RELATIVE_PATH | NETSNMP_DIR_EMPTY_OK );
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
    char           *confpath, *dir, *st = NULL;
    char            certdir[SNMP_MAXPATH];
    struct stat     statbuf;

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

    confpath = strdup(confpath);
    for ( dir = strtok_r(confpath, ENV_SEPARATOR, &st);
          dir; dir = strtok_r(NULL, ENV_SEPARATOR, &st)) {

        /** xxx-rks: add cert dir suffixes */
        /** xxx-rks: read base dirs too? or only read them if configured? */
        snprintf(certdir, sizeof(certdir), "%s/%s", dir, "certs");

        DEBUGMSGT(("9:cert:indexes:rebuild", " config dir: %s\n", certdir ));
        if (stat(certdir, &statbuf) != 0) {
            DEBUGMSGT(("9:cert:indexes:rebuild", " dir not present: %s\n",
                       certdir ));
            continue;
        }
#ifdef S_ISDIR
        if (!S_ISDIR(statbuf.st_mode)) {
            DEBUGMSGT(("9:cert:indexes:rebuild", " not a dir: %s\n", certdir ));
            continue;
        }
#endif

        DEBUGMSGT(("cert:indexes:rebuild", " reading dir: %s\n", certdir ));
        _add_certdir(certdir, &statbuf);

    }
    SNMP_FREE(confpath);
}

#ifdef CERT_MAIN
/*
 * cc -DCERT_MAIN `~/net-snmp/build/main-full/net-snmp-config --cflags` `~/net-snmp/build/main-full/net-snmp-config --build_incldes ~/net-snmp/build/main-full/`  snmplib/cert_util.c   -o cert_util `~/net-snmp/build/main-full/net-snmp-config --build-lib-dirs ~/net-snmp/build/main-full/` `~/net-snmp/build/main-full/net-snmp-config --libs` -lcrypto -lssl
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
    snmp_enable_stderrlog();

    init_snmp("main-full");

    _cert_indexes_load();

    return 0;
}

#endif /* CERT_MAIN */
