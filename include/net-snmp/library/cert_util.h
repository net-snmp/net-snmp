#ifndef NETSNMP_CERT_UTIL_H

#if defined(NETSNMP_USE_OPENSSL) && defined(HAVE_LIBSSL)

#ifndef HEADER_X509_H
#error "must include <openssl/x509.h> before cert_util.h"
#endif

#ifdef  __cplusplus
extern "C" {
#endif

    /*************************************************************************
     *
     * netsnmp_cert structures, defines and function definitions
     *
     *************************************************************************/

void netsnmp_certs_init(void);
void netsnmp_certs_shutdown(void);

    typedef struct netsnmp_cert_common_s {
        char           *dir;
        char           *filename;
        
        u_char          type;
        u_char          allowed_uses;
        u_char          _pad[2]; /* for future use */
    } netsnmp_cert_common;

    typedef struct netsnmp_key_s {
        netsnmp_cert_common info;

        EVP_PKEY       *okey;
        struct netsnmp_cert_s   *cert;
    } netsnmp_key;

    typedef struct netsnmp_cert_s {
        netsnmp_cert_common info;

        X509           *ocert;
        netsnmp_key    *key;
        struct netsnmp_cert_s *issuer_cert;

        char           *issuer;
        char           *subject;
        char           *fingerprint;
        char           *common_name;
        char           *san_rfc822;
        char           *san_ipaddr;
        char           *san_dnsname;

        u_char          hash_type;
        u_char          _pad[3]; /* for future use */
    } netsnmp_cert;

/** types */
    enum { NS_CERT_TYPE_UNKNOWN = 0, NS_CERT_TYPE_PEM, NS_CERT_TYPE_DER,
           NS_CERT_TYPE_PKCS12, NS_CERT_TYPE_KEY };

/** uses */
#define NS_CERT_IDENTITY       0x0001
#define NS_CERT_REMOTE_PEER    0x0002
#define NS_CERT_RESERVED1      0x0004
#define NS_CERT_CA             0x0008

#define NS_CERTKEY_DEFAULT       0x000 /* get default from DS store */
#define NS_CERTKEY_FILE          0x001 /* filename/full path */
#define NS_CERTKEY_FINGERPRINT   0x002 /* public key fingerprint */
#define NS_CERTKEY_CA            0x004 /* trusted CA */
#define NS_CERTKEY_SAN_RFC822    0x008 /* subj alt name: rfc822 */
#define NS_CERTKEY_SAN_DNS       0x010 /* subj alt name: DNS */
#define NS_CERTKEY_SAN_IPADDR    0x020 /* subj alt name: IP address */
#define NS_CERTKEY_COMMON_NAME   0x040 /* common name */
#define NS_CERTKEY_TARGET_PARAM  0x080 /* tlstmParamsTable */
#define NS_CERTKEY_TARGET_ADDR   0x100 /* tlstmAddrTable */

/** RFC 5246 hash algorithms (Section 7.4.1.4.1) */
#define NS_HASH_NONE        0
#define NS_HASH_MD5         1
#define NS_HASH_SHA1        2
#define NS_HASH_SHA224      3
#define NS_HASH_SHA256      4
#define NS_HASH_SHA384      5
#define NS_HASH_SHA512      6
#define NS_HASH_MAX         NS_HASH_SHA512

    /*************************************************************************
     *
     * function definitions
     *
     *************************************************************************/

void netsnmp_certs_init(void);
void netsnmp_certs_shutdown(void);

    netsnmp_cert *netsnmp_cert_find(int what, int where, void *hint);

    int netsnmp_cert_check_vb_fingerprint(const netsnmp_variable_list *var);

    void netsnmp_fp_lowercase_and_strip_colon(char *fp);
    
#ifdef __cplusplus
}
#endif

#endif /* defined(NETSNMP_USE_OPENSSL) && defined(HAVE_LIBSSL) */

#endif /* NETSNMP_CERT_UTIL_H */

