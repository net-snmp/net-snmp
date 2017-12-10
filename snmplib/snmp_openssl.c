/*
 * snmptsmsm.c
 *
 * This code merely does openssl initialization so that multilpe
 * modules are safe to call netsnmp_init_openssl() for bootstrapping
 * without worrying about other callers that may have already done so.
 */

#include <net-snmp/net-snmp-config.h>

#include <net-snmp/net-snmp-includes.h>

#include <net-snmp/library/snmp_openssl.h>

#if defined(NETSNMP_USE_OPENSSL) && defined(HAVE_LIBSSL)

#include <openssl/evp.h>
#include <openssl/ssl.h>

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

#ifndef HAVE_DH_SET0_PQG
int
DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
   /* If the fields p and g in d are NULL, the corresponding input
    * parameters MUST be non-NULL.  q may remain NULL.
    */
   if ((dh->p == NULL && p == NULL)
       || (dh->g == NULL && g == NULL))
       return 0;

   if (p != NULL) {
       BN_free(dh->p);
       dh->p = p;
   }
   if (q != NULL) {
       BN_free(dh->q);
       dh->q = q;
   }
   if (g != NULL) {
       BN_free(dh->g);
       dh->g = g;
   }

   if (q != NULL) {
       dh->length = BN_num_bits(q);
   }

   return 1;
}
#endif

#ifndef HAVE_DH_GET0_PQG
void
DH_get0_pqg(const DH *dh, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
   if (p != NULL)
       *p = dh->p;
   if (q != NULL)
       *q = dh->q;
   if (g != NULL)
       *g = dh->g;
}
#endif

#ifndef HAVE_DH_GET0_KEY
void
DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key)
{
   if (pub_key != NULL)
       *pub_key = dh->pub_key;
   if (priv_key != NULL)
       *priv_key = dh->priv_key;
}
#endif

#endif /* NETSNMP_USE_OPENSSL && HAVE_LIBSSL */
