/*
 * scapi.h
 */

#ifndef _SCAPI_H
#define _SCAPI_H

#ifdef			HAVE_LIBKMT
#	include <kmt.h>
#	include <kmt_algs.h>
#endif



/* 
 * Authentication/privacy transform bitlengths.
 */
#define SNMP_TRANS_AUTHLEN_HMACMD5	128
#define SNMP_TRANS_AUTHLEN_HMACSHA1	160

#define SNMP_TRANS_AUTHLEN_HMAC96	96

#define SNMP_TRANS_PRIVLEN_1DES		64
#define SNMP_TRANS_PRIVLEN_1DES_IV	64



/*
 * Prototypes.
 */
int sc_get_properlength(oid *hashtype, u_int hashtype_len);

int	sc_init (void);
int	sc_shutdown (void);

int	sc_random (	u_char *buf, u_int *buflen);

int	sc_generate_keyed_hash (
		oid    *authtype,	int   authtypelen,
		u_char *key,		u_int keylen,
		u_char *message,	u_int msglen,
		u_char *MAC,		u_int *maclen);

int	sc_check_keyed_hash (
		oid    *authtype,	int   authtypelen,
		u_char *key,		u_int keylen,
		u_char *message,	u_int msglen,
		u_char *MAC,		u_int maclen);

int	sc_encrypt (	oid    *privtype,	int   privtypelen,
				u_char *key,		u_int keylen,
				u_char *iv,		u_int ivlen,
				u_char *plaintext,	u_int ptlen,
				u_char *ciphertext,	u_int *ctlen);

int	sc_decrypt (	oid    *privtype,	int   privtypelen,
				u_char *key,		u_int keylen,
				u_char *iv,		u_int ivlen,
				u_char *ciphertext,	u_int ctlen,
				u_char *plaintext,	u_int *ptlen);

int     sc_hash(oid *hashtype, int hashtypelen, u_char *buf, int buf_len,
                u_char *MAC, u_int *MAC_len);

int     sc_get_transform_type(oid *hashtype, u_int hashtype_len,
                              int (**hash_fn)(
                                const int	  mode,	  void 	   **context,
                                const u_int8_t	 *data,	  const int  data_len,
                                u_int8_t	**digest, int	    *digest_len));
  
/*
 * SCAPI functions specific to KMT.
 */
#ifdef								HAVE_LIBKMT

int	sc_internal_kmtlookup (
		u_int 	 transform, 	
		u_char	*key,		u_int		  keylen,
		u_int	 properlength,	KMT_KEY_LIST	**kmtkeylist,
		int	 dospecify);
#endif



/*
 * All functions devolve to the following block if HAVE_LIBKMT is not defined.
 */
#define	_SCAPI_NOT_CONFIGURED			\
{						\
        DEBUGPL(("SCAPI not configured");      \
	return SNMPERR_SC_NOT_CONFIGURED;	\
}

/* define a transform type if we're using the internal md5 support */
#ifdef USE_INTERNAL_MD5
#define INTERNAL_MD5 1
#endif

#endif	/* _SCAPI_H */

