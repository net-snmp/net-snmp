/*
 * scapi.h
 */

#ifndef _SCAPI_H
#define _SCAPI_H

#ifdef __cplusplus
extern "C" {
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
int	sc_shutdown (int majorID, int minorID, void *serverarg,
                     void *clientarg);

int	sc_random (	u_char *buf, size_t *buflen);

int	sc_generate_keyed_hash (
		oid    *authtype,	size_t   authtypelen,
		u_char *key,		u_int keylen,
		u_char *message,	u_int msglen,
		u_char *MAC,		size_t *maclen);

int	sc_check_keyed_hash (
		oid    *authtype,	size_t   authtypelen,
		u_char *key,		u_int keylen,
		u_char *message,	u_int msglen,
		u_char *MAC,		u_int maclen);

int	sc_encrypt (	oid    *privtype,	size_t   privtypelen,
				u_char *key,		u_int keylen,
				u_char *iv,		u_int ivlen,
				u_char *plaintext,	u_int ptlen,
				u_char *ciphertext,	size_t *ctlen);

int	sc_decrypt (	oid    *privtype,	size_t   privtypelen,
				u_char *key,		u_int keylen,
				u_char *iv,		u_int ivlen,
				u_char *ciphertext,	u_int ctlen,
				u_char *plaintext,	size_t *ptlen);

int     sc_hash(oid *hashtype, size_t hashtypelen, u_char *buf, size_t buf_len,
                u_char *MAC, size_t *MAC_len);

int     sc_get_transform_type(oid *hashtype, u_int hashtype_len,
                              int (**hash_fn)(
                                const int	  mode,	  void 	   **context,
                                const u_char	 *data,	  const int  data_len,
                                u_char		**digest, size_t    *digest_len));
  

/*
 * All functions devolve to the following block if we can't do cryptography
 */
#define	_SCAPI_NOT_CONFIGURED			\
{						\
        snmp_log(LOG_ERR, "Encryption support not enabled.\n"); \
        DEBUGPL(("SCAPI not configured");      \
	return SNMPERR_SC_NOT_CONFIGURED;	\
}

/* define a transform type if we're using the internal md5 support */
#ifdef USE_INTERNAL_MD5
#define INTERNAL_MD5 1
#endif

#ifdef __cplusplus
}
#endif

#endif	/* _SCAPI_H */
