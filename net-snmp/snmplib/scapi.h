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
int	sc_init __P((void));
int	sc_shutdown __P((void));

int	sc_random __P((	u_char *buf, u_int *buflen));

int	sc_generate_keyed_hash __P((
		oid    *authtype,	int   authtypelen,
		u_char *key,		u_int keylen,
		u_char *message,	u_int msglen,
		u_char *MAC,		u_int *maclen));

int	sc_check_keyed_hash __P((
		oid    *authtype,	int   authtypelen,
		u_char *key,		u_int keylen,
		u_char *message,	u_int msglen,
		u_char *MAC,		u_int maclen));

int	sc_encrypt __P((	oid    *privtype,	int   privtypelen,
				u_char *key,		u_int keylen,
				u_char *iv,		u_int ivlen,
				u_char *plaintext,	u_int ptlen,
				u_char *ciphertext,	u_int *ctlen));

int	sc_decrypt __P((	oid    *privtype,	int   privtypelen,
				u_char *key,		u_int keylen,
				u_char *iv,		u_int ivlen,
				u_char *ciphertext,	u_int ctlen,
				u_char *plaintext,	u_int *ptlen));


/*
 * SCAPI functions specific to KMT.
 */
#ifdef								HAVE_LIBKMT

int	sc_internal_kmtlookup __P((
		u_int 	 transform, 	
		u_char	*key,		u_int		  keylen,
		u_int	 properlength,	KMT_KEY_LIST	**kmtkeylist,
		int	 dospecify));
#endif



/*
 * All functions devolve to the following block if HAVE_LIBKMT is not defined.
 */
#define	_SCAPI_NOT_CONFIGURED			\
{						\
	return SNMPERR_SC_NOT_CONFIGURED;	\
}

#endif	/* _SCAPI_H */

