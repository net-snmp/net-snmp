/*
 * keytools.h
 */

#ifndef _KEYTOOLS_H
#define _KEYTOOLS_H


#define USM_LENGTH_EXPANDED_PASSPHRASE	(1024 * 1024)	/* 1Meg. */

#define USM_LENGTH_KU_HASHBLOCK		64		/* In bytes. */

#define USM_LENGTH_P_MIN		8		/* In characters. */
	/* Recommended practice given in <draft-ietf-snmpv3-usm-v2-02.txt>,
	 * Section 11.2 "Defining Users".  Move into cmdline app argument
	 * parsing, and out of the internal routine?  XXX
	 */

#define SET_HASH_TRANSFORM(t)   kmt_hash = t;



/*
 * Simple hash function pointer, and the internal hash functions offered
 * by KMT.
 *
 * FIX  Resolve the broken KMT API issue.
 * 	kmt_s_* prototypes stolen from KMT/algs/kmt_hash.h.
 *
 * FIX	Offer an snmp_hash() function to hide away differences between
 *	this an "internal" MD5 (& whatever else might come...)?
 */
int (*kmt_hash) __P((
	const int	  mode,		void  	 **context,
	const u_int8_t	 *data,		const int  data_len,     
	u_int8_t	**digest,	int	  *digest_len));


extern int (*kmt_s_md5) __P((
		const int	  mode,		void  	 **context,
		const u_int8_t	 *data,		const int  data_len,     
		u_int8_t	**digest,	int	  *digest_len));
extern int (*kmt_s_sha1) __P((
		const int	  mode,		void  	 **context,
		const u_int8_t	 *data,		const int  data_len,     
		u_int8_t	**digest,	int	  *digest_len));
extern int (*kmt_s_ripemd) __P((
		const int	  mode,		void  	 **context,
		const u_int8_t	 *data,		const int  data_len,     
		u_int8_t	**digest,	int	  *digest_len));



/*
 * Prototypes.h
 */
int	generate_Ku __P((	oid	*hashtype,	u_int  hashtype_len,
				u_char	*P,		u_int  pplen,
				u_char	*Ku,		u_int *kulen));

int	generate_kul __P((	oid	*hashtype,	u_int  hashtype_len,
				u_char	*engineID,	u_int  engineID_len,
				u_char	*Ku,		u_int  ku_len,
				u_char	*Kul,		u_int *kul_len));

int	encode_keychange __P((	oid	*hashtype,	u_int  hashtype_len,
				u_char	*oldkey,	u_int  oldkey_len,
				u_char	*newkey,	u_int  newkey_len,
				u_char	*kcstring,	u_int *kcstring_len));

int	decode_keychange __P((	oid	*hashtype,	u_int  hashtype_len,
				u_char	*oldkey,	u_int  oldkey_len,
				u_char	*kcstring,	u_int  kcstring_len,
				u_char	*newkey,	u_int *newkey_len));


/*
 * All functions devolve to the following block if HAVE_LIBKMT is not defined.
 */
#define	_KEYTOOLS_NOT_AVAILABLE			\
{						\
	return SNMPERR_KT_NOT_AVAILABLE;	\
}

#endif /* _KEYTOOLS_H */

