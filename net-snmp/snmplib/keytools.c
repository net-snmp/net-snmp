/*
 * keytools.c
 *
 * FIX	Decide how to publicize simple (currently internal) hash functions
 *	from KMT.  Otherwise they must be pulled from the package directly.
 */

#include "all_system.h"
#include "all_general_local.h"



/*
 * Simple hash function pointer, and the internal hash functions offered
 * by KMT.
 *
 * FIX  Resolve the broken KMT API issue.
 * 	kmt_s_* prototypes stolen from KMT/algs/kmt_hash.h.
 */
static int (*kmt_hash) __P((
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




/*******************************************************************-o-******
 * generate_Ku
 *
 * Parameters:
 *	*hashtype	MIB OID for the transform type for hashing.
 *	 hashtype_len	Length of OID value.
 *	*P		Pre-allocated bytes of passpharase.
 *	 pplen		Length of passphrase.
 *	*Ku		Buffer to contain Ku.
 *	*kulen		Length of Ku buffer.
 *      
 * Returns:
 *	SNMPERR_SUCCESS			Success.
 *	SNMPERR_SC_GENERAL_FAILURE	All errors, including KMT errs.
 *
 *
 * Convert a passphrase into a master user key, Ku, according to the
 * algorithm given in RFC 2274 concerning the SNMPv3 User Security Model (USM)
 * as follows:
 *
 * Expand the passphrase to fill the passphrase buffer space, if necessary,
 * concatenation as many duplicates as possible of P to itself.  If P is
 * larger than the buffer space, truncate it to fit.
 *
 * Then hash the result with the given hashtype transform.  Return
 * the result as Ku.
 *
 * If successful, kulen contains the size of the hash written to Ku.
 *
 * XXX	Should there be an option to store Ku in the KMT cache?  (!)
 */
int
generate_Ku(	oid	*hashtype,	u_int  hashtype_len,
		u_char	*P,		u_int  pplen,
		u_char	*Ku,		u_int *kulen)
{
	int		 rval   = SNMPERR_SUCCESS,
			 nbytes = USM_LENGTH_EXPANDED_PASSPHRASE;

	u_int		 transform,
			 i, pindex = 0;

	char		 buf[USM_LENGTH_KU_HASHBLOCK],
			*bufp;

	void		*context = NULL;

EM(1); /* */


	/*
	 * Sanity check.
	 */
	if ( !hashtype || !P || !Ku || !kulen
		|| (pplen<=0) || (*kulen<=0)
		|| (hashtype_len != USM_LENGTH_OID_TRANSFORM) )
	{
		QUITFUN(SNMPERR_GENERR, generate_Ku_quit);
	}


	/*
	 * Determine transform type.
	 */
	if ( ISTRANSFORM(hashtype, HMACMD5Auth) ) {
		transform = KMT_ALG_HMAC_MD5;	
		kmt_hash  = kmt_s_md5;

	} else if ( ISTRANSFORM(hashtype, HMACSHA1Auth) ) {
		transform = KMT_ALG_HMAC_SHA1;	
		kmt_hash  = kmt_s_sha1;

	} else {
		kmt_hash  = NULL;
		QUITFUN(SNMPERR_GENERR, generate_Ku_quit);
	}


	/*
	 * Expand passphrase and reduce it to a hash.
	 */
	rval = kmt_hash(KMT_CRYPT_MODE_INIT, &context, NULL, 0, NULL, NULL);
	QUITFUN(rval, generate_Ku_quit);

	while (nbytes > 0) {
		bufp = buf;
		for (i = 0; i < USM_LENGTH_KU_HASHBLOCK; i++) {
			*bufp++ = P[pindex++ % pplen];
		}

		rval = kmt_hash(KMT_CRYPT_MODE_UPDATE,
				&context,
				buf,	USM_LENGTH_KU_HASHBLOCK,
				NULL,	NULL);
		QUITFUN(rval, generate_Ku_quit);

		nbytes -= USM_LENGTH_KU_HASHBLOCK;
	}

	rval = kmt_hash(KMT_CRYPT_MODE_FINAL, &context, NULL, 0, &Ku, kulen);
	QUITFUN(rval, generate_Ku_quit);


generate_Ku_quit:
	memset(buf, 0, USM_LENGTH_KU_HASHBLOCK);
	SNMP_FREE(context);

	return rval;

}  /* end generate_Ku() */




/*******************************************************************-o-******
 * generate_kul
 *
 * Parameters:
 *	*hashtype
 *	 hashtype_len
 *	*engineID
 *	 engineID_len
 *	*Ku		Master key for a given user.
 *	 kulen		Length of Ku in bytes.
 *	*Kul		Localized key for a given user at engineID.
 *	*kullen		Length of Kul buffer (IN); Length of Kul key (OUT).
 *      
 * Returns:
 *	SNMPERR_SUCCESS			Success.
 *	SNMPERR_SC_GENERAL_FAILURE	All errors, including KMT errs.
 *
 *
 * Ku must be the proper length (currently fixed) for the given hashtype.
 *
 * Upon successful return, Kul contains the localized form of Ku at
 * engineID, and the length of the key is stored in kul_len.
 *
 * FIX	[Cite RFC and U. Blumenthal, et al.'s paper.  XXX]
 *
 *
 * ASSUMES  SNMP_MAXBUF > sizeof(Ku + engineID + Ku).
 *
 * XXX	An engineID of any length is accepted, even if larger than
 *	what is spec'ed for the textual convention.
 */
int
generate_kul(	oid	*hashtype,	u_int  hashtype_len,
		u_char	*engineID,	u_int  engineID_len,
		u_char	*Ku,		u_int  ku_len,
		u_char	*Kul,		u_int *kul_len)
{
	int		 rval    = SNMPERR_SUCCESS;
	u_int		 transform,
			 properlength,
			 nbytes  = 0;

	char		 buf[SNMP_MAXBUF];
	void		*context = NULL;

EM(1); /* */


	/*
	 * Sanity check.
	 */
	if ( !hashtype || !engineID || !Ku || *Kul || !kul_len
		|| (engineID_len<=0) || (ku_len<=0) || (*kul_len<=0)
		|| (hashtype_len != USM_LENGTH_OID_TRANSFORM) )
	{
		QUITFUN(SNMPERR_GENERR, generate_kul_quit);
	}


	/*
	 * Determine transform type.
	 */
	if ( ISTRANSFORM(hashtype, HMACMD5Auth) ) {
		transform	= KMT_ALG_HMAC_MD5;	
		properlength	= BYTESIZE(SNMP_TRANS_AUTHLEN_HMACMD5);
		kmt_hash	= kmt_s_md5;

	} else if ( ISTRANSFORM(hashtype, HMACSHA1Auth) ) {
		transform	= KMT_ALG_HMAC_SHA1;	
		properlength	= BYTESIZE(SNMP_TRANS_AUTHLEN_HMACSHA1);
		kmt_hash	= kmt_s_sha1;

	} else {
		kmt_hash  = NULL;
		QUITFUN(SNMPERR_GENERR, generate_kul_quit);
	}


	if (ku_len != properlength) {
		QUITFUN(SNMPERR_GENERR, generate_kul_quit);
	}



	/*
	 * Concatenate Ku and engineID properly, then hash the result.
	 * Store it in Kul.
	 */
	memcpy(buf,	   Ku,		nbytes += ku_len);
	memcpy(buf+nbytes, engineID,	nbytes += engineID_len);
	memcpy(buf+nbytes, Ku,		nbytes += ku_len);

	rval = kmt_hash(KMT_CRYPT_MODE_ALL,
			&context,
			buf,	nbytes,
			&Kul,	kul_len);
	QUITFUN(rval, generate_kul_quit);
		

generate_kul_quit:
	SNMP_FREE(context);
	return rval;

}  /* end generate_kul() */




/*******************************************************************-o-******
 * encode_keychange
 *
 * Parameters:
 *	*hashtype
 *	 hashtype_len
 *	*oldkey
 *	 olekey_len
 *	*newkey
 *	 newkey_len
 *	*kcstring
 *	*kcstring_len
 *      
 * Returns:
 *	SNMPERR_SUCCESS			Success.
 *	SNMPERR_SC_GENERAL_FAILURE	All errors, including KMT errs.
 *
 *
 * Uses oldkey and acquired random bytes to encode newkey into kcstring
 * according to the rules of the KeyChange TC described in [cite RFC
 * section XXX].
 *
 * Upon successful return, *kcstring_len contains the length of the
 * encoded string.
 *
 *
 * ASSUMES	Old and new key are always equal to the transform type hash
 * 		output length.  This means *kcstring_len must also be
 *		exactly twice that same length.  XXX
 *
 * ASSUMES	The result is not ASN.1 encoded, the calling environment
 *		this.  FIX -- Tragic flaw?
 */
int
encode_keychange(	oid	*hashtype,	u_int  hashtype_len,
			u_char	*oldkey,	u_int  oldkey_len,
			u_char	*newkey,	u_int  newkey_len,
			u_char	*kcstring,	u_int *kcstring_len)
{
	int		 rval    = SNMPERR_SUCCESS;
	u_int		 transform,
			 properlength,
			 nbytes  = 0;

	u_int8_t	*bufp;
	void		*context = NULL;

EM(1); /* */

	/*
	 * Sanity check.
	 */
	if ( !hashtype || !oldkey || !newkey || !kcstring || !kcstring_len
		|| (oldkey_len<=0) || (newkey_len<=0) || (*kcstring_len<=0)
		|| (hashtype_len != USM_LENGTH_OID_TRANSFORM) )
	{
		QUITFUN(SNMPERR_GENERR, encode_keychange_quit);
	}


	/*
	 * Determine transform type.
	 */
	if ( ISTRANSFORM(hashtype, HMACMD5Auth) ) {
		transform	= KMT_ALG_HMAC_MD5;	
		properlength	= BYTESIZE(SNMP_TRANS_AUTHLEN_HMACMD5);
		kmt_hash	= kmt_s_md5;

	} else if ( ISTRANSFORM(hashtype, HMACSHA1Auth) ) {
		transform	= KMT_ALG_HMAC_SHA1;	
		properlength	= BYTESIZE(SNMP_TRANS_AUTHLEN_HMACSHA1);
		kmt_hash	= kmt_s_sha1;

	} else {
		kmt_hash  = NULL;
		QUITFUN(SNMPERR_GENERR, encode_keychange_quit);
	}


	if ( (oldkey_len != properlength) || (newkey_len != properlength)
		|| (*kcstring_len < (2*properlength)) )
	{
		QUITFUN(SNMPERR_GENERR, encode_keychange_quit);
	}



	/*
	 * Use the old key and some random bytes to encode the new key
	 * in the KeyChange TC format:
	 *	. Get random bytes (store in first half of kcstring),
	 *	. Hash (oldkey | random_bytes) (into second half of kcstring),
	 *	. XOR hash and newkey (into second half of kcstring).
	 *
	 * Getting the wrong number of random bytes is considered an error.
	 */
	nbytes = properlength;
	rval   = sc_random(kcstring, &nbytes);
	QUITFUN(rval, encode_keychange_quit);
	if (nbytes != properlength) {
		QUITFUN(SNMPERR_GENERR, encode_keychange_quit);
	}


	rval = kmt_hash(KMT_CRYPT_MODE_INIT|KMT_CRYPT_MODE_UPDATE,
			&context,
			oldkey, properlength,
			NULL, NULL);
	QUITFUN(rval, encode_keychange_quit);

	bufp = (u_int8_t *) kcstring+properlength;
	rval = kmt_hash(KMT_CRYPT_MODE_UPDATE|KMT_CRYPT_MODE_FINAL,
			&context,
			kcstring, properlength,
			&bufp, kcstring_len);
	*kcstring_len *= 2;
	QUITFUN(rval, encode_keychange_quit);


	kcstring += properlength;
	nbytes    = 0;
	while (nbytes++ < properlength) {
		*kcstring++ = *kcstring ^ *newkey++;
	}



encode_keychange_quit:
	if (rval != SNMPERR_SUCCESS) memset(kcstring, 0, *kcstring_len);
	SNMP_FREE(context);

	return rval;

}  /* end encode_keychange() */




/*******************************************************************-o-******
 * decode_keychange
 *
 * Parameters:
 *	*hashtype
 *	 hashtype_len
 *	*oldkey
 *	 olekey_len
 *	*kcstring
 *	 kcstring_len
 *	*newkey
 *	*newkey_len
 *      
 * Returns:
 *	SNMPERR_SUCCESS			Success.
 *	SNMPERR_SC_GENERAL_FAILURE	All errors, including KMT errs.
 *
 *
 * Decodes a string of bits encoded according to the KeyChange TC described
 * in [cite RFC section XXX].  The new key is extracted from *kcstring with
 * the aid of the old key.
 *
 * Upon successful return, *newkey_len contains the length of the new key.
 *
 *
 * ASSUMES	Old key and new key are the same length as the hashtype
 *		transform output.  Thus kcstring_len must be passed
 *		as at least twice that same size.
 *
 * ASSUMES	kcstring is NOT ASN.1 encoded.  FIX -- Tragic flaw?
 */
int
decode_keychange(	oid	*hashtype,	u_int  hashtype_len,
			u_char	*oldkey,	u_int  oldkey_len,
			u_char	*kcstring,	u_int  kcstring_len,
			u_char	*newkey,	u_int *newkey_len)
{
	int		 rval    = SNMPERR_SUCCESS;
	u_int		 transform,
			 properlength,
			 nbytes  = 0;

	char		*bufp;
	void		*context = NULL;

EM(1); /* */


	/*
	 * Sanity check.
	 */
	if ( !hashtype || !oldkey || !kcstring || !newkey || !newkey_len
		|| (oldkey_len<=0) || (kcstring_len<=0) || (*newkey_len<=0)
		|| (hashtype_len != USM_LENGTH_OID_TRANSFORM) )
	{
		QUITFUN(SNMPERR_GENERR, decode_keychange_quit);
	}


	/*
	 * Determine transform type.
	 */
	if ( ISTRANSFORM(hashtype, HMACMD5Auth) ) {
		transform	= KMT_ALG_HMAC_MD5;	
		properlength	= BYTESIZE(SNMP_TRANS_AUTHLEN_HMACMD5);
		kmt_hash	= kmt_s_md5;

	} else if ( ISTRANSFORM(hashtype, HMACSHA1Auth) ) {
		transform	= KMT_ALG_HMAC_SHA1;	
		properlength	= BYTESIZE(SNMP_TRANS_AUTHLEN_HMACSHA1);
		kmt_hash	= kmt_s_sha1;

	} else {
		kmt_hash  = NULL;
		QUITFUN(SNMPERR_GENERR, decode_keychange_quit);
	}


	if ( (oldkey_len != properlength) || (kcstring_len != (2*properlength))
		|| (*newkey_len < properlength) )
	{
		QUITFUN(SNMPERR_GENERR, decode_keychange_quit);
	}



	/*
	 * Use the old key and the given KeyChange TC string to recover
	 * the new key:
	 *	. Hash (oldkey | random_bytes) (into newkey),
	 *	. XOR hash and encoded (second) half of kcstring (into newkey).
	 *
	 * Getting the wrong number of random bytes is considered an error.
	 */
	rval = kmt_hash(KMT_CRYPT_MODE_INIT|KMT_CRYPT_MODE_UPDATE,
			&context,
			oldkey, properlength,
			NULL, NULL);
	QUITFUN(rval, decode_keychange_quit);

	rval = kmt_hash(KMT_CRYPT_MODE_UPDATE|KMT_CRYPT_MODE_FINAL,
			&context,
			kcstring, properlength,
			&newkey, newkey_len);
	QUITFUN(rval, decode_keychange_quit);


	bufp   = kcstring+properlength;
	nbytes = 0;
	while (nbytes++ < properlength) {
		*newkey++ = *newkey ^ *kcstring++;
	}



decode_keychange_quit:
	if (rval != SNMPERR_SUCCESS) memset(newkey, 0, properlength);
	SNMP_FREE(context);

	return rval;

}  /* end decode_keychange() */
