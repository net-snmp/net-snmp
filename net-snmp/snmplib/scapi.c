/*
 * scapi.c
 *
 * ASSUMES KMT.
 *
 * Keys are stored in the KMT cache using names derived from the key
 * material itself.  This assumes that if two entities configure the same
 * key, there is no state that carries over in the cache for that key
 * from use to use.  Partial hashes/crypts are not allowed, and IVs must
 * be reset each time.  XXX -- tragic error?
 *
 * XXX	Decide whether to return SNMPERR_* codes, or whether to pass through
 *	KMT_ERR_* codes.  Must be all of one or the other...
 *
 * XXX	Bound all functions with HAVE_LIBKMT?
 * XXX	Put "determine transform type" into a function?
 */

#include "all_system.h"
#include "all_general_local.h" /* */




/*******************************************************************-o-******
 * sc_init
 *
 * Returns:
 *	SNMPERR_SUCCESS		Success.
 */
int
sc_init(void)
{
	int		rval = SNMPERR_SUCCESS;

#ifdef HAVE_LIBKMT
	kmt_init();
#else
	rval = SNMPERR_SC_NOT_CONFIGURED;
#endif

	return rval;

}  /* end sc_init() */




/*******************************************************************-o-******
 * sc_shutdown
 *
 * Returns:
 *	SNMPERR_SUCCESS		Success.
 */
int
sc_shutdown(void)
{
	int		rval = SNMPERR_SUCCESS;

#ifdef HAVE_LIBKMT
	kmt_close();
#else
	rval = SNMPERR_SC_NOT_CONFIGURED;
#endif

	return rval;

}  /* end sc_shutdown() */




/*******************************************************************-o-******
 * sc_random
 *
 * Parameters:
 *	*buf		Pre-allocated buffer.
 *	*buflen 	Size of buffer.
 *      
 * Returns:
 *	SNMPERR_SUCCESS			Success.
 *	SNMPERR_SC_GENERAL_FAILURE	Any KMT error.
 */
int
sc_random(u_char *buf, u_int *buflen)
{
	int		rval = SNMPERR_SUCCESS;

/* EM(1); /* */

	rval = kmt_random(KMT_RAND_DEFAULT, buf, *buflen);
	if (rval < 0) {
		rval = SNMPERR_SC_GENERAL_FAILURE;
	} else {
		*buflen = rval;
		rval = SNMPERR_SUCCESS;
	}


	return rval;

}  /* end sc_random() */



/*******************************************************************-o-******
 * sc_generate_keyed_hash
 *
 * Parameters:
 *	 authtype	Type of authentication transform.
 *	 authtypelen
 *	*key		Pointer to key (Kul) to use in keyed hash.
 *	 keylen		Length of key in bytes.
 *	*message	Pointer to the message to hash.
 *	 msglen		Length of the message.
 *	*MAC		Will be returned with allocated bytes containg hash.
 *	*maclen		Length of the hash buffer in bytes.
 *      
 * Returns:
 *	SNMPERR_SUCCESS			Success.
 *	SNMPERR_SC_GENERAL_FAILURE	All errs, including KMT errors.
 *
 *
 * A hash of the first msglen bytes of message using a keyed hash defined
 * by authtype is created and stored in MAC.  Allocated bytes for its
 * storage and its length, maclen, are returned.
 *
 * *maclen is set to the number of bytes stored in MAC.
 *
 * ASSUMED that the number of hash bits is a multiple of 8.
 */
int
sc_generate_keyed_hash(	oid	*authtype,	int    authtypelen,
			u_char	*key,		u_int  keylen,
			u_char	*message,	u_int  msglen,
			u_char	*MAC,		u_int *maclen)
{
	int		rval	= SNMPERR_SUCCESS;
	u_int		transform,
			properlength;

	KMT_KEY_LIST	*kmtkeylist	= NULL;

/* EM(1); /* */


	/*
	 * Sanity check.
	 */
	if ( !authtype || !key || !message || !MAC || !maclen
		|| (keylen<=0) || (msglen<=0) || (*maclen<=0)
		|| (authtypelen != USM_LENGTH_OID_TRANSFORM) )
	{
		QUITFUN(SNMPERR_GENERR, sc_generate_keyed_hash_quit);
	}


	/*
	 * Determine transform type.
	 */
	if ( ISTRANSFORM(authtype, HMACMD5Auth) ) {
		transform    = KMT_ALG_HMAC_MD5;	
		properlength = BYTESIZE(SNMP_TRANS_AUTHLEN_HMACMD5);

	} else if ( ISTRANSFORM(authtype, HMACSHA1Auth) ) {
		transform    = KMT_ALG_HMAC_SHA1;	
		properlength = BYTESIZE(SNMP_TRANS_AUTHLEN_HMACSHA1);

	} else {
		QUITFUN(SNMPERR_GENERR, sc_generate_keyed_hash_quit);
	}

	if ( (*maclen < properlength) || (keylen < properlength) ) {
		QUITFUN(SNMPERR_GENERR, sc_generate_keyed_hash_quit);
	}


	/*
	 * Lookup key in KMT.
	 * Perform the keyed hash over message, store the result in MAC.
	 */
	rval = sc_internal_kmtlookup(	transform,
					key, keylen, properlength,
					&kmtkeylist, TRUE);
	QUITFUN(rval, sc_generate_keyed_hash_quit);
		
	rval = kmt_sign_data(	KMT_CRYPT_MODE_ALL,
				kmt_keylist_key(kmtkeylist), NULL,
				message, msglen,
				&MAC, maclen);
	*maclen = properlength;
	QUITFUN(rval, sc_generate_keyed_hash_quit);



sc_generate_keyed_hash_quit:
	kmt_release_keylist(&kmtkeylist);
	return rval;

}  /* end sc_generate_keyed_hash() */




/*******************************************************************-o-******
 * sc_check_keyed_hash
 *
 * Parameters:
 *	 authtype	Transform type of authentication hash.
 *	*key		Key bits in a string of bytes.
 *	 keylen		Length of key in bytes.
 *	*message	Message for which to check the hash.
 *	 msglen		Length of message.
 *	*MAC		Given hash.
 *	 maclen		Length of given hash.
 *      
 * Returns:
 *	SNMPERR_SUCCESS	Success.
 *	SNMP_SC_GENERAL_FAILURE	Any error, including KMT errs.
 */
int
sc_check_keyed_hash(	oid	*authtype,	int   authtypelen,
			u_char	*key,		u_int keylen,
			u_char	*message,	u_int msglen,
			u_char	*MAC,		u_int maclen)
{
	int		rval	= SNMPERR_SUCCESS;
	u_int		transform,
			properlength;

	KMT_KEY_LIST	*kmtkeylist	= NULL;

/* EM(1); /* */


	/*
	 * Sanity check.
	 */
	if ( !authtype || !key || !message || !MAC 
		|| (keylen<=0) || (msglen<=0) || (maclen<=0)
		|| (authtypelen != USM_LENGTH_OID_TRANSFORM) )
	{
		QUITFUN(SNMPERR_GENERR, sc_check_keyed_hash_quit);
	}


	/*
	 * Determine transform type.
	 */
	if ( ISTRANSFORM(authtype, HMACMD5Auth) ) {
		transform    = KMT_ALG_HMAC_MD5;	
		properlength = BYTESIZE(SNMP_TRANS_AUTHLEN_HMACMD5);

	} else if ( ISTRANSFORM(authtype, HMACSHA1Auth) ) {
		transform    = KMT_ALG_HMAC_SHA1;	
		properlength = BYTESIZE(SNMP_TRANS_AUTHLEN_HMACSHA1);

	} else {
		QUITFUN(SNMPERR_GENERR, sc_check_keyed_hash_quit);
	}

	if ( (maclen < properlength) || (keylen < properlength) ) {
		QUITFUN(SNMPERR_GENERR, sc_check_keyed_hash_quit);
	}



	/*
	 * Lookup key in KMT.
	 * Check the keyed hash for message.
	 */
	rval = sc_internal_kmtlookup(	transform,
					key, keylen, properlength,
					&kmtkeylist, FALSE);
	QUITFUN(rval, sc_check_keyed_hash_quit);
		
	rval = kmt_verify_data(	KMT_CRYPT_MODE_ALL,
				kmt_keylist_key(kmtkeylist), NULL,
				message, msglen,
				MAC, maclen);

	QUITFUN(rval, sc_check_keyed_hash_quit);


sc_check_keyed_hash_quit:
	kmt_release_keylist(&kmtkeylist);
	return rval;

}  /* end sc_check_keyed_hash() */




/*******************************************************************-o-******
 * sc_encrypt
 *
 * Parameters:
 *	 privtype	Type of privacy cryptographic transform.
 *	*key		Key bits for crypting.
 *	 keylen		Length of key (buffer) in bytes.
 *	*iv		IV bits for crypting.
 *	 ivlen		Length of iv (buffer) in bytes.
 *	*plaintext	Plaintext to crypt.
 *	 ptlen		Length of plaintext.
 *	*ciphertext	Ciphertext to crypt.
 *	*ctlen		Length of ciphertext.
 *      
 * Returns:
 *	SNMPERR_SUCCESS		Success.
 *	SNMPERR_SC_GENERAL_FAILURE	Any error, including KMT errs.
 *
 *
 * Encrypt plaintext into ciphertext using key and iv.
 *
 * ctlen contains actual number of crypted bytes in ciphertext upon
 * successful return.
 */
int
sc_encrypt(	oid    *privtype,	int   privtypelen,
		u_char *key,		u_int keylen,
		u_char *iv,		u_int ivlen,
		u_char *plaintext,	u_int ptlen,
		u_char *ciphertext,	u_int *ctlen)
{
	int		rval	= SNMPERR_SUCCESS;
	u_int		transform,
			properlength,
			properlength_iv;

	KMT_KEY_LIST	*kmtkeylist = NULL;

/* EM(1); /* */


	/*
	 * Sanity check.
	 */
	if ( !privtype || !key || !iv || !plaintext || !ciphertext || !ctlen
		|| (keylen<=0) || (ivlen<=0) || (ptlen<=0) || (*ctlen<=0)
		|| (privtypelen != USM_LENGTH_OID_TRANSFORM) )
	{
		QUITFUN(SNMPERR_GENERR, sc_encrypt_quit);
	}


	/*
	 * Determine privacy transform.
	 */
	if ( ISTRANSFORM(privtype, DESPriv) ) {
		transform	= KMT_ALG_DES;	
		properlength	= BYTESIZE(SNMP_TRANS_PRIVLEN_1DES);
		properlength_iv	= BYTESIZE(SNMP_TRANS_PRIVLEN_1DES_IV);

	} else {
		QUITFUN(SNMPERR_GENERR, sc_encrypt_quit);
	}

	if ( (keylen<properlength) || (ivlen<properlength_iv) ) {
		QUITFUN(SNMPERR_GENERR, sc_encrypt_quit);
	}


	/*
	 * Lookup key in KMT.
	 * Encrypt plaintext into ciphertext.
	 */
	rval = sc_internal_kmtlookup(	transform,
					key, keylen, properlength,
					&kmtkeylist, TRUE);
	QUITFUN(rval, sc_encrypt_quit);

	rval = kmt_encrypt_data(KMT_CRYPT_MODE_ALL,
				kmt_keylist_key(kmtkeylist), NULL,
				plaintext, ptlen,
				&ciphertext, ctlen,
				&iv);
	QUITFUN(rval, sc_encrypt_quit);


sc_encrypt_quit:
	kmt_release_keylist(&kmtkeylist);
	return rval;

}  /* end sc_encrypt() */




/*******************************************************************-o-******
 * sc_decrypt
 *
 * Parameters:
 *	 privtype
 *	*key
 *	 keylen
 *	*iv
 *	 ivlen
 *	*ciphertext
 *	 ctlen
 *	*plaintext
 *	*ptlen
 *      
 * Returns:
 *	SNMPERR_SUCCESS		Success.
 *      SNMPERR_SC_GENERAL_FAILURE      Any error, including KMT errs.
 *
 *
 * Decrypt ciphertext into plaintext using key and iv.
 *
 * ptlen contains actual number of plaintext bytes in plaintext upon
 * successful return.
 */
int
sc_decrypt(	oid    *privtype,	int   privtypelen,
		u_char *key,		u_int keylen,
		u_char *iv,		u_int ivlen,
		u_char *ciphertext,	u_int ctlen,
		u_char *plaintext,	u_int *ptlen)
{
	int		rval	= SNMPERR_SUCCESS;
	u_int		transform,
			properlength,
			properlength_iv;

	KMT_KEY_LIST	*kmtkeylist = NULL;

/* EM(1); /* */


	/*
	 * Sanity check.
	 */
	if ( !privtype || !key || !iv || !plaintext || !ciphertext || !ptlen
		|| (ctlen<=0) || (*ptlen<=0)
		|| (privtypelen != USM_LENGTH_OID_TRANSFORM) )
	{
		QUITFUN(SNMPERR_GENERR, sc_decrypt_quit);
	}


	/*
	 * Determine privacy transform.
	 */
	if ( ISTRANSFORM(privtype, DESPriv) ) {
		transform	= KMT_ALG_DES;	
		properlength	= BYTESIZE(SNMP_TRANS_PRIVLEN_1DES);
		properlength_iv	= BYTESIZE(SNMP_TRANS_PRIVLEN_1DES_IV);

	} else {
		QUITFUN(SNMPERR_GENERR, sc_decrypt_quit);
	}

	if ( (keylen<properlength) || (ivlen<properlength_iv) ) {
		QUITFUN(SNMPERR_GENERR, sc_decrypt_quit);
	}


	/*
	 * Lookup key in KMT.
	 * Decrypt ciphertext into plaintext.
	 */
	rval = sc_internal_kmtlookup(	transform,
					key, keylen, properlength,
					&kmtkeylist, FALSE);
	QUITFUN(rval, sc_decrypt_quit);

	rval = kmt_decrypt_data(KMT_CRYPT_MODE_ALL,
				kmt_keylist_key(kmtkeylist), NULL,
				ciphertext, ctlen,
				&plaintext, ptlen,
				&iv);
	QUITFUN(rval, sc_decrypt_quit);


sc_decrypt_quit:
	kmt_release_keylist(&kmtkeylist);
	return rval;

}  /* end sc_decrypt() */


	

/*******************************************************************-o-******
 * sc_internal_kmtlookup
 *
 * Parameters:
 *	  transform		Cryptographic algorithm associated with key.
 *	 *key			Key bits in a string of bytes.
 *	  keylen		Number of bytes in key.
 *	  properlen		Number of bytes in a properly formed key.
 *	**kmtkeylist		Hook to return KMT_KEY_LIST with key entry.
 *	  dospecify		TRUE if a new key should be added to KMT cache.
 *      
 * Returns:
 *	SNMPERR_SUCCESS			Success.
 *	SNMPERR_SC_GENERAL_FAILURE	Any err, including KMT errors.
 *
 * Lookup the key in the KMT cache.
 * Add a new key if the requested key is not found.
 * Always returns one or 0 keys.
 *
 * NOTE  Default "mode" is proper for all currently known SNMPv3 algorithms.
 * NOTE  Identical keys may be instantiated with different transforms.
 *
 * ASSUME	No transform has more than one mode of use in the SNMP context.
 */
int
sc_internal_kmtlookup(	u_int 	 transform, 
			u_char	*key,		u_int		  keylen,
			u_int	 properlength,	KMT_KEY_LIST	**kmtkeylist,
			int	 dospecify)
{
	int	 rval		 = SNMPERR_SUCCESS,
		 tmode		 = 0,			/* KMT default. */
		 keyname_len;
	char	*keyname	 = NULL;

	KMT_ATTRIBUTE	kmt_attribute = { KMT_ATTR_ALG, transform };


/* EM(1); /* */


	*kmtkeylist = NULL;
	keyname_len = binary_to_hex(key, keylen, &keyname);

	rval = kmt_get_keylist_from_cache(
				kmtkeylist, keyname, &kmt_attribute, 1);

	if (dospecify && rval != KMT_ERR_SUCCESS) {
		rval = kmt_specify_key(	keyname, properlength * 8,
					transform, tmode,
					NULL, key, keylen,
					kmtkeylist);

		if (rval != KMT_ERR_SUCCESS) {
			rval = SNMPERR_SC_GENERAL_FAILURE;

		} else {
			kmt_set_expiry(kmt_keylist_key(*kmtkeylist), 0, 0);
		}
	}

	if (ISDF(KMTDUMP1) && *kmtkeylist) {
		fprintf(stdout, "\n");
		kmt_dump_keylist(*kmtkeylist, "In sc_internal_kmtlookup()");
	}


        free_zero(keyname, keyname_len);

	return rval;

}  /* end sc_internal_kmtlookup() */

