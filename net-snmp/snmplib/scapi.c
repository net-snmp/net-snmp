/*
 * scapi.c
 *
 * ASSUMES KMT.
 *
 * Keys are stored in the KMT cache using names derived from the key
 * material itself.  This assumes that if two entities configure the same
 * key, there is no state that carries over in the cache for that key
 * from use to use.  Partial hashes/crypts are not allowed, and IVs must
 * be reset each time.  XXX -- fatal error?
 *
 * XXX	Decide whether to return SNMPERR_* codes, or whether to pass through
 *	KMT_ERR_* codes.  Must be all of one or the other...
 */

#include "all_system.h"
#include "all_general_local.h" /* */




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

EM(1); /* */

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
 *	  authtype	Type of authentication transform.
 *	 *key		Pointer to key (Kul) to use in keyed hash.
 *	  keylen	Length of key in bytes.
 *	 *message	Pointer to the message to hash.
 *	  msglen	Length of the message.
 *	**MAC		Will be returned with allocated bytes containg hash.
 *	 *maclen	Length of the hash buffer in bytes.
 *      
 * Returns:
 *	SNMPERR_SUCCESS		Success.
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
sc_generate_keyed_hash(	oid	*authtype,	int authtypelen,
			u_char	*key,		u_int keylen,
			u_char	*message,	u_int msglen,
			u_char	*MAC,		u_int *maclen)
{
	int		rval		= SNMPERR_SUCCESS;
	u_int		transform,
			properlength,
			keyname_len	= 0;

	char		*keyname	= NULL;
	KMT_KEY		*kmtkey		= NULL;
	KMT_KEY_LIST	*kmtkeylist	= NULL;

EM(1); /* */


	/*
	 * Sanity check.
	 */
	if ( !key || !message || !MAC || !maclen
		|| (keylen <= 0) || (msglen <= 0) || (*maclen <= 0) )
	{
		rval = SNMPERR_SC_GENERAL_FAILURE;
		goto sc_generate_keyed_hash_quit;
	}


	if ( !strncmp((char *) authtype,
		(char *) usmHMACMD5AuthProtocol, USM_LENGTH_OID_TRANSFORM) )
	{
		transform    = KMT_ALG_HMAC_MD5;	
		properlength = BYTESIZE(SNMP_TRANS_AUTHLEN_HMACMD5);

	} else if ( !strncmp((char *) authtype,
		(char *) usmHMACSHA1AuthProtocol, USM_LENGTH_OID_TRANSFORM) )
	{
		transform    = KMT_ALG_HMAC_SHA1;	
		properlength = BYTESIZE(SNMP_TRANS_AUTHLEN_HMACSHA1);

	} else {
		rval = SNMPERR_SC_GENERAL_FAILURE;
		goto sc_generate_keyed_hash_quit;
	}


	if ( (*maclen < properlength) || (keylen < properlength) ) {
		rval = SNMPERR_SC_GENERAL_FAILURE;
		goto sc_generate_keyed_hash_quit;
	}

	
	/*
	 * Lookup the key in the KMT cache.  Add a new key if the requested
	 * key is not found.
	 *
	 * ASSUME the result is 1 or 0 keys.
	 *
	 * FIX	Isolate this as a function.
	 */
	keyname_len = binary_to_hex(key, keylen, &keyname);

	rval = kmt_get_keylist_from_cache(&kmtkeylist, keyname, NULL, 0);

	if (rval != KMT_ERR_SUCCESS) {
		rval = kmt_specify_key(	keyname, properlength * 8,
					transform, 0,
					NULL, key, keylen,
					&kmtkeylist);

		if (rval != KMT_ERR_SUCCESS) {
			rval = SNMPERR_SC_GENERAL_FAILURE;
			goto sc_generate_keyed_hash_quit;
		}

		kmt_set_expiry(kmt_keylist_key(kmtkeylist), 0, 0);
	}



	/*
	 * Perform the keyed hash over message, store the result in MAC.
	 */
	rval = kmt_sign_data(	KMT_CRYPT_MODE_ALL,
				kmt_keylist_key(kmtkeylist), NULL,
				message, msglen,
				&MAC, maclen);

	*maclen = properlength;

	if (rval != KMT_ERR_SUCCESS) {
		rval = SNMPERR_SC_GENERAL_FAILURE;
		goto sc_generate_keyed_hash_quit;
	}



sc_generate_keyed_hash_quit:
	kmt_release_keylist(&kmtkeylist);
	SNMP_FREE(keyname);

	return rval;

}  /* end sc_generate_keyed_hash() */




/*******************************************************************-o-******
 * sc_check_keyed_hash
 *
 * Parameters:
 *	 authtype
 *	*key
 *	*message
 *	 msglen
 *	*MAC
 *	 maclen
 *      
 * Returns:
 *	SNMPERR_SUCCESS		Success.
 */
int
sc_check_keyed_hash(	oid	*authtype,	int   authtypelen,
			u_char	*key,		u_int keylen,
			u_char	*message,	u_int msglen,
			u_char	*MAC,		u_int maclen)
{
	int		rval = SNMPERR_SUCCESS;

EM0(1, "UNIMPLEMENTED");	/* EM(1); /* */

sc_check_keyed_hash_quit:
	return rval;

}  /* end sc_check_keyed_hash() */




/*******************************************************************-o-******
 * sc_encrypt
 *
 * Parameters:
 *	 privtype
 *	*key
 *	 keylen
 *	*iv
 *	 ivlen
 *	*plaintext
 *	 ptlen
 *	*ciphertext
 *	*ctlen
 *      
 * Returns:
 *	SNMPERR_SUCCESS		Success.
 */
int
sc_encrypt(	oid    *privtype,	int   privtypelen,
		u_char *key,		u_int keylen,
		u_char *iv,		u_int ivlen,
		u_char *plaintext,	u_int ptlen,
		u_char *ciphertext,	u_int *ctlen)
{
	int		rval = SNMPERR_SUCCESS;

EM0(1, "UNIMPLEMENTED");	/* EM(1); /* */

sc_encrypt_quit:
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
 */
int
sc_decrypt(	oid    *privtype,	int   privtypelen,
		u_char *key,		u_int keylen,
		u_char *iv,		u_int ivlen,
		u_char *ciphertext,	u_int ctlen,
		u_char *plaintext,	u_int *ptlen)
{
	int		rval = SNMPERR_SUCCESS;

EM0(1, "UNIMPLEMENTED");	/* EM(1); /* */

sc_decrypt_quit:
	return rval;

}  /* end sc_decrypt() */

