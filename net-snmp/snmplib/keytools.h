/*
 * keytools.h
 */

#ifndef _KEYTOOLS_H
#define _KEYTOOLS_H


#define USM_LENGTH_EXPANDED_PASSPHRASE	(1024 * 1024)	/* 1Meg. */
#define USM_LENGTH_KU_HASHBLOCK		64		/* In bytes. */




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

#endif /* _KEYTOOLS_H */

