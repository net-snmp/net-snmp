/*
 * keytools.h
 */

#ifndef _KEYTOOLS_H
#define _KEYTOOLS_H



/*
 * Prototypes.h
 */
int	generate_kul __P((	u_char	*engineID,      u_int   engineIDLen,
				u_char	*Ku,		u_int	kulen,
				u_char	**Kul,		u_int	*kullen));

int	generate_Ku __P((u_char *P, u_int pplen, u_char **Ku, u_int *kulen));

int	do_keychange __P((
			u_char *userSecurityName,	int isOwn,
			u_char *newkey,			u_int newkey_len,
			u_char **kcstring,		u_int *kcstring_len));

#endif /* _KEYTOOLS_H */
