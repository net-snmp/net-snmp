/* 
 * snmpusm.h
 *
 * Header file for USM support.
 */

#ifndef SNMPUSM_H
#define SNMPUSM_H

#define WILDCARDSTRING "*"

/*
 * General.
 */
#define USM_MAX_ID_LENGTH		1024		/* In bytes. */
#define USM_MAX_SALT_LENGTH		64		/* In BITS. */
#define USM_MAX_KEYEDHASH_LENGTH	128		/* In BITS. */

#define USM_TIME_WINDOW			150



/*
 * USM message processing error codes. USM_ERR_* form used in snmpusm.c;
 * SNMPERR_USM_* form is defined in the snmp_api.h file.
 */
#define USM_ERR_NO_ERROR		   SNMPERR_SUCCESS
#define USM_ERR_GENERIC_ERROR		   SNMPERR_USM_GENERICERROR
#define USM_ERR_UNKNOWN_SECURITY_NAME	   SNMPERR_USM_UNKNOWNSECURITYNAME
#define USM_ERR_UNSUPPORTED_SECURITY_LEVEL SNMPERR_USM_UNSUPPORTEDSECURITYLEVEL
#define USM_ERR_ENCRYPTION_ERROR	   SNMPERR_USM_ENCRYPTIONERROR
#define USM_ERR_AUTHENTICATION_FAILURE	   SNMPERR_USM_AUTHENTICATIONFAILURE
#define USM_ERR_PARSE_ERROR		   SNMPERR_USM_PARSEERROR
#define USM_ERR_UNKNOWN_ENGINE_ID	   SNMPERR_USM_UNKNOWNENGINEID
#define USM_ERR_NOT_IN_TIME_WINDOW	   SNMPERR_USM_NOTINTIMEWINDOW
#define USM_ERR_DECRYPTION_ERROR	   SNMPERR_USM_DECRYPTIONERROR



/*
 * Structures.
 */
struct usmStateReference {
	u_char		*usr_name;
	u_int		 usr_name_length;
	u_char		*usr_engine_id;
	u_int		 usr_engine_id_length;
	oid		*usr_auth_protocol;
	u_int		 usr_auth_protocol_length;
	u_char		*usr_auth_key;
	u_int		 usr_auth_key_length;
	oid		*usr_priv_protocol;
	u_int		 usr_priv_protocol_length;
	u_char		*usr_priv_key;
	u_int		 usr_priv_key_length;
	u_int		 usr_sec_level;
};


/* struct usmUser: a structure to represent a given user in a list */
/* Note: Any changes made to this structure need to be reflected in
   the following functions: */

struct usmUser;
struct usmUser {
   u_char         *engineID;
   int            engineIDLen;
   u_char         *name;
   u_char         *secName;
   oid            *cloneFrom;
   int            cloneFromLen;
   oid            *authProtocol;
   int            authProtocolLen;
   u_char         *authKey;
   int            authKeyLen;
   oid            *privProtocol;
   int            privProtocolLen;
   u_char         *privKey;
   int            privKeyLen;
   u_char         *userPublicString;
   int            userStatus;
   int            userStorageType;
   struct usmUser *next;
   struct usmUser *prev;
};



/*
 * Prototypes.
 */
void	usm_set_reportErrorOnUnknownID (int value);

struct usmStateReference *
	usm_malloc_usmStateReference (void);

void	usm_free_usmStateReference (void *old);

int	usm_set_usmStateReference_name (
		struct usmStateReference	*ref,
		u_char				*name,
		u_int				 name_len);

int	usm_set_usmStateReference_engine_id (
		struct usmStateReference	*ref,
		u_char				*engine_id,
		u_int				 engine_id_len);

int	usm_set_usmStateReference_auth_protocol (
		struct usmStateReference *ref,
		oid *auth_protocol,
		u_int auth_protocol_len);

int	usm_set_usmStateReference_auth_key (
		struct usmStateReference *ref,
		u_char *auth_key,
		u_int auth_key_len);

int	usm_set_usmStateReference_priv_protocol (
		struct usmStateReference *ref,
		oid *priv_protocol,
		u_int priv_protocol_len);

int	usm_set_usmStateReference_priv_key (
		struct usmStateReference *ref,
		u_char *priv_key,
		u_int priv_key_len);

int	usm_set_usmStateReference_sec_level (
		struct usmStateReference *ref,
		u_int sec_level);

#ifdef SNMP_TESTING_CODE
void	emergency_print (u_char *field, u_int length);
#endif

int	asn_predict_int_length (int type, long number, int len);

int	asn_predict_length (int type, u_char *ptr, int u_char_len);

int	usm_set_salt (
		u_char		*iv,
		int		*iv_length,
		u_char		*priv_salt,
		int		 priv_salt_length,
		u_char		*msgSalt );

int	usm_parse_security_parameters (
		u_char  *secParams,
		u_int    remaining,
		u_char  *secEngineID,
		int     *secEngineIDLen,
		u_int   *boots_uint,
		u_int   *time_uint,
		u_char  *secName,
		int     *secNameLen,
		u_char  *signature,
		u_int   *signature_length,
		u_char  *salt,
		u_int   *salt_length,
		u_char **data_ptr);

int	usm_check_and_update_timeliness (
		u_char *secEngineID,
		int     secEngineIDLen,
		u_int   boots_uint,
		u_int   time_uint,
		int    *error);

void usm_set_reportErrorOnUnknownID (int value);
void usm_free_usmStateReference (void *old);

int usm_generate_out_msg (int, u_char *, int, int, int, u_char *,int,
			      u_char *, int, int, u_char *, int, void *,
			      u_char *, int *, u_char **, int *);

int usm_process_in_msg (int, int, u_char *, int, int, u_char *, int,
			    u_char *, int *, u_char *, int *, u_char **, int *,
			    int *, void **);

int             usm_check_secLevel(int level, struct usmUser *user);
struct usmUser *usm_get_userList();
struct usmUser *usm_get_user(char *engineID, int engineIDLen, char *name);
struct usmUser *usm_get_user_from_list(char *engineID, int engineIDLen,
                                       char *name, struct usmUser *userList,
                                       int use_default);
struct usmUser *usm_add_user(struct usmUser *user);
struct usmUser *usm_add_user_to_list(struct usmUser *user,
                                     struct usmUser *userList);
struct usmUser *usm_free_user(struct usmUser *user);
struct usmUser *usm_create_user(void);
struct usmUser *usm_create_initial_user();
struct usmUser *usm_cloneFrom_user(struct usmUser *from, struct usmUser *to);
struct usmUser *usm_remove_user(struct usmUser *user);
struct usmUser *usm_remove_user_from_list(struct usmUser *user,
                                          struct usmUser **userList);
char           *get_objid(char *line, oid **optr, int *len);
void            usm_save_users(char *token, char *type);
void            usm_save_users_from_list(struct usmUser *user, char *token,
                                        char *type);
void            usm_save_user(struct usmUser *user, char *token, char *type);
struct usmUser *usm_read_user(char *line);
void            usm_parse_config_usmUser(char *token, char *line);

void            usm_set_password(char *token, char *line);
void            usm_set_user_password(struct usmUser *user, char *token,
                                      char *line);
void            init_usm_post_config(void);

#endif /* SNMPUSM_H */
