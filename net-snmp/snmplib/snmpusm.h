/* 
 * snmpusm.h
 *
 * Header file for USM support.
 */

#ifndef SNMPUSM_H
#define SNMPUSM_H


/*
 * Numeric MIB names for auth and priv transforms.
 */
static oid usmNoAuthProtocol[]       = { 1,3,6,1,6,3,10,1,1,1 };
static oid usmHMACMD5AuthProtocol[]  = { 1,3,6,1,6,3,10,1,1,2 };
static oid usmHMACSHA1AuthProtocol[] = { 1,3,6,1,6,3,10,1,1,3 };

static oid usmNoPrivProtocol[]       = { 1,3,6,1,6,3,10,1,2,1 };
static oid usmDESPrivProtocol[]      = { 1,3,6,1,6,3,10,1,2,2 };

#define USM_LENGTH_OID_TRANSFORM	10

#define USM_ERR_NO_ERROR			(-1300)
#define USM_ERR_GENERIC_ERROR			(-1301)
#define USM_ERR_UNKNOWN_SECURITY_NAME		(-1302)
#define USM_ERR_UNSUPPORTED_SECURITY_LEVEL	(-1303)
#define USM_ERR_ENCRYPTION_ERROR		(-1304)
#define USM_ERR_AUTHENTICATION_FAILURE		(-1305)

/* struct usmUser: a structure to represent a given user in a list */

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



/* Note: Any changes made to this structure need to be reflected in
   the following functions: */

int usm_generate_out_msg __P((int, u_char *, int, int, int, u_char *,int,
			      u_char *, int, int, u_char *, int, void *,
			      u_char *, int *, u_char **, int *));

int usm_process_in_msg __P((int, int, u_char *, int, int, u_char *, int,
			    u_char *, int *, u_char *, int *, u_char **, int *,
			    int *, void **));

int             usm_check_secLevel(int level, struct usmUser *user);
struct usmUser *usm_get_userList();
struct usmUser *usm_get_user(char *engineID, int engineIDLen, char *name);
struct usmUser *usm_get_user_from_list(char *engineID, int engineIDLen,
                                       char *name, struct usmUser *userList);
struct usmUser *usm_add_user(struct usmUser *user);
struct usmUser *usm_add_user_to_list(struct usmUser *user,
                                     struct usmUser *userList);
struct usmUser *usm_free_user(struct usmUser *user);
struct usmUser *usm_clone_user(struct usmUser *from);
struct usmUser *usm_create_initial_user();
struct usmUser *usm_cloneFrom_user(struct usmUser *from, struct usmUser *to);
struct usmUser *usm_remove_user(struct usmUser *user);
struct usmUser *usm_remove_user_from_list(struct usmUser *user,
                                          struct usmUser *userList);
char           *get_objid(char *line, oid **optr, int *len);
void            usm_save_users(char *token, char *type);
void            usm_save_users_from_list(struct usmUser *user, char *token,
                                        char *type);
void            usm_save_user(struct usmUser *user, char *token, char *type);
struct usmUser *usm_read_user(char *line);
void            usm_parse_config_usmUser(char *token, char *line);

void            usm_set_password(char *token, char *line);


#endif /* SNMPUSM_H */
