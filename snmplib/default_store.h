/* default_store.h: storage space for defaults */
#ifndef DEFAULT_STORE_H
#define DEFAULT_STORE_H

#define DS_MAX_IDS 3
#define DS_MAX_SUBIDS 10

#define DS_LIBRARY_ID     0
#define DS_APPLICATION_ID 1
#define DS_TOKEN_ID       2

struct ds_read_config {
   u_char type;
   char  *token;
   int    storeid;
   int    which;
   struct ds_read_config *next;
};
   
int ds_set_boolean(int storeid, int which, int value);
int ds_get_boolean(int storeid, int which);
int ds_set_int(int storeid, int which, int value);
int ds_get_int(int storeid, int which);
int ds_set_string(int storeid, int which, char *value);
char *ds_get_string(int storeid, int which);

#endif /* DEFAULT_STORE_H */
