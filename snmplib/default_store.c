/* default_store.h: storage space for defaults */

#include <config.h>
#include <sys/types.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_WINSOCK_H
#include <winsock.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_debug.h"
#include "snmp_logging.h"
#include "tools.h"
#include "read_config.h"
#include "default_store.h"
#include "read_config.h"
#include "system.h"

struct ds_read_config *ds_configs = NULL;

int ds_integers[DS_MAX_IDS][DS_MAX_SUBIDS];
char ds_booleans[DS_MAX_IDS][DS_MAX_SUBIDS/8];  /* bit vector storage. */
char *ds_strings[DS_MAX_IDS][DS_MAX_SUBIDS];  /* bit vector storage. */

int
ds_set_boolean(int storeid, int which, int value) {

  if (storeid >= DS_MAX_IDS || which >= DS_MAX_SUBIDS ||
      storeid < 0 || which < 0)
    return SNMPERR_GENERR;
    
  DEBUGMSGTL(("ds_set_boolean","Setting %d:%d = %d/%s\n", storeid, which,
              value, ((value)?"True":"False")));

  if (value > 0)
    ds_booleans[storeid][which/8] |= (1 << (which%8));
  else
    ds_booleans[storeid][which/8] &= (0xff7f >> (7-(which%8)));

  return SNMPERR_SUCCESS;
}

int
ds_toggle_boolean(int storeid, int which) {

  if (storeid >= DS_MAX_IDS || which >= DS_MAX_SUBIDS ||
      storeid < 0 || which < 0)
    return SNMPERR_GENERR;
    
  if ((ds_booleans[storeid][which/8] & (1 << (which % 8))) == 0)
    ds_booleans[storeid][which/8] |= (1 << (which%8));
  else
    ds_booleans[storeid][which/8] &= (0xff7f >> (7-(which%8)));

  DEBUGMSGTL(("ds_toggle_boolean","Setting %d:%d = %d/%s\n", storeid, which,
              ds_booleans[storeid][which/8],
              ((ds_booleans[storeid][which/8])?"True":"False")));

  return SNMPERR_SUCCESS;
}

int
ds_get_boolean(int storeid, int which) {
  if (storeid >= DS_MAX_IDS || which >= DS_MAX_SUBIDS ||
      storeid < 0 || which < 0)
    return SNMPERR_GENERR;

  return ((ds_booleans[storeid][which/8] & (1 << (which%8))) ? 1 : 0);
}

int
ds_set_int(int storeid, int which, int value) {
  if (storeid >= DS_MAX_IDS || which >= DS_MAX_SUBIDS ||
      storeid < 0 || which < 0)
    return SNMPERR_GENERR;

  DEBUGMSGTL(("ds_set_int","Setting %d:%d = %d\n", storeid, which, value));

  ds_integers[storeid][which] = value;
  return SNMPERR_SUCCESS;
}

int
ds_get_int(int storeid, int which) {
  if (storeid >= DS_MAX_IDS || which >= DS_MAX_SUBIDS ||
      storeid < 0 || which < 0)
    return SNMPERR_GENERR;

  return (ds_integers[storeid][which]);
}

int
ds_set_string(int storeid, int which, const char *value) {

  if (storeid >= DS_MAX_IDS || which >= DS_MAX_SUBIDS ||
      storeid < 0 || which < 0)
    return SNMPERR_GENERR;
    
  DEBUGMSGTL(("ds_set_string","Setting %d:%d = %s\n", storeid, which,
              value));

  if (ds_strings[storeid][which] != NULL)
    free(ds_strings[storeid][which]);

  if (value)
    ds_strings[storeid][which] = strdup(value);
  else 
    ds_strings[storeid][which] = NULL;
  
  return SNMPERR_SUCCESS;
}

char *
ds_get_string(int storeid, int which) {
  if (storeid >= DS_MAX_IDS || which >= DS_MAX_SUBIDS ||
      storeid < 0 || which < 0)
    return NULL;

  return (ds_strings[storeid][which]);
}

void
ds_handle_config(const char *token, char *line) {
  struct ds_read_config *drsp;
  char buf[SNMP_MAXBUF];
  int itmp;

  DEBUGMSGTL(("ds_handle_config", "handling %s\n", token));
  for(drsp = ds_configs; drsp != NULL && strcasecmp(token, drsp->token) != 0;
      drsp = drsp->next);
  if (drsp != NULL) {
    DEBUGMSGTL(("ds_handle_config",
                "setting: token=%s, type=%d, id=%d, which=%d\n",
                drsp->token, drsp->type, drsp->storeid, drsp->which));
    switch (drsp->type) {
      case ASN_BOOLEAN:
        if (strncasecmp(line,"yes",3) == 0 || strncasecmp(line,"true",4) == 0) {
          itmp = 1;
        } else if (strncasecmp(line,"no",3) == 0 ||
                strncasecmp(line,"false",5) == 0) {
          itmp = 0;
        } else if (atoi(line) > 0) {
          itmp = 1;
        } else {
          itmp = 0;
        }
        ds_set_boolean(drsp->storeid, drsp->which, itmp);
        DEBUGMSGTL(("ds_handle_config", "bool: %d\n", itmp));
        break;

      case ASN_INTEGER:
        ds_set_int(drsp->storeid, drsp->which, atoi(line));
        DEBUGMSGTL(("ds_handle_config", "int: %d\n", atoi(line)));
        break;

      case ASN_OCTET_STR:
        if (*line == '"') {
            copy_word(line, buf);
            ds_set_string(drsp->storeid, drsp->which, buf);
        } else {
            ds_set_string(drsp->storeid, drsp->which, line);
        }
        DEBUGMSGTL(("ds_handle_config", "string: %s\n", line));
        break;

      default:
        snmp_log(LOG_CRIT,"ds_handle_config *** unknown type %d\n", drsp->type);
        break;
    }
  } else {
    snmp_log(LOG_CRIT, "ds_handle_config *** no registration for %s\n", token);
  }
}


int
ds_register_config(u_char type, const char *ftype, const char *token,
                   int storeid, int which) {
  struct ds_read_config *drsp;

  if (storeid >= DS_MAX_IDS || which >= DS_MAX_SUBIDS ||
      storeid < 0 || which < 0 || token == NULL)
    return SNMPERR_GENERR;

  if (ds_configs == NULL) {
    ds_configs = SNMP_MALLOC_STRUCT(ds_read_config);
    drsp = ds_configs;
  } else {
    for(drsp = ds_configs; drsp->next != NULL; drsp = drsp->next);
    drsp->next = SNMP_MALLOC_STRUCT(ds_read_config);
    drsp = drsp->next;
  }

  drsp->type = type;
  drsp->token = strdup(token);
  drsp->storeid = storeid;
  drsp->which = which;

  switch (type) {
    case ASN_BOOLEAN:
      register_config_handler(ftype, token, ds_handle_config, NULL,"(1|yes|true|0|no|false)");
      break;

    case ASN_INTEGER:
      register_config_handler(ftype, token, ds_handle_config, NULL,"integerValue");
      break;

    case ASN_OCTET_STR:
      register_config_handler(ftype, token, ds_handle_config, NULL,"string");
      break;
    
  }
  return SNMPERR_SUCCESS;
}

int
ds_register_premib(u_char type, const char *ftype, const char *token,
                   int storeid, int which) {
  struct ds_read_config *drsp;

  if (storeid >= DS_MAX_IDS || which >= DS_MAX_SUBIDS ||
      storeid < 0 || which < 0 || token == NULL)
    return SNMPERR_GENERR;

  if (ds_configs == NULL) {
    ds_configs = SNMP_MALLOC_STRUCT(ds_read_config);
    drsp = ds_configs;
  } else {
    for(drsp = ds_configs; drsp->next != NULL; drsp = drsp->next);
    drsp->next = SNMP_MALLOC_STRUCT(ds_read_config);
    drsp = drsp->next;
  }

  drsp->type = type;
  drsp->token = strdup(token);
  drsp->storeid = storeid;
  drsp->which = which;

  switch (type) {
    case ASN_BOOLEAN:
      register_premib_handler(ftype, token, ds_handle_config, NULL,"(1|yes|true|0|no|false)");
      break;

    case ASN_INTEGER:
      register_premib_handler(ftype, token, ds_handle_config, NULL,"integerValue");
      break;

    case ASN_OCTET_STR:
      register_premib_handler(ftype, token, ds_handle_config, NULL,"string");
      break;
    
  }
  return SNMPERR_SUCCESS;
}

