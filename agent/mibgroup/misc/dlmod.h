/*
 *  pass: pass through extensiblity
 */
#ifndef _MIBGROUP_DLMOD_H
#define _MIBGROUP_DLMOD_H


/* config file parsing routines */
void dlmod_free_config __P((void));
void dlmod_parse_config __P((char *, char *));
config_parse_dot_conf("dlmod", dlmod_parse_config, dlmod_free_config)

#include "mibdefs.h"

#endif /* _MIBGROUP_DLMOD_H */
