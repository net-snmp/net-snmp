/*
 * agent_read_config.h: reads configuration files for extensible sections.
 *
 */
#ifndef _MIBGROUP_READ_CONFIG_H
#define _MIBGROUP_READ_CONFIG_H

void init_agent_read_config __P((void));
RETSIGTYPE update_config __P((int));
int tree_compare __P((const void *, const void *));
void setup_tree __P((void));
void load_subtree __P((struct subtree *));
int is_parent __P((oid *, int, oid *));
void snmpd_register_config_handler __P((char *,
                                        void (*parser)(char *, char *),
                                        void (*releaser) (void)));
void snmpd_unregister_config_handler __P((char *));
void snmpd_store_config __P((char *));

#endif /* _MIBGROUP_READ_CONFIG_H */
