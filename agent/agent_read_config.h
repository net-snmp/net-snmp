/*
 * agent_read_config.h: reads configuration files for extensible sections.
 *
 */
#ifndef _AGENT_READ_CONFIG_H
#define _AGENT_READ_CONFIG_H

void init_agent_read_config (void);
void update_config (void);
struct subtree;
void snmpd_register_config_handler (const char *,
                                    void (*parser)(char *, char *),
                                    void (*releaser) (void),
                                    const char *);
void snmpd_unregister_config_handler (const char *);
void snmpd_store_config (const char *);

#endif /* _AGENT_READ_CONFIG_H */
