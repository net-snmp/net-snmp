#ifndef _MIBGROUP_MTA_H
#define _MIBGROUP_MTA_H

config_add_mib(MTA-MIB)
config_parse_dot_conf("sendmail", mta_sendmail_parse_config, NULL, "\"config\"|\"stats\"|\"queue\" path | \"index\"|\"statcachetime\"|\"dircachetime\" integer")

void init_mta_sendmail(void);
void mta_sendmail_parse_config(const char *token, char *line);

static FindVarMethod var_mtaEntry;
static FindVarMethod var_mtaGroupEntry;

#endif /* _MIBGROUP_MTA_H */
