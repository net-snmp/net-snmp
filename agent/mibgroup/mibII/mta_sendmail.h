#ifndef _MIBGROUP_MTA_H
#define _MIBGROUP_MTA_H

config_add_mib(MTA-MIB)

void init_mta_sendmail(void);

static FindVarMethod var_mtaEntry;
static FindVarMethod var_mtaGroupEntry;

#endif /* _MIBGROUP_MTA_H */
