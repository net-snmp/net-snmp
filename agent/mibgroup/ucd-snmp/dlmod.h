/*
 *  Dynamic Loadable Agent Modules MIB (UCD-DLMOD-MIB) - dlmod.h
 *
 */

#ifndef MIBGROUP_DLMOD_H
#define MIBGROUP_DLMOD_H

config_add_mib(UCD-DLMOD-MIB)

void init_dlmod(void);
void shutdown_dlmod(void);

#endif                          /* MIBGROUP_DLMOD_H */
