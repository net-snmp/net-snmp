/*
 *  Template MIB group interface - wombat.h
 *
 */
#ifndef _MIBGROUP_WOMBAT_H
#define _MIBGROUP_WOMBAT_H

extern void	init_wombat();
extern u_char	*var_wombat();


#define	WOMBATUPTIME		1
#define	WOMBATCURRENT		2
#define	WOMBATMAX		3

#ifdef IN_SNMP_VARS_C

struct variableN wombat_variables[] = {
    { WOMBATUPTIME,  TIMETICKS, RONLY, var_wombat, 1, {1}},
    { WOMBATCURRENT,   COUNTER, RONLY, var_wombat, 1, {2}},
    { WOMBATHIGHWATER, COUNTER, RONLY, var_wombat, 1, {3}}
};
#define WOMBAT_SUBTREE  { \
    { MIB, 99}, 7, (struct variable *)wombat_variables, \
	sizeof(wombat_variables)/sizeof(*wombat_variables), \
	sizeof(*wombat_variables) }
#endif

#endif /* _MIBGROUP_WOMBAT_H */
