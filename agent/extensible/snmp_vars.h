u_char *var_wes_shell();
u_char *var_wes_hp();

/* the variable that stores the process watching mib info */
struct variable2 wes_proc_variables[] = {
  {PROCINDEX, INTEGER, RONLY, var_wes_proc, 1, {1 }},
  {PROCNAMES, STRING, RONLY, var_wes_proc, 1, {2 }}, 
    {PROCMIN, INTEGER, RONLY, var_wes_proc, 1, {3 }}, 
    {PROCMAX, INTEGER, RONLY, var_wes_proc, 1, {4 }},
    {PROCCOUNT, INTEGER, RONLY, var_wes_proc, 1, {5 }},
    {PROCERROR, INTEGER, RONLY, var_wes_proc, 1, {6 }},
    {PROCERRORMSG, STRING, RONLY, var_wes_proc, 1, {7 }}
};

/* the extensible commands variables */
struct variable2 wes_extensible_variables[] = {
  {SHELLINDEX, INTEGER, RONLY, var_wes_shell, 1, {1 }},
  {SHELLNAMES, STRING, RONLY, var_wes_shell, 1, {2 }}, 
    {SHELLCOMMAND, STRING, RONLY, var_wes_shell, 1, {3 }}, 
    {SHELLRESULT, INTEGER, RONLY, var_wes_shell, 1, {6 }},
    {SHELLOUTPUT, STRING, RONLY, var_wes_shell, 1, {7 }}
};

struct variable2 wes_mem_variables[] = {
  {MEMTOTALSWAP, INTEGER, RONLY, var_wes_mem, 1, {1 }},
  {MEMUSEDSWAP, INTEGER, RONLY, var_wes_mem, 1, {2 }},
  {MEMTOTALREAL, INTEGER, RONLY, var_wes_mem, 1, {3 }},
  {MEMUSEDREAL, INTEGER, RONLY, var_wes_mem, 1, {4 }},
  {MEMTOTALSWAPTXT, INTEGER, RONLY, var_wes_mem, 1, {5 }},
  {MEMUSEDSWAPTXT, INTEGER, RONLY, var_wes_mem, 1, {6 }},
  {MEMTOTALREALTXT, INTEGER, RONLY, var_wes_mem, 1, {7 }},
  {MEMUSEDREALTXT, INTEGER, RONLY, var_wes_mem, 1, {8 }},
  {MEMTOTALFREE, INTEGER, RONLY, var_wes_mem, 1, {9 }}
};

struct variable2 wes_hp_variables[] = {
  {HPCONF, INTEGER, RWRITE, var_wes_hp, 1, {1 }},
  {HPRECONFIG, INTEGER, RWRITE, var_wes_hp, 1, {2 }},
  {HPFLAG, INTEGER, RWRITE, var_wes_hp, 1, {3 }},
  {HPLOGMASK, INTEGER, RWRITE, var_wes_hp, 1, {4 }},
  {HPSTATUS, INTEGER, RWRITE, var_wes_hp, 1, {6 }}
};

struct variable2 wes_hptrap_variables[] = {
  {HPTRAP, IPADDRESS, RWRITE, var_wes_hp, 1, {1 }},
};
