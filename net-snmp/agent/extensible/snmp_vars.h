u_char *var_wes_shell();

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
    {SHELLRESULT, INTEGER, RONLY, var_wes_shell, 1, {4 }},
    {SHELLOUTPUT, STRING, RONLY, var_wes_shell, 1, {5 }}
};

struct variable2 wes_mem_variables[] = {
  {MEMTOTALSWAP, INTEGER, RONLY, var_wes_mem, 1, {1 }},
  {MEMUSEDSWAP, INTEGER, RONLY, var_wes_mem, 1, {2 }}
};

