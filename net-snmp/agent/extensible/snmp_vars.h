/* the variable that stores the process watching mib info */
struct variable2 wes_proc_variables[] = {
  {WESINDEX, INTEGER, RONLY, var_wes_proc, 1, {1 }},
  {WESNAMES, STRING, RONLY, var_wes_proc, 1, {2 }}, 
    {WESMIN, INTEGER, RONLY, var_wes_proc, 1, {3 }}, 
    {WESMAX, INTEGER, RONLY, var_wes_proc, 1, {4 }},
    {WESCOUNT, INTEGER, RONLY, var_wes_proc, 1, {5 }},
    {WESERROR, INTEGER, RONLY, var_wes_proc, 1, {6 }},
    {WESERRORMSG, STRING, RONLY, var_wes_proc, 1, {7 }}
};

