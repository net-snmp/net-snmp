u_char *var_wes_shell();
u_char *var_wes_disk();
u_char *var_wes_hp();
u_char *var_wes_lockd_test();

/* the variable that stores the process watching mib info */
struct variable2 wes_proc_variables[] = {
  {PROCINDEX, INTEGER, RONLY, var_wes_proc, 1, {PROCINDEX}},
  {PROCNAMES, STRING, RONLY, var_wes_proc, 1, {PROCNAMES}}, 
    {PROCMIN, INTEGER, RONLY, var_wes_proc, 1, {PROCMIN}}, 
    {PROCMAX, INTEGER, RONLY, var_wes_proc, 1, {PROCMAX}},
    {PROCCOUNT, INTEGER, RONLY, var_wes_proc, 1, {PROCCOUNT}},
    {ERRORFLAG, INTEGER, RONLY, var_wes_proc, 1, {ERRORFLAG}},
    {ERRORMSG, STRING, RONLY, var_wes_proc, 1, {ERRORMSG}}
};

/* the extensible commands variables */
struct variable2 wes_extensible_variables[] = {
  {SHELLINDEX, INTEGER, RONLY, var_wes_shell, 1, {SHELLINDEX}},
  {SHELLNAMES, STRING, RONLY, var_wes_shell, 1, {SHELLNAMES}}, 
    {SHELLCOMMAND, STRING, RONLY, var_wes_shell, 1, {SHELLCOMMAND}}, 
    {ERRORFLAG, INTEGER, RONLY, var_wes_shell, 1, {ERRORFLAG}},
    {ERRORMSG, STRING, RONLY, var_wes_shell, 1, {ERRORMSG}}
};

/* the lockd test variables */
struct variable2 wes_lockd_variables[] = {
  {LOCKDINDEX, INTEGER, RONLY, var_wes_lockd_test, 1, {LOCKDINDEX}},
    {ERRORFLAG, INTEGER, RONLY, var_wes_lockd_test, 1, {ERRORFLAG}},
    {ERRORMSG, STRING, RONLY, var_wes_lockd_test, 1, {ERRORMSG}}
};

struct variable2 wes_mem_variables[] = {
  {MEMTOTALSWAP, INTEGER, RONLY, var_wes_mem, 1, {MEMTOTALSWAP}},
  {MEMUSEDSWAP, INTEGER, RONLY, var_wes_mem, 1, {MEMUSEDSWAP}},
  {MEMTOTALREAL, INTEGER, RONLY, var_wes_mem, 1, {MEMTOTALREAL}},
  {MEMUSEDREAL, INTEGER, RONLY, var_wes_mem, 1, {MEMUSEDREAL}},
  {MEMTOTALSWAPTXT, INTEGER, RONLY, var_wes_mem, 1, {MEMTOTALSWAPTXT}},
  {MEMUSEDSWAPTXT, INTEGER, RONLY, var_wes_mem, 1, {MEMUSEDSWAPTXT}},
  {MEMTOTALREALTXT, INTEGER, RONLY, var_wes_mem, 1, {MEMTOTALREALTXT}},
  {MEMUSEDREALTXT, INTEGER, RONLY, var_wes_mem, 1, {MEMUSEDREALTXT}},
  {MEMTOTALFREE, INTEGER, RONLY, var_wes_mem, 1, {MEMTOTALFREE}},
  {ERRORFLAG, INTEGER, RONLY, var_wes_mem, 1, {ERRORFLAG }},
  {ERRORMSG, STRING, RONLY, var_wes_mem, 1, {ERRORMSG }}
};

struct variable2 wes_disk_variables[] = {
  {DISKINDEX, INTEGER, RONLY, var_wes_disk, 1, {DISKINDEX}},
  {DISKPATH, STRING, RONLY, var_wes_disk, 1, {DISKPATH}},
  {DISKDEVICE, STRING, RONLY, var_wes_disk, 1, {DISKDEVICE}},
  {DISKMINIMUM, INTEGER, RONLY, var_wes_disk, 1, {DISKMINIMUM}},
  {DISKTOTAL, INTEGER, RONLY, var_wes_disk, 1, {DISKTOTAL}},
  {DISKAVAIL, INTEGER, RONLY, var_wes_disk, 1, {DISKAVAIL}},
  {DISKUSED, INTEGER, RONLY, var_wes_disk, 1, {DISKUSED}},
  {DISKPERCENT, INTEGER, RONLY, var_wes_disk, 1, {DISKPERCENT}},
  {ERRORFLAG, INTEGER, RONLY, var_wes_disk, 1, {ERRORFLAG }},
  {ERRORMSG, STRING, RONLY, var_wes_disk, 1, {ERRORMSG }}
};

struct variable2 wes_hp_variables[] = {
  {HPCONF, INTEGER, RWRITE, var_wes_hp, 1, {HPCONF}},
  {HPRECONFIG, INTEGER, RWRITE, var_wes_hp, 1, {HPRECONFIG}},
  {HPFLAG, INTEGER, RWRITE, var_wes_hp, 1, {HPFLAG}},
  {HPLOGMASK, INTEGER, RWRITE, var_wes_hp, 1, {ERRORFLAG}},
  {HPSTATUS, INTEGER, RWRITE, var_wes_hp, 1, {ERRORMSG}}
};

struct variable2 wes_hptrap_variables[] = {
  {HPTRAP, IPADDRESS, RWRITE, var_wes_hp, 1, {HPTRAP }},
};
