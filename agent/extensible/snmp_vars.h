u_char *var_wes_shell();
u_char *var_wes_disk();
u_char *var_wes_version();
u_char *var_wes_hp();
u_char *var_wes_lockd_test();

/* the variable that stores the process watching mib info */
struct variable2 wes_proc_variables[] = {
  {MIBINDEX, INTEGER, RONLY, var_wes_proc, 1, {MIBINDEX}},
  {ERRORNAME, STRING, RONLY, var_wes_proc, 1, {ERRORNAME}}, 
    {PROCMIN, INTEGER, RONLY, var_wes_proc, 1, {PROCMIN}}, 
    {PROCMAX, INTEGER, RONLY, var_wes_proc, 1, {PROCMAX}},
    {PROCCOUNT, INTEGER, RONLY, var_wes_proc, 1, {PROCCOUNT}},
    {ERRORFLAG, INTEGER, RONLY, var_wes_proc, 1, {ERRORFLAG}},
    {ERRORMSG, STRING, RONLY, var_wes_proc, 1, {ERRORMSG}}
};

/* the extensible commands variables */
struct variable2 wes_extensible_variables[] = {
  {MIBINDEX, INTEGER, RONLY, var_wes_shell, 1, {MIBINDEX}},
  {ERRORNAME, STRING, RONLY, var_wes_shell, 1, {ERRORNAME}}, 
    {SHELLCOMMAND, STRING, RONLY, var_wes_shell, 1, {SHELLCOMMAND}}, 
    {ERRORFLAG, INTEGER, RONLY, var_wes_shell, 1, {ERRORFLAG}},
    {ERRORMSG, STRING, RONLY, var_wes_shell, 1, {ERRORMSG}}
};

/* the lockd test variables */
struct variable2 wes_lockd_variables[] = {
  {MIBINDEX, INTEGER, RONLY, var_wes_lockd_test, 1, {MIBINDEX}},
    {ERRORFLAG, INTEGER, RONLY, var_wes_lockd_test, 1, {ERRORFLAG}},
    {ERRORMSG, STRING, RONLY, var_wes_lockd_test, 1, {ERRORMSG}}
};

#ifdef hpux
struct variable2 wes_mem_variables[] = {
  {MIBINDEX, INTEGER, RONLY, var_wes_mem,1,{MIBINDEX}},
  {ERRORNAME, STRING, RONLY, var_wes_mem, 1, {ERRORNAME }},
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
#endif

#ifdef hpux
struct variable2 wes_disk_variables[] = {
  {MIBINDEX, INTEGER, RONLY, var_wes_disk, 1, {MIBINDEX}},
  {ERRORNAME, STRING, RONLY, var_wes_disk, 1, {ERRORNAME}},
  {DISKDEVICE, STRING, RONLY, var_wes_disk, 1, {DISKDEVICE}},
  {DISKMINIMUM, INTEGER, RONLY, var_wes_disk, 1, {DISKMINIMUM}},
  {DISKTOTAL, INTEGER, RONLY, var_wes_disk, 1, {DISKTOTAL}},
  {DISKAVAIL, INTEGER, RONLY, var_wes_disk, 1, {DISKAVAIL}},
  {DISKUSED, INTEGER, RONLY, var_wes_disk, 1, {DISKUSED}},
  {DISKPERCENT, INTEGER, RONLY, var_wes_disk, 1, {DISKPERCENT}},
  {ERRORFLAG, INTEGER, RONLY, var_wes_disk, 1, {ERRORFLAG }},
  {ERRORMSG, STRING, RONLY, var_wes_disk, 1, {ERRORMSG }}
};
#endif

struct variable2 wes_version_variables[] = {
  {MIBINDEX, INTEGER, RONLY, var_wes_version, 1, {MIBINDEX}},
  {VERDATE, STRING, RONLY, var_wes_version, 1, {VERDATE}},
  {VERCDATE, STRING, RONLY, var_wes_version, 1, {VERCDATE}},
  {VERIDENT, STRING, RONLY, var_wes_version, 1, {VERIDENT}}
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
