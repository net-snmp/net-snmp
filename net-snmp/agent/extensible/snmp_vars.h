
#ifdef USEPROCMIB
/* the variable that stores the process watching mib info */

struct variable2 extensible_proc_variables[] = {
  {MIBINDEX, INTEGER, RONLY, var_extensible_proc, 1, {MIBINDEX}},
  {ERRORNAME, STRING, RONLY, var_extensible_proc, 1, {ERRORNAME}}, 
    {PROCMIN, INTEGER, RONLY, var_extensible_proc, 1, {PROCMIN}}, 
    {PROCMAX, INTEGER, RONLY, var_extensible_proc, 1, {PROCMAX}},
    {PROCCOUNT, INTEGER, RONLY, var_extensible_proc, 1, {PROCCOUNT}},
    {ERRORFLAG, INTEGER, RONLY, var_extensible_proc, 1, {ERRORFLAG}},
    {ERRORMSG, STRING, RONLY, var_extensible_proc, 1, {ERRORMSG}},
  {ERRORFIX, INTEGER, RWRITE, var_extensible_proc, 1, {ERRORFIX }}
};
#endif

#ifdef USESHELLMIB
/* the extensible commands variables */

struct variable2 extensible_extensible_variables[] = {
  {MIBINDEX, INTEGER, RONLY, var_extensible_shell, 1, {MIBINDEX}},
  {ERRORNAME, STRING, RONLY, var_extensible_shell, 1, {ERRORNAME}}, 
    {SHELLCOMMAND, STRING, RONLY, var_extensible_shell, 1, {SHELLCOMMAND}}, 
    {ERRORFLAG, INTEGER, RONLY, var_extensible_shell, 1, {ERRORFLAG}},
    {ERRORMSG, STRING, RONLY, var_extensible_shell, 1, {ERRORMSG}},
  {ERRORFIX, INTEGER, RWRITE, var_extensible_shell, 1, {ERRORFIX }}
};
#endif

#ifdef USELOCKDMIB
/* the lockd test variables */

struct variable2 extensible_lockd_variables[] = {
  {MIBINDEX, INTEGER, RONLY, var_extensible_lockd_test, 1, {MIBINDEX}},
    {ERRORFLAG, INTEGER, RONLY, var_extensible_lockd_test, 1, {ERRORFLAG}},
    {ERRORMSG, STRING, RONLY, var_extensible_lockd_test, 1, {ERRORMSG}}
};
#endif

#ifdef USEMEMMIB

struct variable2 extensible_mem_variables[] = {
  {MIBINDEX, INTEGER, RONLY, var_extensible_mem,1,{MIBINDEX}},
  {ERRORNAME, STRING, RONLY, var_extensible_mem, 1, {ERRORNAME }},
  {MEMTOTALSWAP, INTEGER, RONLY, var_extensible_mem, 1, {MEMTOTALSWAP}},
  {MEMUSEDSWAP, INTEGER, RONLY, var_extensible_mem, 1, {MEMUSEDSWAP}},
  {MEMTOTALREAL, INTEGER, RONLY, var_extensible_mem, 1, {MEMTOTALREAL}},
  {MEMUSEDREAL, INTEGER, RONLY, var_extensible_mem, 1, {MEMUSEDREAL}},
  {MEMTOTALSWAPTXT, INTEGER, RONLY, var_extensible_mem, 1, {MEMTOTALSWAPTXT}},
  {MEMUSEDSWAPTXT, INTEGER, RONLY, var_extensible_mem, 1, {MEMUSEDSWAPTXT}},
  {MEMTOTALREALTXT, INTEGER, RONLY, var_extensible_mem, 1, {MEMTOTALREALTXT}},
  {MEMUSEDREALTXT, INTEGER, RONLY, var_extensible_mem, 1, {MEMUSEDREALTXT}},
  {MEMTOTALFREE, INTEGER, RONLY, var_extensible_mem, 1, {MEMTOTALFREE}},
  {ERRORFLAG, INTEGER, RONLY, var_extensible_mem, 1, {ERRORFLAG }},
  {ERRORMSG, STRING, RONLY, var_extensible_mem, 1, {ERRORMSG }}
};
#endif

#ifdef USEDISKMIB

struct variable2 extensible_disk_variables[] = {
  {MIBINDEX, INTEGER, RONLY, var_extensible_disk, 1, {MIBINDEX}},
  {ERRORNAME, STRING, RONLY, var_extensible_disk, 1, {ERRORNAME}},
  {DISKDEVICE, STRING, RONLY, var_extensible_disk, 1, {DISKDEVICE}},
  {DISKMINIMUM, INTEGER, RONLY, var_extensible_disk, 1, {DISKMINIMUM}},
  {DISKTOTAL, INTEGER, RONLY, var_extensible_disk, 1, {DISKTOTAL}},
  {DISKAVAIL, INTEGER, RONLY, var_extensible_disk, 1, {DISKAVAIL}},
  {DISKUSED, INTEGER, RONLY, var_extensible_disk, 1, {DISKUSED}},
  {DISKPERCENT, INTEGER, RONLY, var_extensible_disk, 1, {DISKPERCENT}},
  {ERRORFLAG, INTEGER, RONLY, var_extensible_disk, 1, {ERRORFLAG }},
  {ERRORMSG, STRING, RONLY, var_extensible_disk, 1, {ERRORMSG }}
};
#endif

#ifdef USEVERSIONMIB

struct variable2 extensible_version_variables[] = {
  {MIBINDEX, INTEGER, RONLY, var_extensible_version, 1, {MIBINDEX}},
  {VERTAG, STRING, RONLY, var_extensible_version, 1, {VERTAG}},
  {VERDATE, STRING, RONLY, var_extensible_version, 1, {VERDATE}},
  {VERCDATE, STRING, RONLY, var_extensible_version, 1, {VERCDATE}},
  {VERIDENT, STRING, RONLY, var_extensible_version, 1, {VERIDENT}},
  {VERCLEARCACHE, INTEGER, RONLY, var_extensible_version, 1, {VERCLEARCACHE}},
  {VERUPDATECONFIG, INTEGER, RWRITE, var_extensible_version, 1, {VERUPDATECONFIG}},
  {VERRESTARTAGENT, INTEGER, RWRITE, var_extensible_version, 1, {VERRESTARTAGENT}}
};
#endif

#ifdef USELOADAVEMIB

struct variable2 extensible_loadave_variables[] = {
  {MIBINDEX, INTEGER, RONLY, var_extensible_loadave, 1, {MIBINDEX}},
  {ERRORNAME, STRING, RONLY, var_extensible_loadave, 1, {ERRORNAME}},
  {LOADAVE, STRING, RONLY, var_extensible_loadave, 1, {LOADAVE}},
  {LOADMAXVAL, STRING, RONLY, var_extensible_loadave, 1, {LOADMAXVAL}},
    {ERRORFLAG, INTEGER, RONLY, var_extensible_loadave, 1, {ERRORFLAG}},
    {ERRORMSG, STRING, RONLY, var_extensible_loadave, 1, {ERRORMSG}}
};
#endif

#ifdef USEERRORMIB

struct variable2 extensible_error_variables[] = {
  {MIBINDEX, INTEGER, RONLY, var_extensible_errors, 1, {MIBINDEX}},
  {ERRORNAME, STRING, RONLY, var_extensible_errors, 1, {ERRORNAME}},
    {ERRORFLAG, INTEGER, RONLY, var_extensible_errors, 1, {ERRORFLAG}},
    {ERRORMSG, STRING, RONLY, var_extensible_errors, 1, {ERRORMSG}}
};
#endif

/* mimics part of the hpux tree */
#ifdef hpux  

struct variable2 extensible_hp_variables[] = {
  {HPCONF, INTEGER, RWRITE, var_extensible_hp, 1, {HPCONF}},
  {HPRECONFIG, INTEGER, RWRITE, var_extensible_hp, 1, {HPRECONFIG}},
  {HPFLAG, INTEGER, RWRITE, var_extensible_hp, 1, {HPFLAG}},
  {HPLOGMASK, INTEGER, RWRITE, var_extensible_hp, 1, {ERRORFLAG}},
  {HPSTATUS, INTEGER, RWRITE, var_extensible_hp, 1, {ERRORMSG}}
};

struct variable2 extensible_hptrap_variables[] = {
  {HPTRAP, IPADDRESS, RWRITE, var_extensible_hp, 1, {HPTRAP }},
};
#endif
