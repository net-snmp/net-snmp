#ifdef hpux
  {{1,3,6,1,4,1,11,2,13,1,2,1},12,(struct variable *)extensible_hptrap_variables,
   sizeof(extensible_hptrap_variables)/sizeof(*extensible_hptrap_variables),
   sizeof(*extensible_hptrap_variables)},
  {{1,3,6,1,4,1,11,2,13,2},10,(struct variable *)extensible_hp_variables,
   sizeof(extensible_hp_variables)/sizeof(*extensible_hp_variables),
   sizeof(*extensible_hp_variables)},
#endif
#ifdef USEPROCMIB
  {{EXTENSIBLEMIB, PROCMIBNUM}, EXTENSIBLENUM+1,
   (struct variable *)extensible_proc_variables,
   sizeof(extensible_proc_variables)/sizeof(*extensible_proc_variables),
   sizeof(*extensible_proc_variables)},
#endif
#ifdef USESHELLMIB
  {{EXTENSIBLEMIB, SHELLMIBNUM}, EXTENSIBLENUM+1,
   (struct variable *)extensible_extensible_variables,
   sizeof(extensible_extensible_variables)/sizeof(*extensible_extensible_variables),
   sizeof(*extensible_extensible_variables)},
#endif
#ifdef USEMEMMIB
  {{EXTENSIBLEMIB, MEMMIBNUM}, EXTENSIBLENUM+1, (struct variable *)extensible_mem_variables,
   sizeof(extensible_mem_variables)/sizeof(*extensible_mem_variables),
   sizeof(*extensible_mem_variables)},
#endif
#ifdef USELOCKDMIB
  {{EXTENSIBLEMIB, LOCKDMIBNUM}, EXTENSIBLENUM+1, (struct variable *)extensible_lockd_variables,
   sizeof(extensible_lockd_variables)/sizeof(*extensible_lockd_variables),
   sizeof(*extensible_lockd_variables)},
#endif
#ifdef USEDISKMIB
  {{EXTENSIBLEMIB, DISKMIBNUM}, EXTENSIBLENUM+1, (struct variable *)extensible_disk_variables,
   sizeof(extensible_disk_variables)/sizeof(*extensible_disk_variables),
   sizeof(*extensible_disk_variables)},
#endif
#ifdef USELOADAVEMIB
  {{EXTENSIBLEMIB, LOADAVEMIBNUM}, EXTENSIBLENUM+1, (struct variable *)extensible_loadave_variables,
   sizeof(extensible_loadave_variables)/sizeof(*extensible_loadave_variables),
   sizeof(*extensible_loadave_variables)},
#endif
#ifdef USEVERSIONMIB
  {{EXTENSIBLEMIB, VERSIONMIBNUM}, EXTENSIBLENUM+1, (struct variable *)extensible_version_variables,
   sizeof(extensible_version_variables)/sizeof(*extensible_version_variables),
   sizeof(*extensible_version_variables)},
#endif
#ifdef USEERRORMIB
  {{EXTENSIBLEMIB, ERRORMIBNUM}, EXTENSIBLENUM+1, (struct variable *)extensible_error_variables,
   sizeof(extensible_error_variables)/sizeof(*extensible_error_variables),
   sizeof(*extensible_error_variables)},
#endif
