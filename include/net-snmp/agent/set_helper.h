typedef struct set_info_s {
   int   action;
   void *stateRef;

/* don't use yet: */
   void **oldData;
   int   setCleanupFlags;       /* XXX: client sets this to: */
#define AUTO_FREE_STATEREF 0x01 /* calls free(stateRef) */
#define AUTO_FREE_OLDDATA  0x02 /* calls free(*oldData) */
#define AUTO_UNDO          0x04 /* ... */
} set_info;

