#ifndef OLD_API_H
#define OLD_API_H

#define OLD_API_NAME "old_api"

typedef struct old_api_info_s {
   struct variable *var;
   size_t varsize;
   size_t numvars;

   /* old stuff */
   struct snmp_session *ss;
   int flags;
} old_api_info;

typedef struct old_opi_cache_s {
   u_char *data;
   WriteMethod *write_method;
} old_api_cache;

int register_old_api(const char *moduleName,
                     struct variable *var,
                     size_t varsize,
                     size_t numvars,
                     oid *mibloc,
                     size_t mibloclen,
                     int priority,
                     int range_subid,
                     oid range_ubound,
                     struct snmp_session *ss,
                     const char *context,
                     int timeout,
                     int flags);
NodeHandler old_api_helper;

/* really shouldn't be used */
struct agent_snmp_session  *get_current_agent_session(void);

#endif /* OLD_API_H */
