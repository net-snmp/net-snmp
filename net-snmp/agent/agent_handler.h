#ifndef AGENT_HANDLER_H
#define AGENT_HANDLER_H

#ifdef __cplusplus
extern "C" {
#endif

/** @addgroup handler */

struct handler_registration_s;

typedef struct mib_handler_s {
   char   *handler_name;
   void   *myvoid;       /* for handler's internal use */

   int (*access_method)(struct mib_handler_s *,
                        struct handler_registration_s *,
                        struct agent_request_info_s   *,
                        struct request_info_s         *);

   struct mib_handler_s *next;
   struct mib_handler_s *prev;
} mib_handler;

#define HANDLER_CAN_GETANDGETNEXT     0x1 /* must be able to do both */
#define HANDLER_CAN_SET               0x2
#define HANDLER_CAN_GETBULK           0x4

#define HANDLER_CAN_RONLY   (HANDLER_CAN_GETANDGETNEXT)
#define HANDLER_CAN_RWRITE  (HANDLER_CAN_GETANDGETNEXT | HANDLER_CAN_SET)
#define HANDLER_CAN_DEFAULT HANDLER_CAN_RONLY

/* root registration info */
typedef struct handler_registration_s {

   char   *handlerName;  /* for mrTable listings, and other uses */
   char   *contextName;  /* NULL = default context */

   /* where are we registered at? */
   oid    *rootoid;
   size_t  rootoid_len;

   /* handler details */
   mib_handler *handler;
   int modes;
   
   /* more optional stuff */
   int     priority;
   int     range_subid;
   oid     range_ubound;
   int     timeout;

} handler_registration;

/* function handler definitions */
typedef int (NodeHandler)(
    mib_handler               *handler,
    handler_registration      *reginfo, /* pointer to registration struct */
    agent_request_info        *reqinfo, /* pointer to current transaction */
    request_info              *requests
    );

typedef struct delegated_cache_s {
   int                        transaction_id;
   mib_handler               *handler;
   handler_registration      *reginfo;
   agent_request_info        *reqinfo;
   request_info              *requests;
   void                      *localinfo;
} delegated_cache;

/* handler API functions */
int register_handler(handler_registration *reginfo);
int inject_handler(handler_registration *reginfo, mib_handler *handler);
mib_handler *find_handler_by_name(handler_registration *reginfo, char *name);
void *find_handler_data_by_name(handler_registration *reginfo, char *name);
int call_handlers(handler_registration *reginfo,
                  agent_request_info   *reqinfo,
                  request_info         *requests);
int call_handler(mib_handler          *next_handler,
                 handler_registration *reginfo,
                 agent_request_info   *reqinfo,
                 request_info         *requests);
int call_next_handler(mib_handler          *current,
                      handler_registration *reginfo,
                      agent_request_info   *reqinfo,
                      request_info         *requests);
mib_handler *create_handler(const char *name,
                            NodeHandler *handler_access_method);
handler_registration *
create_handler_registration(const char *name,
                            NodeHandler *handler_access_method,
                            oid *reg_oid, size_t reg_oid_len, int modes);
delegated_cache *
create_delegated_cache(mib_handler               *,
                       handler_registration      *,
                       agent_request_info        *,
                       request_info              *,
                       void                      *);
inline delegated_cache *handler_check_cache(delegated_cache *dcache);
void register_handler_by_name(const char *, mib_handler *);

inline void
request_add_list_data(request_info *request, data_list *node);

inline void *
request_get_list_data(request_info *request, const char *name);

inline void
free_request_data_set(request_info *request);

inline void
free_request_data_sets(request_info *request);

#define REQUEST_IS_DELEGATED     1
#define REQUEST_IS_NOT_DELEGATED 0
void handler_mark_requests_as_delegated(request_info *, int);
void *handler_get_parent_data(request_info *, const char *);

#ifdef __cplusplus
};
#endif

#endif /* AGENT_HANDLER_H */
