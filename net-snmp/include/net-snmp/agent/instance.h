/* testhandler.h */

/* The instance helper is designed to simplify the task of adding simple
 * instances to the mib tree.
 */

/* GETNEXTs are auto-converted to a GET.
 * non-valid GETs are dropped.
 * The client can assume that if you're called for a GET, it shouldn't
 * have to check the oid at all.  Just answer.
 */

int register_instance(handler_registration *reginfo);
int register_read_only_instance(handler_registration *reginfo);

#define INSTANCE_HANDLER_NAME "instance"

mib_handler *get_instance_handler(void);
   
int register_read_only_ulong_instance(const char *name,
                                      oid *reg_oid, size_t reg_oid_len,
                                      u_long *it);
int register_ulong_instance(const char *name, oid *reg_oid, size_t reg_oid_len,
                            u_long *it);
int register_read_only_counter32_instance(const char *name,
                                          oid *reg_oid, size_t reg_oid_len,
                                          u_long *it);
int register_read_only_long_instance(const char *name,
                                     oid *reg_oid, size_t reg_oid_len,
                                     long *it);
int register_long_instance(const char *name, oid *reg_oid, size_t reg_oid_len,
                           long *it);


NodeHandler instance_helper_handler;
NodeHandler instance_ulong_handler;
NodeHandler instance_long_handler;
NodeHandler instance_counter32_handler;
