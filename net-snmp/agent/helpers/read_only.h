/* read_only.h */

/* The helper merely intercepts SET requests and handles them early on
   making everything read-only (no SETs are actually permitted).
   Useful as a helper to handlers that are implementing MIBs with no
   SET support.
 */


mib_handler *get_read_only_handler(void);
void init_read_only_helper(void);
   
NodeHandler read_only_helper;

