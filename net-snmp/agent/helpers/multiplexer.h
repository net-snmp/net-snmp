/* The multiplexer helper */

/** @name multiplexer @{ */

/** @struct mib_handler_methods
 *  Defines the subhandlers to be called by the multiplexer helper
 */
typedef struct mib_handler_methods_s {
   /** called when a GET request is received */
   mib_handler *get_handler;
   /** called when a GETNEXT request is received */
   mib_handler *getnext_handler;
   /** called when a GETBULK request is received */
   mib_handler *getbulk_handler;
   /** called when a SET request is received */
   mib_handler *set_handler;
} mib_handler_methods;

/** @} */

mib_handler *get_multiplexer_handler(mib_handler_methods *);

NodeHandler multiplexer_helper_handler;

