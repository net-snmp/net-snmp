/*
 * transform_oids.h
 *
 * Numeric MIB names for auth and priv transforms.
 */


static oid usmNoAuthProtocol[]       = { 1,3,6,1,6,3,10,1,1,1 };
static oid usmHMACMD5AuthProtocol[]  = { 1,3,6,1,6,3,10,1,1,2 };
static oid usmHMACSHA1AuthProtocol[] = { 1,3,6,1,6,3,10,1,1,3 };

static oid usmNoPrivProtocol[]       = { 1,3,6,1,6,3,10,1,2,1 };
static oid usmDESPrivProtocol[]      = { 1,3,6,1,6,3,10,1,2,2 };


#	define s(p)	shh = usm ## p ## Protocol;
static void shh2(void)		/* FIX -- This is silly... */
{ oid *shh; s(NoAuth) s(HMACMD5Auth) s(HMACSHA1Auth) s(NoPriv) s(DESPriv) }
#	undef s

