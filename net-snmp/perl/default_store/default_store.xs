#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <net-snmp/library/default_store.h>

static int
not_here(char *s)
{
    croak("%s not implemented on this architecture", s);
    return -1;
}

static double
constant_DS_LIB_N(char *name, int len, int arg)
{
    switch (name[8 + 0]) {
    case 'O':
	if (strEQ(name + 8, "O_TOKEN_WARNINGS")) {	/* DS_LIB_N removed */
#ifdef DS_LIB_NO_TOKEN_WARNINGS
	    return DS_LIB_NO_TOKEN_WARNINGS;
#else
	    goto not_there;
#endif
	}
    case 'U':
	if (strEQ(name + 8, "UMERIC_TIMETICKS")) {	/* DS_LIB_N removed */
#ifdef DS_LIB_NUMERIC_TIMETICKS
	    return DS_LIB_NUMERIC_TIMETICKS;
#else
	    goto not_there;
#endif
	}
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

static double
constant_DS_LIB_PRINT_N(char *name, int len, int arg)
{
    if (14 + 7 >= len ) {
	errno = EINVAL;
	return 0;
    }
    switch (name[14 + 7]) {
    case 'E':
	if (strEQ(name + 14, "UMERIC_ENUM")) {	/* DS_LIB_PRINT_N removed */
#ifdef DS_LIB_PRINT_NUMERIC_ENUM
	    return DS_LIB_PRINT_NUMERIC_ENUM;
#else
	    goto not_there;
#endif
	}
    case 'O':
	if (strEQ(name + 14, "UMERIC_OIDS")) {	/* DS_LIB_PRINT_N removed */
#ifdef DS_LIB_PRINT_NUMERIC_OIDS
	    return DS_LIB_PRINT_NUMERIC_OIDS;
#else
	    goto not_there;
#endif
	}
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

static double
constant_DS_LIB_PRIN(char *name, int len, int arg)
{
    if (11 + 2 >= len ) {
	errno = EINVAL;
	return 0;
    }
    switch (name[11 + 2]) {
    case 'B':
	if (strEQ(name + 11, "T_BARE_VALUE")) {	/* DS_LIB_PRIN removed */
#ifdef DS_LIB_PRINT_BARE_VALUE
	    return DS_LIB_PRINT_BARE_VALUE;
#else
	    goto not_there;
#endif
	}
    case 'F':
	if (strEQ(name + 11, "T_FULL_OID")) {	/* DS_LIB_PRIN removed */
#ifdef DS_LIB_PRINT_FULL_OID
	    return DS_LIB_PRINT_FULL_OID;
#else
	    goto not_there;
#endif
	}
    case 'H':
	if (strEQ(name + 11, "T_HEX_TEXT")) {	/* DS_LIB_PRIN removed */
#ifdef DS_LIB_PRINT_HEX_TEXT
	    return DS_LIB_PRINT_HEX_TEXT;
#else
	    goto not_there;
#endif
	}
    case 'N':
	if (!strnEQ(name + 11,"T_", 2))
	    break;
	return constant_DS_LIB_PRINT_N(name, len, arg);
    case 'S':
	if (strEQ(name + 11, "T_SUFFIX_ONLY")) {	/* DS_LIB_PRIN removed */
#ifdef DS_LIB_PRINT_SUFFIX_ONLY
	    return DS_LIB_PRINT_SUFFIX_ONLY;
#else
	    goto not_there;
#endif
	}
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

static double
constant_DS_LIB_PR(char *name, int len, int arg)
{
    if (9 + 1 >= len ) {
	errno = EINVAL;
	return 0;
    }
    switch (name[9 + 1]) {
    case 'N':
	if (!strnEQ(name + 9,"I", 1))
	    break;
	return constant_DS_LIB_PRIN(name, len, arg);
    case 'V':
	if (strEQ(name + 9, "IVPASSPHRASE")) {	/* DS_LIB_PR removed */
#ifdef DS_LIB_PRIVPASSPHRASE
	    return DS_LIB_PRIVPASSPHRASE;
#else
	    goto not_there;
#endif
	}
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

static double
constant_DS_LIB_P(char *name, int len, int arg)
{
    switch (name[8 + 0]) {
    case 'A':
	if (strEQ(name + 8, "ASSPHRASE")) {	/* DS_LIB_P removed */
#ifdef DS_LIB_PASSPHRASE
	    return DS_LIB_PASSPHRASE;
#else
	    goto not_there;
#endif
	}
    case 'E':
	if (strEQ(name + 8, "ERSISTENT_DIR")) {	/* DS_LIB_P removed */
#ifdef DS_LIB_PERSISTENT_DIR
	    return DS_LIB_PERSISTENT_DIR;
#else
	    goto not_there;
#endif
	}
    case 'R':
	return constant_DS_LIB_PR(name, len, arg);
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

static double
constant_DS_LIB_A(char *name, int len, int arg)
{
    switch (name[8 + 0]) {
    case 'L':
	if (strEQ(name + 8, "LARM_DONT_USE_SIG")) {	/* DS_LIB_A removed */
#ifdef DS_LIB_ALARM_DONT_USE_SIG
	    return DS_LIB_ALARM_DONT_USE_SIG;
#else
	    goto not_there;
#endif
	}
    case 'P':
	if (strEQ(name + 8, "PPTYPE")) {	/* DS_LIB_A removed */
#ifdef DS_LIB_APPTYPE
	    return DS_LIB_APPTYPE;
#else
	    goto not_there;
#endif
	}
    case 'U':
	if (strEQ(name + 8, "UTHPASSPHRASE")) {	/* DS_LIB_A removed */
#ifdef DS_LIB_AUTHPASSPHRASE
	    return DS_LIB_AUTHPASSPHRASE;
#else
	    goto not_there;
#endif
	}
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

static double
constant_DS_LIB_RE(char *name, int len, int arg)
{
    switch (name[9 + 0]) {
    case 'G':
	if (strEQ(name + 9, "GEX_ACCESS")) {	/* DS_LIB_RE removed */
#ifdef DS_LIB_REGEX_ACCESS
	    return DS_LIB_REGEX_ACCESS;
#else
	    goto not_there;
#endif
	}
    case 'V':
	if (strEQ(name + 9, "VERSE_ENCODE")) {	/* DS_LIB_RE removed */
#ifdef DS_LIB_REVERSE_ENCODE
	    return DS_LIB_REVERSE_ENCODE;
#else
	    goto not_there;
#endif
	}
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

static double
constant_DS_LIB_R(char *name, int len, int arg)
{
    switch (name[8 + 0]) {
    case 'A':
	if (strEQ(name + 8, "ANDOM_ACCESS")) {	/* DS_LIB_R removed */
#ifdef DS_LIB_RANDOM_ACCESS
	    return DS_LIB_RANDOM_ACCESS;
#else
	    goto not_there;
#endif
	}
    case 'E':
	return constant_DS_LIB_RE(name, len, arg);
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

static double
constant_DS_LIB_SE(char *name, int len, int arg)
{
    if (9 + 1 >= len ) {
	errno = EINVAL;
	return 0;
    }
    switch (name[9 + 1]) {
    case 'L':
	if (strEQ(name + 9, "CLEVEL")) {	/* DS_LIB_SE removed */
#ifdef DS_LIB_SECLEVEL
	    return DS_LIB_SECLEVEL;
#else
	    goto not_there;
#endif
	}
    case 'M':
	if (strEQ(name + 9, "CMODEL")) {	/* DS_LIB_SE removed */
#ifdef DS_LIB_SECMODEL
	    return DS_LIB_SECMODEL;
#else
	    goto not_there;
#endif
	}
    case 'N':
	if (strEQ(name + 9, "CNAME")) {	/* DS_LIB_SE removed */
#ifdef DS_LIB_SECNAME
	    return DS_LIB_SECNAME;
#else
	    goto not_there;
#endif
	}
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

static double
constant_DS_LIB_S(char *name, int len, int arg)
{
    switch (name[8 + 0]) {
    case 'A':
	if (strEQ(name + 8, "AVE_MIB_DESCRS")) {	/* DS_LIB_S removed */
#ifdef DS_LIB_SAVE_MIB_DESCRS
	    return DS_LIB_SAVE_MIB_DESCRS;
#else
	    goto not_there;
#endif
	}
    case 'E':
	return constant_DS_LIB_SE(name, len, arg);
    case 'N':
	if (strEQ(name + 8, "NMPVERSION")) {	/* DS_LIB_S removed */
#ifdef DS_LIB_SNMPVERSION
	    return DS_LIB_SNMPVERSION;
#else
	    goto not_there;
#endif
	}
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

static double
constant_DS_LIB_CON(char *name, int len, int arg)
{
    switch (name[10 + 0]) {
    case 'F':
	if (strEQ(name + 10, "FIGURATION_DIR")) {	/* DS_LIB_CON removed */
#ifdef DS_LIB_CONFIGURATION_DIR
	    return DS_LIB_CONFIGURATION_DIR;
#else
	    goto not_there;
#endif
	}
    case 'T':
	if (strEQ(name + 10, "TEXT")) {	/* DS_LIB_CON removed */
#ifdef DS_LIB_CONTEXT
	    return DS_LIB_CONTEXT;
#else
	    goto not_there;
#endif
	}
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

static double
constant_DS_LIB_C(char *name, int len, int arg)
{
    if (8 + 1 >= len ) {
	errno = EINVAL;
	return 0;
    }
    switch (name[8 + 1]) {
    case 'M':
	if (strEQ(name + 8, "OMMUNITY")) {	/* DS_LIB_C removed */
#ifdef DS_LIB_COMMUNITY
	    return DS_LIB_COMMUNITY;
#else
	    goto not_there;
#endif
	}
    case 'N':
	if (!strnEQ(name + 8,"O", 1))
	    break;
	return constant_DS_LIB_CON(name, len, arg);
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

static double
constant_DS_LIB_DO(char *name, int len, int arg)
{
    if (9 + 3 >= len ) {
	errno = EINVAL;
	return 0;
    }
    switch (name[9 + 3]) {
    case 'B':
	if (strEQ(name + 9, "NT_BREAKDOWN_OIDS")) {	/* DS_LIB_DO removed */
#ifdef DS_LIB_DONT_BREAKDOWN_OIDS
	    return DS_LIB_DONT_BREAKDOWN_OIDS;
#else
	    goto not_there;
#endif
	}
    case 'C':
	if (strEQ(name + 9, "NT_CHECK_RANGE")) {	/* DS_LIB_DO removed */
#ifdef DS_LIB_DONT_CHECK_RANGE
	    return DS_LIB_DONT_CHECK_RANGE;
#else
	    goto not_there;
#endif
	}
    case 'R':
	if (strEQ(name + 9, "NT_READ_CONFIGS")) {	/* DS_LIB_DO removed */
#ifdef DS_LIB_DONT_READ_CONFIGS
	    return DS_LIB_DONT_READ_CONFIGS;
#else
	    goto not_there;
#endif
	}
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

static double
constant_DS_LIB_D(char *name, int len, int arg)
{
    switch (name[8 + 0]) {
    case 'E':
	if (strEQ(name + 8, "EFAULT_PORT")) {	/* DS_LIB_D removed */
#ifdef DS_LIB_DEFAULT_PORT
	    return DS_LIB_DEFAULT_PORT;
#else
	    goto not_there;
#endif
	}
    case 'O':
	return constant_DS_LIB_DO(name, len, arg);
    case 'U':
	if (strEQ(name + 8, "UMP_PACKET")) {	/* DS_LIB_D removed */
#ifdef DS_LIB_DUMP_PACKET
	    return DS_LIB_DUMP_PACKET;
#else
	    goto not_there;
#endif
	}
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

static double
constant_DS_LIB_E(char *name, int len, int arg)
{
    switch (name[8 + 0]) {
    case 'S':
	if (strEQ(name + 8, "SCAPE_QUOTES")) {	/* DS_LIB_E removed */
#ifdef DS_LIB_ESCAPE_QUOTES
	    return DS_LIB_ESCAPE_QUOTES;
#else
	    goto not_there;
#endif
	}
    case 'X':
	if (strEQ(name + 8, "XTENDED_INDEX")) {	/* DS_LIB_E removed */
#ifdef DS_LIB_EXTENDED_INDEX
	    return DS_LIB_EXTENDED_INDEX;
#else
	    goto not_there;
#endif
	}
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

static double
constant_DS_LIB_M(char *name, int len, int arg)
{
    if (8 + 3 >= len ) {
	errno = EINVAL;
	return 0;
    }
    switch (name[8 + 3]) {
    case 'C':
	if (strEQ(name + 8, "IB_COMMENT_TERM")) {	/* DS_LIB_M removed */
#ifdef DS_LIB_MIB_COMMENT_TERM
	    return DS_LIB_MIB_COMMENT_TERM;
#else
	    goto not_there;
#endif
	}
    case 'E':
	if (strEQ(name + 8, "IB_ERRORS")) {	/* DS_LIB_M removed */
#ifdef DS_LIB_MIB_ERRORS
	    return DS_LIB_MIB_ERRORS;
#else
	    goto not_there;
#endif
	}
    case 'P':
	if (strEQ(name + 8, "IB_PARSE_LABEL")) {	/* DS_LIB_M removed */
#ifdef DS_LIB_MIB_PARSE_LABEL
	    return DS_LIB_MIB_PARSE_LABEL;
#else
	    goto not_there;
#endif
	}
    case 'R':
	if (strEQ(name + 8, "IB_REPLACE")) {	/* DS_LIB_M removed */
#ifdef DS_LIB_MIB_REPLACE
	    return DS_LIB_MIB_REPLACE;
#else
	    goto not_there;
#endif
	}
    case 'W':
	if (strEQ(name + 8, "IB_WARNINGS")) {	/* DS_LIB_M removed */
#ifdef DS_LIB_MIB_WARNINGS
	    return DS_LIB_MIB_WARNINGS;
#else
	    goto not_there;
#endif
	}
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

static double
constant_DS_LIB_(char *name, int len, int arg)
{
    switch (name[7 + 0]) {
    case 'A':
	return constant_DS_LIB_A(name, len, arg);
    case 'C':
	return constant_DS_LIB_C(name, len, arg);
    case 'D':
	return constant_DS_LIB_D(name, len, arg);
    case 'E':
	return constant_DS_LIB_E(name, len, arg);
    case 'L':
	if (strEQ(name + 7, "LOG_TIMESTAMP")) {	/* DS_LIB_ removed */
#ifdef DS_LIB_LOG_TIMESTAMP
	    return DS_LIB_LOG_TIMESTAMP;
#else
	    goto not_there;
#endif
	}
    case 'M':
	return constant_DS_LIB_M(name, len, arg);
    case 'N':
	return constant_DS_LIB_N(name, len, arg);
    case 'O':
	if (strEQ(name + 7, "OPTIONALCONFIG")) {	/* DS_LIB_ removed */
#ifdef DS_LIB_OPTIONALCONFIG
	    return DS_LIB_OPTIONALCONFIG;
#else
	    goto not_there;
#endif
	}
    case 'P':
	return constant_DS_LIB_P(name, len, arg);
    case 'Q':
	if (strEQ(name + 7, "QUICK_PRINT")) {	/* DS_LIB_ removed */
#ifdef DS_LIB_QUICK_PRINT
	    return DS_LIB_QUICK_PRINT;
#else
	    goto not_there;
#endif
	}
    case 'R':
	return constant_DS_LIB_R(name, len, arg);
    case 'S':
	return constant_DS_LIB_S(name, len, arg);
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

static double
constant_DS_L(char *name, int len, int arg)
{
    if (4 + 2 >= len ) {
	errno = EINVAL;
	return 0;
    }
    switch (name[4 + 2]) {
    case 'R':
	if (strEQ(name + 4, "IBRARY_ID")) {	/* DS_L removed */
#ifdef DS_LIBRARY_ID
	    return DS_LIBRARY_ID;
#else
	    goto not_there;
#endif
	}
    case '_':
	if (!strnEQ(name + 4,"IB", 2))
	    break;
	return constant_DS_LIB_(name, len, arg);
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

static double
constant_DS_M(char *name, int len, int arg)
{
    if (4 + 3 >= len ) {
	errno = EINVAL;
	return 0;
    }
    switch (name[4 + 3]) {
    case 'I':
	if (strEQ(name + 4, "AX_IDS")) {	/* DS_M removed */
#ifdef DS_MAX_IDS
	    return DS_MAX_IDS;
#else
	    goto not_there;
#endif
	}
    case 'S':
	if (strEQ(name + 4, "AX_SUBIDS")) {	/* DS_M removed */
#ifdef DS_MAX_SUBIDS
	    return DS_MAX_SUBIDS;
#else
	    goto not_there;
#endif
	}
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

static double
constant_DS(char *name, int len, int arg)
{
    if (2 + 1 >= len ) {
	errno = EINVAL;
	return 0;
    }
    switch (name[2 + 1]) {
    case 'A':
	if (strEQ(name + 2, "_APPLICATION_ID")) {	/* DS removed */
#ifdef DS_APPLICATION_ID
	    return DS_APPLICATION_ID;
#else
	    goto not_there;
#endif
	}
    case 'L':
	if (!strnEQ(name + 2,"_", 1))
	    break;
	return constant_DS_L(name, len, arg);
    case 'M':
	if (!strnEQ(name + 2,"_", 1))
	    break;
	return constant_DS_M(name, len, arg);
    case 'T':
	if (strEQ(name + 2, "_TOKEN_ID")) {	/* DS removed */
#ifdef DS_TOKEN_ID
	    return DS_TOKEN_ID;
#else
	    goto not_there;
#endif
	}
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

static double
constant(char *name, int len, int arg)
{
    errno = 0;
    if (0 + 1 >= len ) {
	errno = EINVAL;
	return 0;
    }
    switch (name[0 + 1]) {
    case 'E':
	if (strEQ(name + 0, "DEFAULT_STORE_H")) {	/*  removed */
#ifdef DEFAULT_STORE_H
	    return DEFAULT_STORE_H;
#else
	    goto not_there;
#endif
	}
    case 'S':
	if (!strnEQ(name + 0,"D", 1))
	    break;
	return constant_DS(name, len, arg);
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}


MODULE = NetSNMP::default_store		PACKAGE = NetSNMP::default_store		


double
constant(sv,arg)
    PREINIT:
	STRLEN		len;
    INPUT:
	SV *		sv
	char *		s = SvPV(sv, len);
	int		arg
    CODE:
	RETVAL = constant(s,len,arg);
    OUTPUT:
	RETVAL


int
ds_get_boolean(storeid, which)
	int	storeid
	int	which

int
ds_get_int(storeid, which)
	int	storeid
	int	which

char *
ds_get_string(storeid, which)
	int	storeid
	int	which

void *
ds_get_void(storeid, which)
	int	storeid
	int	which

int
ds_register_config(type, ftype, token, storeid, which)
	unsigned char	type
	const char *	ftype
	const char *	token
	int	storeid
	int	which

int
ds_register_premib(type, ftype, token, storeid, which)
	unsigned char	type
	const char *	ftype
	const char *	token
	int	storeid
	int	which

int
ds_set_boolean(storeid, which, value)
	int	storeid
	int	which
	int	value

int
ds_set_int(storeid, which, value)
	int	storeid
	int	which
	int	value

int
ds_set_string(storeid, which, value)
	int	storeid
	int	which
	const char *	value

int
ds_set_void(storeid, which, value)
	int	storeid
	int	which
	void *	value

void
ds_shutdown()

int
ds_toggle_boolean(storeid, which)
	int	storeid
	int	which
