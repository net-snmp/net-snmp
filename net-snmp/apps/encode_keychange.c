/*
 * encode_keychange.c
 *
 * Collect information to build a KeyChange encoding, per the textual
 * convention given in RFC 2274, Section 5.  Compute the value and
 * dump to stdout as a string of hex nibbles.
 *
 *
 * Passphrase material may come from many sources.  The following are
 * checked in order (see get_user_passphrases()):
 *	- Prompt always if -f is given.
 *	- Commandline arguments.
 *	- PASSPHRASE_FILE.
 *	- Prompts on stdout.   Use -P to turn off prompt tags.
 *
 *
 * FIX	Better name?
 * FIX	Change encode_keychange() to take random bits?
 * FIX	QUITFUN not quite appropriate here...
 * FIX	This is slow...
 */

static char *rcsid = "$Id$";	/* */

#include "../snmplib/all_system.h"
#include "../snmplib/all_general_local.h"

#include "../snmplib/transform_oids.h"

#include <stdlib.h>

extern char     *optarg;
extern int      optind, optopt, opterr;

#if !defined(__linux__)
extern int	optreset;
#endif



/*
 * Globals, &c...
 */
char *local_progname;

#define NL	"\n"

#define USAGE	"Usage: %s [-fhPvV] -t (md5|sha1) [-O \"<old_passphrase>\"][-N \"<new_passphrase>\"][-E [0x]<engineID>]"

#define OPTIONLIST	"E:fhN:O:Pt:vVD"

#define PASSPHRASE_DIR		".snmp"
	/* Rooted at $HOME.
	 */
#define PASSPHRASE_FILE		PASSPHRASE_DIR ## "/passphrase.ek"
	/* 
	 * Format: two lines containing old and new passphrases, nothing more.
	 * 	
	 * XXX	Add creature comforts like: comments and 
	 *	tokens identifying passphrases, separate directory check,
	 *	check in current directory (?), traverse a path of
	 *	directories (?)...
	 * FIX	Better name?
	 */

#define VERBOSE_FILE	stderr


int	forcepassphrase		= 0,	/* Always prompt for passphrases. */
	promptindicator		= 1,	/* Output an indicator that input
					 *   is requested.		  */
	visible			= 0,	/* Echo passphrases to terminal.  */
	verbose			= 0,	/* Output progress to stderr. 	  */
	engineid_len		= 0;

u_char	*engineid		= NULL,	/* Both input & final binary form.*/
	*newpass		= NULL,
        *oldpass		= NULL;

char	*transform_type_input	= NULL;

oid	*transform_type		= NULL;	/* Type of HMAC hash to use.	  */



/*
 * Prototypes.
 */
void	usage(FILE *ofp);
void	usage_synopsis(FILE *ofp);
int	get_user_passphrases(void);





/*******************************************************************-o-******
 */
int
main(int argc, char **argv)
{
	int		  rval		= SNMPERR_SUCCESS;
	u_int		  oldKu_len	= SNMP_MAXBUF_SMALL,
			  newKu_len	= SNMP_MAXBUF_SMALL,
			  oldkul_len	= SNMP_MAXBUF_SMALL,
			  newkul_len	= SNMP_MAXBUF_SMALL,
			  keychange_len	= SNMP_MAXBUF_SMALL;

        char              ch,
			 *s = NULL;
	u_char		  oldKu[SNMP_MAXBUF_SMALL],
			  newKu[SNMP_MAXBUF_SMALL],
			  oldkul[SNMP_MAXBUF_SMALL],
			  newkul[SNMP_MAXBUF_SMALL],
			  keychange[SNMP_MAXBUF_SMALL];

        int               i;

 	local_progname = argv[0];

EM(-1);	/* */

 
	/*
	 * Parse.
	 */
	while ( (ch = getopt(argc, argv, OPTIONLIST)) != EOF )
	{
		switch(ch) {

                case 'D':       snmp_set_do_debugging(1);       break;
		case 'E':	engineid = optarg;		break;
		case 'f':	forcepassphrase = 1;		break;
		case 'N':	newpass = optarg;		break;
		case 'O':	oldpass = optarg;		break;
		case 'P':	promptindicator = 0;		break;
		case 't':	transform_type_input = optarg;	break;
		case 'v':	verbose = 1;			break;
		case 'V':	visible = 1;			break;
		case 'h':
			rval = 0;
		default:
			usage(stdout);
			exit(rval);
		}

		argc -= 1; argv += 1;
                if (optarg) { argc -= 1; argv += 1; optarg = NULL; }
		optind = 1;
#if !defined(__linux__)
		optreset = 1;
#endif

	}  /* endwhile getopt */

	if ((argc > 1)) {
		usage(stdout);
		exit(1000);

	} else if ( !transform_type_input ) {
		fprintf(stderr, "The -t option is mandatory.\n");
		usage_synopsis(stdout);
		exit(1000);
	}



	/*
	 * Convert and error check transform_type.
	 */
	if ( !strcmp(transform_type_input, "md5") ) {
		transform_type = usmHMACMD5AuthProtocol;

	} else if ( !strcmp(transform_type_input, "sha1") ) {
		transform_type = usmHMACSHA1AuthProtocol;

	} else {
		fprintf(stderr,
			"Unrecognized hash transform: \"%s\".\n",
			transform_type_input);
		usage_synopsis(stderr);
		QUITFUN(rval = SNMPERR_GENERR, main_quit);
	}

	if (verbose) {
		fprintf(VERBOSE_FILE, "Hash:\t\t%s\n",
			(transform_type == usmHMACMD5AuthProtocol)
				? "usmHMACMD5AuthProtocol"
				: "usmHMACSHA1AuthProtocol"
			);
	}



	/* 
	 * Build engineID.  Accept hex engineID as the bits
	 * "in-and-of-themselves", otherwise create an engineID with the
	 * given string as text.
	 *
	 * If no engineID is given, lookup the first IP address for the
	 * localhost and use that (see setup_engineID()).
	 */
	if ( engineid && (tolower(*(engineid+1)) == 'x') ) {
		engineid_len = hex_to_binary2(	engineid+2,
						strlen(engineid)-2,
						(char **) &engineid);
                DEBUGP("engineIDLen: %d\n", engineid_len);
	} else {
		engineid_len = setup_engineID(&engineid, engineid);

	} 

	if (verbose) {
		fprintf(VERBOSE_FILE, "EngineID:\t%s\n",
			/* XXX = */ dump_snmpEngineID(engineid, &engineid_len));
	}



	/*
	 * Get passphrases from user.
	 */
	rval = get_user_passphrases();
	QUITFUN(rval, main_quit);

	if ( strlen(oldpass) < USM_LENGTH_P_MIN ) {
		fprintf(stderr, "Old passphrase must be greater than %d "
				"characters in length.\n",
				USM_LENGTH_P_MIN);
		QUITFUN(rval = SNMPERR_GENERR, main_quit);

	} else if ( strlen(newpass) < USM_LENGTH_P_MIN ) {
		fprintf(stderr, "New passphrase must be greater than %d "
				"characters in length.\n",
				USM_LENGTH_P_MIN);
		QUITFUN(rval = SNMPERR_GENERR, main_quit);
	}

	if (verbose) {
		fprintf(VERBOSE_FILE,
			"Old passphrase:\t%s\nNew passphrase:\t%s\n",
			oldpass, newpass);
	}



	/* 
	 * Compute Ku and Kul's from old and new passphrases, then
	 * compute the keychange string & print it out.
	 */
	rval = sc_init();
	QUITFUN(rval, main_quit);


	rval = generate_Ku(	transform_type, USM_LENGTH_OID_TRANSFORM,
				oldpass, strlen(oldpass),
				oldKu, &oldKu_len);
	QUITFUN(rval, main_quit);


	rval = generate_Ku(	transform_type, USM_LENGTH_OID_TRANSFORM,
				newpass, strlen(newpass),
				newKu, &newKu_len);
	QUITFUN(rval, main_quit);


        DEBUGP("EID (%d): ", engineid_len);
        for(i=0; i < engineid_len; i++)
          DEBUGP("%02x",(int) (engineid[i]));
        DEBUGP("\n");

        DEBUGP("old Ku (%d) (from %s): ", oldKu_len, oldpass);
        for(i=0; i < oldKu_len; i++)
          DEBUGP("%02x",(int) (oldKu[i]));
        DEBUGP("\n");

	rval = generate_kul(	transform_type, USM_LENGTH_OID_TRANSFORM,
				engineid, engineid_len,
				oldKu, oldKu_len,
				oldkul, &oldkul_len);
	QUITFUN(rval, main_quit);


        DEBUGP("generating old Kul (%d) (from Ku): ", oldkul_len);
        for(i=0; i < oldkul_len; i++)
          DEBUGP("%02x",(int) (oldkul[i]));
        DEBUGP("\n");

	rval = generate_kul(	transform_type, USM_LENGTH_OID_TRANSFORM,
				engineid, engineid_len,
				newKu, newKu_len,
				newkul, &newkul_len);
	QUITFUN(rval, main_quit);
        
        DEBUGP("generating new Kul (%d) (from Ku): ", oldkul_len);
        for(i=0; i < newkul_len; i++)
          DEBUGP("%02x",newkul[i]);
        DEBUGP("\n");

	rval = encode_keychange(transform_type, USM_LENGTH_OID_TRANSFORM,
				oldkul, oldkul_len,
				newkul, newkul_len,
				keychange, &keychange_len);
	QUITFUN(rval, main_quit);



	binary_to_hex(keychange, keychange_len, &s);
	printf("%s%s\n",
		(verbose) ? "KeyChange string:\t" : "", /* XXX stdout */
		s);


	/*
	 * Cleanup.
	 */
main_quit:
	sc_shutdown();

	SNMP_ZERO(oldpass,	strlen(oldpass));
	SNMP_ZERO(newpass,	strlen(newpass));

	SNMP_ZERO(oldKu,	oldKu_len);
	SNMP_ZERO(newKu,	newKu_len);

	SNMP_ZERO(oldkul,	oldkul_len);
	SNMP_ZERO(newkul,	newkul_len);

	SNMP_ZERO(s, strlen(s));

	return rval;

} /* end main() */




/*******************************************************************-o-******
 */
void
usage_synopsis(FILE *ofp)
{
	fprintf(ofp, USAGE "

    -E [0x]<engineID>		EngineID used for kul generation.
    -f				Force passphrases to be read from stdin.
    -h				Help.
    -N \"<new_passphrase>\"	Passphrase used to generate new Ku.
    -O \"<old_passphrase>\"	Passphrase used to generate old Ku.
    -P				Turn off prompt indicators.
    -t md5 | sha1		HMAC hash transform type.
    -v				Verbose.
    -V				Visible.  Echo passphrases to terminal.
		"
		NL, local_progname);

}  /* end usage_synopsis() */

void
usage(FILE *ofp)
{
	char	*s;

	usage_synopsis(ofp);

	fprintf(ofp,
		"
    Only -t is mandatory.  The transform is used to convert P=>Ku, convert
    Ku=>Kul, and to hash the old Kul with the random bits.

    Passphrase will be taken from the first successful source as follows:
	a) Commandline options,
	b) The file \"%s/%s\",
	c) stdin  -or-  User input from the terminal.

    -f will require reading from the stdin/terminal, ignoring a) and b).
    -P will prevent prompts for passphrases to stdout from being printed.

    <engineID> is intepreted as a hex string when preceeded by \"0x\",
    otherwise it is created to contain \"text\".  If nothing is given,
    <engineID> is constructed from the first IP address for the local host.
		"
		NL, (s = getenv("HOME"))?s:"$HOME", PASSPHRASE_FILE);


/* FIX -- make this possible?
    -r [0x]<random_bits>	Random bits used in KeyChange XOR.

    <engineID> and <random_bits> are intepreted as hex strings when
    preceeded by \"0x\", otherwise <engineID> is created to contain \"text\"
    and <random_bits> are the same as the ascii input.

    <random_bits> will be generated by SCAPI if not given.  If value is
    too long, it will be truncated; if too short, the remainder will be
    filled in with zeros.
 */

}  /* end usage() */





/*******************************************************************-o-******
 * get_user_passphrases
 *
 * Returns:
 *	SNMPERR_SUCCESS		Success.
 *	SNMPERR_GENERR		Otherwise.
 *
 *
 * Acquire new and old passphrases from the user:
 *
 *	+ Always prompt if 'forcepassphrase' is set.
 *	+ Use given arguments if they are defined.
 *	+ Otherwise read file format from PASSWORD_FILE.
 *		Sanity check existence and permissions of the path.
 *		ASSUME for now that PASSWORD_FILE is rooted only at $HOME.
 *	+ Otherwise prompt user for passphrase(s).
 *		Echo input if 'visible' is set.
 *		Turning off 'promptindicator' makes piping in input cleaner.
 *
 * NOTE Only using forcepassphrase mandates taking both passphrases
 * from the same source.  Otherwise processing continues until both 
 * passphrases are defined.
 */
int
get_user_passphrases(void)
{
	int		 rval = SNMPERR_SUCCESS,
			 len;

	u_char		*obuf = NULL,
			*nbuf = NULL;
        
	char		 path[SNMP_MAXBUF],
			 buf[SNMP_MAXBUF],
			*s    = NULL;

	struct stat	 statbuf;
	FILE		*fp;

EM(-1); /* */


	/*
	 * Allow prompts to the user to override all other sources.
	 * Nothing to do otherwise if oldpass and newpass are already defined.
	 */
	if ( forcepassphrase )		goto get_user_passphrases_prompt;
	if ( oldpass && newpass )	goto get_user_passphrases_quit;



	/*
	 * Read passphrases out of PASSPHRASE_FILE.  Sanity check the
	 * path for existence and access first.  Refuse to read
	 * if the permissions are wrong.
	 */
	s = getenv("HOME");
	sprintf(path, "%s/%s", s, PASSPHRASE_DIR);

							/* Test directory. */
	if ( stat(path, &statbuf) < 0 ) {
		fprintf(stderr, "Cannot access directory \"%s\".\n", path);
		QUITFUN(rval = SNMPERR_GENERR, get_user_passphrases_quit);

	} else if ( statbuf.st_mode & (S_IRWXG|S_IRWXO) ) {
		fprintf(stderr,
		    "Directory \"%s\" is accessible by group or world.\n",
		    path);
		QUITFUN(rval = SNMPERR_GENERR, get_user_passphrases_quit);
	}

							/* Test file. */
	sprintf(path, "%s/%s", s, PASSPHRASE_FILE);
	if ( stat(path, &statbuf) < 0 ) {
		fprintf(stderr, "Cannot access file \"%s\".\n", path);
		QUITFUN(rval = SNMPERR_GENERR, get_user_passphrases_quit);

	} else if ( statbuf.st_mode & (S_IRWXG|S_IRWXO) ) {
		fprintf(stderr,
			"File \"%s\" is accessible by group or world.\n", path);
		QUITFUN(rval = SNMPERR_GENERR, get_user_passphrases_quit);
	}

							/* Open the file. */
	if ( (fp = fopen(path, "r")) < 0 ) {
		fprintf(stderr, "Cannot open \"%s\".", path);
		QUITFUN(rval = SNMPERR_GENERR, get_user_passphrases_quit);
	}

							/* Read 1st line. */
	if ( !fgets(buf, SNMP_MAXBUF, fp) ) {		
		if ( verbose ) {
			fprintf(VERBOSE_FILE, 
				"Passphrase file \"%s\" is empty...\n", path);
		}
		goto get_user_passphrases_prompt;

	} else if ( !oldpass ) {
		len = strlen(buf);
		if ( buf[len-1] == '\n' )	buf[--len] = '\0';
		oldpass = SNMP_MALLOC(len+1);
		memcpy(oldpass, buf, len+1);
	}
							/* Read 2nd line. */
	if ( !fgets(buf, SNMP_MAXBUF, fp) ) {		
		if ( verbose ) {
			fprintf(VERBOSE_FILE, 
				"Only one line in file \"%s\"...\n", path);
		}

	} else if ( !newpass ) {
		len = strlen(buf);
		if ( buf[len-1] == '\n' )	buf[--len] = '\0';
		newpass = SNMP_MALLOC(len+1);
		memcpy(newpass, buf, len+1);
	}

	if ( oldpass && newpass )	goto get_user_passphrases_quit;



	/*
	 * Prompt the user for passphrase entry.  Visible prompts
	 * may be omitted, and invisible entry may turned off.
	 */
get_user_passphrases_prompt:
	if ( forcepassphrase ) {
		oldpass = newpass = NULL;
	}

	if ( ! oldpass ) {
		oldpass = obuf
			= snmp_getpassphrase(
			    (promptindicator) ? "Old passphrase: " : "",
			    visible);
	}
	if ( ! newpass ) {
		newpass = nbuf
			= snmp_getpassphrase(
			    (promptindicator) ? "New passphrase: " : "",
			    visible);
	}



	/*
	 * Check that both passphrases were defined.
	 */
	if ( oldpass && newpass ) {
		goto get_user_passphrases_quit;
	} else {
		rval = SNMPERR_GENERR;
	}


get_user_passphrases_quit:
	SNMP_ZERO(buf, SNMP_MAXBUF);

	if ( obuf != oldpass ) {
		SNMP_ZERO(obuf, strlen(obuf));
		SNMP_FREE(obuf);
	}
	if ( nbuf != newpass ) {
		SNMP_ZERO(nbuf, strlen(nbuf));
		SNMP_FREE(nbuf);
	}

	return rval;

}  /* end get_user_passphrases() */

