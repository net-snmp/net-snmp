/*
 * etimetest.c
 *
 * Expected SUCCESSes for all tests:	3
 *
 * Returns:
 *	Number of FAILUREs.
 *
 * Test of hash_engineID().				SUCCESSes:  0
 * Test of LCD Engine ID and Time List.			SUCCESSes:  3
 */

static char *rcsid = "$Id$";	/* */


#include "all_system.h"
#include "all_general_local.h"

static u_int    dummy_etime, dummy_eboot;       /* For ISENGINEKNOWN(). */


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

#define USAGE	"Usage: %s [-h][-s <seconds>][-aeH]"
#define OPTIONLIST	"aehHs:"

int	doalltests	= 0,
	dohashindex	= 0,
	doetimetest	= 0;

#define	ALLOPTIONS	(doalltests + dohashindex + doetimetest)



#define LOCAL_MAXBUF	(1024 * 8)
#define NL		"\n"

#define OUTPUT(o)	fprintf(stdout, "\n\n%s\n\n", o);

#define SUCCESS(s)					\
{							\
	if (!failcount)					\
		fprintf(stdout, "\nSUCCESS: %s\n", s);	\
}

#define FAILED(e, f)					\
{							\
	if (e != SNMPERR_SUCCESS) {			\
		fprintf(stdout, "\nFAILED: %s\n", f);	\
		failcount += 1;				\
	}						\
}



/*
 * Global variables.
 */
int sleeptime = 7;

#define BLAT "alk;djf;an riu;alicenmrul;aiknglksajhe1 adcfalcenrco2"




/*
 * Prototypes.
 */
void	usage(FILE *ofp);

int	test_etime(void);
int	test_hashindex(void);




int
main(int argc, char **argv)
{
	int		 rval		= SNMPERR_SUCCESS,
			 failcount	= 0;
	char		 ch;

	local_progname = argv[0];

EM(-1);	/* */

	/*
	 * Parse.
	 */
	while ( (ch = getopt(argc, argv, OPTIONLIST)) != EOF )
	{
		switch(ch) {
		case 'a':	doalltests = 1;			break;
		case 'e':	doetimetest = 1;		break;
		case 'H':	dohashindex = 1;		break;
		case 's':	sleeptime = atoi(optarg);
				if (sleeptime < 0) {
					usage(stderr); exit(1000);
				}				break;
		break;
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

	} else if ( ALLOPTIONS != 1 ) {
		usage(stdout);
		exit(1000);
	}


	/*
	 * Test stuff.
	 */
	rval = sc_init();
	FAILED(rval, "sc_init()");


	if (dohashindex || doalltests) {
		failcount += test_hashindex();
	}
	if (doetimetest || doalltests) {
		failcount += test_etime();
	}


	/*
	 * Cleanup.
	 */
	rval = sc_shutdown();
	FAILED(rval, "sc_shutdown()");

	return failcount;

} /* end main() */





void
usage(FILE *ofp)
{
	fprintf(ofp,

	USAGE								
	""								NL
	"    -a			All tests."				NL
	"    -e			Exercise the list of enginetimes."	NL
	"    -h			Help."					NL
	"    -H			Test hash_engineID()."			NL
	"    -s <seconds>	Seconds to pause.  (Default: 0.)"	NL
									NL
		, local_progname);

}  /* end usage() */




#ifdef EXAMPLE
/*******************************************************************-o-******
 * test_dosomething
 *
 * Returns:
 *	Number of failures.
 *
 *
 * Test template.
 */
int
test_dosomething(void)
{
	int		rval = SNMPERR_SUCCESS,
			failcount = 0;

EM0(1, "UNIMPLEMENTED");	/* EM(1); /* */

test_dosomething_quit:
	return failcount;

}  /* end test_dosomething() */
#endif /* EXAMPLE */





/*******************************************************************-o-******
 * test_hashindex
 *
 * Returns:
 *	Number of failures.
 *
 *
 * Test hash_engineID().
 */
int
test_hashindex(void)
{
	int		/* rval = SNMPERR_SUCCESS,	*/
			failcount = 0;
	char		*s;

EM(-1); /* */


	OUTPUT(	"Visual spot check of hash index outputs.  "
		"(Success or failure not noted.)");

	s = "A";
	fprintf(stdout, "%s = %d\n", s, hash_engineID(s, strlen(s)) );

	s = "BB";
	fprintf(stdout, "%s = %d\n", s, hash_engineID(s, strlen(s)) );

	s = "CCC";
	fprintf(stdout, "%s = %d\n", s, hash_engineID(s, strlen(s)) );

	s = "DDDD";
	fprintf(stdout, "%s = %d\n", s, hash_engineID(s, strlen(s)) );

	s = "EEEEE";
	fprintf(stdout, "%s = %d\n", s, hash_engineID(s, strlen(s)) );

	s = BLAT;
	fprintf(stdout, "%s = %d\n", s, hash_engineID(s, strlen(s)) );


	OUTPUT("Visual spot check -- DONE.");

	return failcount;

}  /* end test_hashindex() */





/*******************************************************************-o-******
 * test_etime
 *
 * Returns:
 *	Number of failures.
 *
 * Test of LCD Engine ID and Time List.	
 */
int
test_etime(void)
{
	int		rval = SNMPERR_SUCCESS,
			failcount = 0;
	u_int		etime, eboot;

EM(-1); /* */



	/* ------------------------------------ -o-
	 */
	OUTPUT("Query of empty list, two set actions.");


	rval = ISENGINEKNOWN("A", 1);
	if (rval == TRUE) {
		FAILED(SNMPERR_GENERR, "Query of empty list returned TRUE.")
	}


#ifdef FIXmissingargument
	rval = set_enginetime("BB", 2, 20, 2);
	FAILED(rval, "set_enginetime()");


	rval = set_enginetime("CCC", 3, 90127, 31);
	FAILED(rval, "set_enginetime()");
#else
	FAILED(SNMPERR_GENERR, "FIX  update set_enginetime() args...");
#endif


	SUCCESS("Check of empty list, and two additions.");



	/* ------------------------------------ -o-
	 */
	OUTPUT("Add entries using macros, test for existence with macros.");


	rval = ENSURE_ENGINE_RECORD("DDDD", 4);
	FAILED(rval, "ENSURE_ENGINE_RECORD()");


	rval = MAKENEW_ENGINE_RECORD("EEEEE", 5);
	if (rval == SNMPERR_SUCCESS) {
		FAILED(	rval,
			"MAKENEW_ENGINE_RECORD returned success for "
			"missing record.");
	}


	rval = MAKENEW_ENGINE_RECORD("BB", 2);
	FAILED(rval, "MAKENEW_ENGINE_RECORD().");


	SUCCESS("Added entries with macros, tested for existence with macros.");



	/* ------------------------------------ -o-
	 */
	OUTPUT("Dump the list and then sleep.");

	dump_etimelist();

	fprintf(stdout, "\nSleeping for %d second%s... ",
					sleeptime, (sleeptime==1)?"":"s");
	fflush(stdout);

	sleep(sleeptime);
	fprintf(stdout, "\n");



	/* ------------------------------------ -o-
	 */
	OUTPUT("Retrieve data from real/stubbed records, update real/stubbed.");



#ifdef FIXmissingargument
	rval = get_enginetime("BB", 2, &etime, &eboot);
	FAILED(rval, "get_enginetime().");
#else
	FAILED(SNMPERR_GENERR, "FIX3  update set_enginetime() args...");
#endif

	fprintf(stdout, "BB = <%d,%d>\n", etime, eboot);
	if ( (etime < 20) || (eboot < 2) ) {
		FAILED(	SNMPERR_GENERR,
			"get_enginetime() returned bad values.  (1)");
	}


#ifdef FIXmissingargument
	rval = get_enginetime("DDDD", 4, &etime, &eboot);
	FAILED(rval, "get_enginetime().");
#else
	FAILED(SNMPERR_GENERR, "FIX3  update set_enginetime() args...");
#endif

	fprintf(stdout, "DDDD = <%d,%d>\n", etime, eboot);
	if ( (etime < sleeptime) || (eboot != 0) ) {
		FAILED(	SNMPERR_GENERR,
			"get_enginetime() returned bad values.  (2)");
	}


#ifdef FIXmissingargument
	rval = set_enginetime("CCC", 3, 10000, 234);
	FAILED(rval, "set_enginetime().");


	rval = set_enginetime("EEEEE", 5, 55555, 9876);
	FAILED(rval, "set_enginetime().");
#else
	FAILED(SNMPERR_GENERR, "FIX2  update set_enginetime() args...");
#endif


	SUCCESS("Retrieval and updates.");



	/* ------------------------------------ -o-
	 */
	OUTPUT("Sleep again, then dump the list one last time.");

	fprintf(stdout, "Sleeping for %d second%s... ",
					sleeptime, (sleeptime==1)?"":"s");
	fflush(stdout);

	sleep(sleeptime);
	fprintf(stdout, "\n");

	dump_etimelist();


	return failcount;

}  /* end test_etime() */

