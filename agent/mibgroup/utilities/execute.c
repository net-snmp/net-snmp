/*
 * Utility routines to assist with the running of sub-commands
 */

#include <net-snmp/net-snmp-config.h>

#if HAVE_IO_H
#include <io.h>
#endif
#include <stdio.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_MALLOC_H
#include <malloc.h>
#endif
#include <sys/types.h>
#include <ctype.h>
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "util_funcs.h"

int
run_shell_command( char *command, char *input,
                   char *output,  int *out_len)	/* Or realloc style ? */
{
#if HAVE_SYSTEM
    const char *ifname;    /* Filename for input  redirection */
    const char *ofname;    /* Filename for output redirection */
    char        shellline[STRMAX];   /* The full command to run */
    int         result;    /* and the return value of the command */

    if (!command)
        return -1;

    DEBUGMSGTL(("run_shell_command", "running %s\n", command));
    DEBUGMSGTL(("run:shell", "running '%s'\n", command));

    /*
     * Set up the command to run....
     */
    if (input) {
        FILE       *file;

        ifname = make_tempfile();
        if(NULL == ifname)
            return -1;
        file = fopen(ifname, "w");
        if(NULL == file) {
            snmp_log(LOG_ERR,"couldn't open temporary file %s\n", ifname);
            unlink(ifname);
            return -1;
        }
	fprintf(file, "%s", input);
        fclose( file );

        if (output) {
            ofname = make_tempfile();
            if(NULL == ofname) {
                if(ifname)
                    unlink(ifname);
                return -1;
            }
            snprintf( shellline, sizeof(shellline), "(%s) < \"%s\" > \"%s\"",
                      command, ifname, ofname );
        } else {
            ofname = NULL;   /* Just to shut the compiler up! */
            snprintf( shellline, sizeof(shellline), "(%s) < \"%s\"",
                      command, ifname );
        }
    } else {
        ifname = NULL;   /* Just to shut the compiler up! */
        if (output) {
            ofname = make_tempfile();
            if(NULL == ofname)
                return -1;
            snprintf( shellline, sizeof(shellline), "(%s) > \"%s\"",
                      command, ofname );
        } else {
            ofname = NULL;   /* Just to shut the compiler up! */
            snprintf( shellline, sizeof(shellline), "%s",
                      command );
        }
    }

    /*
     * ... and run it
     */
    result = system(shellline);

    /*
     * If output was requested, then retrieve & return it.
     * Tidy up, and return the result of the command.
     */
    if ( output && out_len && (*out_len != 0) ) {
        int         fd;        /* For processing any output */
        int         len = 0;
        fd = open(ofname, O_RDONLY);
        if(fd >= 0)
            len  = read( fd, output, *out_len-1 );
	*out_len = len;
	if (len >= 0) output[len] = 0;
	else output[0] = 0;
	if (fd >= 0) close(fd);
        unlink(ofname);
    }
    if ( input ) {
        unlink(ifname);
    }

    return result;
#else
    return -1;
#endif
}


/*
 * Split the given command up into separate tokens,
 * ready to be passed to 'execv'
 */
static char **
tokenize_exec_command( char *command, int *argc )
{
    char ctmp[STRMAX];
    char *cptr1, *cptr2;
    char **argv;
    int  count, i;

    if (!command)
        return NULL;

    memset( ctmp, 0, STRMAX );
    /*
     * Make a copy of the command into the 'ctmp' buffer,
     *    splitting it into separate tokens
     *    (but still all in the one buffer).
     */
    count = 1;
    for (cptr1 = command, cptr2 = ctmp;
            cptr1 && *cptr1;
            cptr1++, cptr2++) {
        *cptr2 = *cptr1;
	if (isspace(*cptr1)) {
            /*
             * We've reached the end of a token, so increase
             * the count, and mark this in the command copy.
             * Then get ready for the next word.
             */
            count++;
            *cptr2 = 0;    /* End of token */
	    cptr1 = skip_white(cptr1);
	    if (!cptr1)
	        break;
	    cptr1--;	/* Back up one, ready for the next loop */
	}
    }

    /*
     * Now set up the 'argv' array,
     *   copying tokens out of the 'cptr' buffer
     */
    argv = (char **) calloc((count + 2), sizeof(char *));
    if (argv == NULL)
        return NULL;
    cptr2 = ctmp;
    for (i = 0; i < count; i++) {
        argv[i] = strdup( cptr2 );
        cptr2  += strlen( cptr2 )+1;
    }
    argv[count] = 0;
    *argc       = count;
        
    return argv;
}


int
run_exec_command( char *command, char *input,
                  char *output,  int  *out_len)	/* Or realloc style ? */
{
#if HAVE_EXECV
    int ipipe[2];
    int opipe[2];
    int i, len;
    int pid;
    int result;
    char **argv;
    int argc;

    DEBUGMSGTL(("run:exec", "running '%s'\n", command));
    pipe(ipipe);
    pipe(opipe);
    if ((pid = fork()) == 0) {
        /*
         * Child process
         */

        /*
         * Set stdin/out/err to use the pipe
         *   and close everything else
         */
        close(0);
        dup(  ipipe[0]);
	close(ipipe[1]);

        close(1);
        dup(  opipe[1]);
        close(opipe[0]);
        close(2);
        dup(1);
        for (i = getdtablesize()-1; i>2; i--)
            close(i);

        /*
         * Set up the argv array and execute it
         * This is being run in the child process,
         *   so will release resources when it terminates.
         */
        argv = tokenize_exec_command( command, &argc );
        execv( argv[0], argv );
        perror( argv[0] );
        exit(1);	/* End of child */

    } else if (pid > 0) {
        /*
         * Parent process
         */

        /*
	 * Pass the input message (if any) to the child,
         * wait for the child to finish executing, and read
         *    any output into the output buffer (if provided)
         */
	close(ipipe[0]);
	close(opipe[1]);
	if (input) {
	   write(ipipe[1], input, strlen(input));
	   close(ipipe[1]);	/* or flush? */
        }
	else close(ipipe[1]);
        if (waitpid(pid, &result, 0) < 0 ) {
            snmp_log_perror("waitpid");
            return -1;
        }
        if (output) {
            len = read( opipe[0], output, *out_len-1 );
	    if (len >= 0) output[len] = 0;
	    else output[0] = 0;
	    *out_len = len;
        }
	close(opipe[0]);
	return WEXITSTATUS(result);

    } else {
        /*
         * Parent process - fork failed
         */
        snmp_log_perror("fork");
	close(ipipe[0]);
	close(ipipe[1]);
	close(opipe[0]);
	close(opipe[1]);
	return -1;
    }
    
#else
    /*
     * If necessary, fall back to using 'system'
     */
    return run_shell_command( command, input, output, out_len );
#endif
}
