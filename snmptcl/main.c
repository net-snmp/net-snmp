/* main.c
 * Main-program for
 *	tclnmm
 *	tclsnmp
 *	tclcurses
 * 
 * Poul-Henning Kamp, phk@data.fls.dk
 * 920318 0.00
 * 920319 0.01
 * 920324 0.02
 */

#include <curses.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "tcl.h"

extern int exit();

Tcl_Interp *interp;
Tcl_CmdBuf buffer;
int quitFlag = 0;

int
main(argc,argv)
    int argc;
    char **argv;
    {
    char line[1000], *cmd;
    int result, gotPartial;

    interp = Tcl_CreateInterp();
#ifndef NO_SNMP
    snmp_init(interp);
#endif
#ifndef NO_CURSES
    curses_init(interp);
#endif
    if(argc > 1)
	{
	cmd = Tcl_Merge(argc-1,argv+1);
	Tcl_SetVar(interp,"argv",cmd,TCL_GLOBAL_ONLY);
	sprintf(line,"%d",argc-1);
	Tcl_SetVar(interp,"argc",line,TCL_GLOBAL_ONLY);
	if(TCL_OK == Tcl_EvalFile(interp,*++argv))
	    exit(0);
	cmd=Tcl_GetVar(interp,"errorInfo",TCL_GLOBAL_ONLY);
	if(!cmd)
	    cmd=interp->result;
	fprintf(stderr,"%s\n",cmd );
	exit(1);
	}
    else
	{
	buffer = Tcl_CreateCmdBuf();
	gotPartial = 0;
	while (1) 
	    {
	    clearerr(stdin);
	    if (!gotPartial) 
		{
		fputs("tclnet: ", stdout);
		fflush(stdout);
		}
	    if (fgets(line, 1000, stdin) == NULL) 
		{
		if (!gotPartial) 
		    exit(0);
		line[0] = 0;
		}
	    cmd = Tcl_AssembleCmd(buffer, line);
	    if (cmd == NULL) 
	        {
		gotPartial = 1;
		continue;
		}

	    gotPartial = 0;
	    result = Tcl_RecordAndEval(interp, cmd, 0);
	    if (result == TCL_OK) 
		{
		if (*interp->result != 0) 
		    printf("%s\n", interp->result);
		if (quitFlag) 
		    {
		    Tcl_DeleteInterp(interp);
		    Tcl_DeleteCmdBuf(buffer);
		    exit(0);
		    }
		} 
	    else 
		{
		if (result == TCL_ERROR) 
		    printf("Error");
		else 
		    printf("Error %d", result);
		if (*interp->result != 0) 
		    printf(": %s\n", interp->result);
		else 
		    printf("\n");
		}
	    }
	}
    }
