/* tcl_misc.h
 * Small usefull things for tcl-packages.
 * 
 * Poul-Henning Kamp, phk@data.fls.dk
 * 920318 0.00
 * 920319 0.01
 * 920324 0.02
 */

static int
Error(interp,where,why)
    Tcl_Interp  *interp;
    char *where;
    char *why;
    {
    Tcl_AddErrorInfo(interp,where);
    Tcl_AddErrorInfo(interp,": ");
    Tcl_AddErrorInfo(interp,why);
    return TCL_ERROR;
    }

#define CHKNARG(min,max,where) {\
    if(argc<min) return Error(interp,where,"too few args.");\
    if(argc>max) return Error(interp,where,"too many args.");\
    }

static int
Failed(interp,where,why)
    Tcl_Interp  *interp;
    char *where;
    char *why;
    {
    Tcl_AddErrorInfo(interp,where);
    Tcl_AddErrorInfo(interp,": ");
    if(why)
	{
	Tcl_AddErrorInfo(interp,why);
	Tcl_AddErrorInfo(interp," failed.");
	}
    else
	Tcl_AddErrorInfo(interp,"failed.");
    return TCL_ERROR;
    }

#define IFW(st) if(**argv==*st && !strcmp(*argv,st))

#define HUH(interp,where) Error(interp,where,"Huh ?")
