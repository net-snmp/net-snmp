/*
 * htext.c --
 *
 * Copyright 1990 Regents of the University of California.
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies.  The University of California
 * makes no representations about the suitability of this
 * software for any purpose.  It is provided "as is" without
 * express or implied warranty.
 *
 * Copyright 1991,1992 by AT&T Bell Laboratories.
 * Permission to use, copy, modify, and distribute this software
 * and its documentation for any purpose and without fee is hereby
 * granted, provided that the above copyright notice appear in all
 * copies and that both that the copyright notice and warranty
 * disclaimer appear in supporting documentation, and that the
 * names of AT&T Bell Laboratories any of their entities not be used
 * in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 *
 * AT&T disclaims all warranties with regard to this software, including
 * all implied warranties of merchantability and fitness.  In no event
 * shall AT&T be liable for any special, indirect or consequential
 * damages or any damages whatsoever resulting from loss of use, data
 * or profits, whether in an action of contract, negligence or other
 * tortious action, arising out of or in connection with the use or
 * performance of this software.
 *
 * Hypertext widget created by George Howlett.
 */

/*
 * To do:
 *
 * 1) Fix scroll unit round off errors.
 *
 * 2) Bug in reporting errors in Tcl evaluations.
 *
 * 3) Selections of text. (characters, word, line)
 *
 * 4) Tabstops for easier placement of text and child widgets.
 *    Use variable "tabstops" to set/reset tabstops.
 *
 * 5) Better error checking.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <tcl.h>
#include <tk.h>
#include <X11/Xutil.h>

#define TRUE 		1
#define FALSE		0
#define NULLSTR(s)	((s)==NULL || *(s)=='\0')
#define LINES_ALLOC_CHUNK 512
#define MAX_WIN_SIZE    3000

#define MIN(a,b)	(((a)<(b))?(a):(b))
#define MAX(a,b)	(((a)>(b))?(a):(b))

#ifdef DEBUG
#include <malloc.h>
#endif

#ifdef __GNUG__
#define INLINE inline
#else
#define INLINE
#endif

/*
 * Flags passed to TkMeasureChars: taken from tkInt.h
 */
#define TK_WHOLE_WORDS          1
#define TK_AT_LEAST_ONE         2
#define TK_PARTIAL_OK           4

#define BLACK		"Black"
#define WHITE		"White"
#define BISQUE1		"#ffe4c4"
#define BISQUE2		"#eed5b7"
#define BISQUE3		"#cdb79e"
#define LIGHTBLUE2	"#b2dfee"
#define LIGHTPINK1	"#ffaeb9"
#define MAROON		"#b03060"

/*
 * Flag bits children subwindows:
 *
 * VISIBLE:          Child is in the viewport.
 * MAPPED:	     Child is mapped on the screen.
 */
#define MAPPED			2
#define VISIBLE			4
/*
 * Flag bits for the hypertext widget:
 *
 * REDRAW_PENDING:   Non-zero means a DoWhenIdle handler has already been
 *		     queued to redraw this window.
 *
 * LAYOUT_NEEDED:    Something has happened which requires the layout of
 *		     the text and child window positions to be recalculated.
 *                   The following actions may cause this:
 *
 *		     - the contents of the hypertext has changed by
 *		  	either the -file or -text options.
 *		     - a text attribute has changed (line spacing, font, etc)
 *		     - a subwindow has changed (resized or moved).
 *		     - a child configuration option has changed.
 *
 * LAYOUT_CHANGED:   The layout was recalculated and the size of the world
 *		     (text layout) has changed.
 *
 * VIEWPORT_MOVED:   The position of the viewport has moved.  The occurs
 *		     when scrolling or goto-ing a new line.
 *
 * VIEWPORT_RESIZED: The size of the viewport (i.e. window size) has changed.
 *
 * IGNORE_EXPOSURES: Ignore exposure events in the text window.  Potentially
 *		     many expose events may occur when unmapping, rearranging,
 *		     or resizing child subwindows during a single call to
 *		     the text display routine.  This flag is examined in the
 *		     event handler to determine if a call to the display
 *		     routine is necessary.
 *
 * GOTO_PENDING:     Non-zero means that the widget should move to a new
 *		     starting line number when redrawing.
 *
 */
#define REDRAW_PENDING		1
#define IGNORE_EXPOSURES	2
#define VIEWPORT_RESIZED	4
#define VIEWPORT_MOVED		8
#define LAYOUT_NEEDED		0x10
#define LAYOUT_CHANGED		0x20
#define GOTO_PENDING 		0x40

typedef struct Child {

    /* private: */
    struct Hypertext *parent;/* Parent widget */
    Tk_Window tkwin;	     /* Widget window */
    int flags;

    int x, y;		     /* Origin of child subwindow */
    short int width, height; /* Size of child region */

    int precedingTextEnd;    /* Number of characters of text */
    int precedingTextWidth;  /* Width of normal text preceding child */

    struct Child *nextPtr;   /* Next child in list */

    /* public: */
    int widthWanted;	     /* Constraint for width */
    int heightWanted;	     /* Constraint for height */
    int padX;		     /* Pad to child width */
    int padY;		     /* Pad to height */
    Tk_Anchor anchor;
} Child;

/*
 * Information used for parsing configuration specs:
 */

/*
 * Defaults for children:
 */
#define DEF_CHILD_WIDTH_WANTED  "0"
#define DEF_CHILD_HEIGHT_WANTED	"0"
#define DEF_CHILD_ANCHOR        "center"
#define DEF_CHILD_PADX		"0"
#define DEF_CHILD_PADY		"0"

static Tk_ConfigSpec childConfigSpecs[]=
{
    {TK_CONFIG_ANCHOR, "-anchor", "anchor", "anchor",
     DEF_CHILD_ANCHOR, Tk_Offset (Child, anchor), 0},
    {TK_CONFIG_PIXELS, "-height", "height", "Height",
     DEF_CHILD_HEIGHT_WANTED, Tk_Offset (Child, heightWanted), 0},
    {TK_CONFIG_PIXELS, "-padx", "padX", "Pad",
     DEF_CHILD_PADX, Tk_Offset (Child, padX), 0},
    {TK_CONFIG_PIXELS, "-pady", "padY", "Pad",
     DEF_CHILD_PADY, Tk_Offset (Child, padY), 0},
    {TK_CONFIG_PIXELS, "-width", "width", "Width",
     DEF_CHILD_WIDTH_WANTED, Tk_Offset (Child, widthWanted), 0},
    {TK_CONFIG_END, (char *)NULL, (char *)NULL, (char *)NULL,
     (char *)NULL, 0, 0}
};

/*
 * Structure to contain the contents of a single line of text and the
 * children on that line.
 *
 * Individual lines are not configureable, although changes to the
 * size of children do effect its values.
 */

typedef struct {
    /* private: */
    int offset;		     /* offset (in pixels) from world coordinate 0,0 */

    short int height;	     /* Height of line */
    short int width;	     /* Width of line */
    short int baseline;	     /* Baseline of text */
    short int textLength;    /* Number of characters in normal text */
    char *text;		     /* The plain text on the line */

    Child *children;	     /* List of children for the line */
    Child *lastChild;	     /* Last child in list */

} Line;

/*
 * Hypertext widget.
 */
typedef struct Hypertext {
    /* private: */
    Tk_Window tkwin;	     /* Window that embodies the child. NULL means
			      * that the window has been destroyed. */
    Tcl_Interp *interp;	     /* Interpreter associated with child. */
    int flags;

    GC gc;		     /* Graphics context for normal text */
    Tk_3DBorder border;	     /* used ?? */
    XColor *normalFg;

    Line **lineArr;	     /* Array of text lines */
    int numLines;	     /* Number of filled entries in array */
    int arraySize;	     /* Number of entries allocated for array */
    int height;		     /* Height of text in pixels */
    int width;		     /* Width of text in pixels */

    /*
     * The view port is the width and height of the window and the origin of
     * the viewport (upper left corner) in world coordinates.
     */
    int x, y;
    int newX, newY;
    int lineRequested;	     /* Line requested by "gotoline" command */
    int first, last;	     /* Range of lines displayed */

    /*
     * Selections:
     */
    Tk_3DBorder selBorder;   /* Border and background for selected
			      * characters. */
    int selBorderWidth;	     /* Width of border around selection. */
    XColor *selFgColorPtr;   /* Foreground color for selected text. */
    GC selTextGC;	     /* For drawing selected text. */

    /*
     * Information about what's selected, if any.
     */

    int selectFirst;	     /* Position of first selected character (-1
			      * means nothing selected). */
    int selectLast;	     /* Position of last selected character (-1 means
			      * nothing selected). */
    int selectAnchor;	     /* Fixed end of selection (i.e. "select to"
			      * operation will use this as one end of the
			      * selection). */

    /*
     * Information for scanning:
     */

    int scanMarkX;	     /* X-position at which scan started (e.g. button
			      * was pressed here). */
    int scanPtX;	     /* Position (x-offset) of the viewport when the
			      * scan started. */

    int scanMarkY;	     /* Y-position at which scan started (e.g. button
			      * was pressed here). */
    int scanPtY;	     /* Position (y-offset) of the viewport when the
			      * scan started. */

    /* public: */
    char *geometry;
    char *yScrollCmd;	     /* Name of vertical scrollbar to invoke */
    int yScrollUnits;	     /* # of pixels per vert scroll */
    char *xScrollCmd;	     /* Name of horizontal scroll bar to invoke */
    int xScrollUnits;	     /* # of pixels per horiz scroll */
    int lineSpacing;	     /* # of pixels between lines */
    int specChar;	     /* Special character designating a TCL command
			      * block in a hypertext file. */
    XFontStruct *fontPtr;    /* Font for normal text */

    char *fileName;	     /* Name of hypertext file  */
    char *text;		     /* Text */
    Cursor cursor;	     /* X Cursor for child */

} Hypertext;

#define DEF_HTEXT_ACTIVE_BG_COLOR	BISQUE2
#define DEF_HTEXT_ACTIVE_BG_MONO	BLACK
#define DEF_HTEXT_ACTIVE_FG_COLOR	BLACK
#define DEF_HTEXT_ACTIVE_FG_MONO	WHITE
#define DEF_HTEXT_BG_COLOR		BISQUE1
#define DEF_HTEXT_BG_MONO		WHITE
#define DEF_HTEXT_COMMAND		((char *) NULL)
#define DEF_HTEXT_CURSOR		"pencil"
#define DEF_HTEXT_FONT			"*-Helvetica-Bold-R-Normal-*-120-*"
#define DEF_HTEXT_FG			BLACK
#define DEF_HTEXT_GEOMETRY	        "500x500"
#define DEF_HTEXT_OFF_VALUE		"0"
#define DEF_HTEXT_ON_VALUE		"1"
#define DEF_HTEXT_RELIEF		"sunken"
#define DEF_HTEXT_SCROLL_UNITS		"10"
#define DEF_HTEXT_LINE_SPACING		"1"
#define DEF_HTEXT_SPEC_CHAR	        "0x25"


static Tk_ConfigSpec configSpecs[]=
{
    {TK_CONFIG_BORDER, "-background", "background", "Background",
   DEF_HTEXT_BG_COLOR, Tk_Offset (Hypertext, border), TK_CONFIG_COLOR_ONLY},
    {TK_CONFIG_BORDER, "-background", "background", "Background",
     DEF_HTEXT_BG_MONO, Tk_Offset (Hypertext, border), TK_CONFIG_MONO_ONLY},
    {TK_CONFIG_SYNONYM, "-bg", "background", (char *)NULL,
     (char *)NULL, 0, 0},
    {TK_CONFIG_SYNONYM, "-fg", "foreground", (char *)NULL,
     (char *)NULL, 0, 0},
    {TK_CONFIG_FONT, "-font", "font", "Font",
     DEF_HTEXT_FONT, Tk_Offset (Hypertext, fontPtr), 0},
    {TK_CONFIG_COLOR, "-foreground", "foreground", "Foreground",
     DEF_HTEXT_FG, Tk_Offset (Hypertext, normalFg), 0},
    {TK_CONFIG_STRING, "-geometry", "geometry", "Geometry",
     DEF_HTEXT_GEOMETRY, Tk_Offset (Hypertext, geometry), 0},
    {TK_CONFIG_STRING, "-text", "text", "Text",
     (char *)NULL, Tk_Offset (Hypertext, text), 0},
    {TK_CONFIG_STRING, "-filename", "fileName", "FileName",
     (char *)NULL, Tk_Offset (Hypertext, fileName), 0},
    {TK_CONFIG_INT, "-specialchar", "specialChar", "SpecialChar",
     DEF_HTEXT_SPEC_CHAR, Tk_Offset (Hypertext, specChar), 0},
    {TK_CONFIG_STRING, "-yscrollcommand", "yScrollCommand", "ScrollCommand",
     (char *)NULL, Tk_Offset (Hypertext, yScrollCmd), 0},
    {TK_CONFIG_PIXELS, "-yscrollunits", "yScrollUnits", "yScrollUnits",
     DEF_HTEXT_SCROLL_UNITS, Tk_Offset (Hypertext, yScrollUnits), 0},
    {TK_CONFIG_STRING, "-xscrollcommand", "xScrollCommand", "ScrollCommand",
     (char *)NULL, Tk_Offset (Hypertext, xScrollCmd), 0},
    {TK_CONFIG_PIXELS, "-xscrollunits", "xScrollUnits", "ScrollUnits",
     DEF_HTEXT_SCROLL_UNITS, Tk_Offset (Hypertext, xScrollUnits), 0},
    {TK_CONFIG_PIXELS, "-linespacing", "lineSpacing", "LineSpacing",
     DEF_HTEXT_LINE_SPACING, Tk_Offset (Hypertext, lineSpacing), 0},
    {TK_CONFIG_ACTIVE_CURSOR, "-cursor", "cursor", "Cursor",
     DEF_HTEXT_CURSOR, Tk_Offset (Hypertext, cursor), TK_CONFIG_NULL_OK},
    {TK_CONFIG_END, (char *)NULL, (char *)NULL, (char *)NULL,
     (char *)NULL, 0, 0}
};

/* Forward Declarations */
static Hypertext *CreateText _ANSI_ARGS_ ((Tcl_Interp * interp,
					   Tk_Window tkwin, char *name));
static void DestroyText _ANSI_ARGS_ ((ClientData clientdata));
static int ConfigureText _ANSI_ARGS_ ((Tcl_Interp * interp,
		    Hypertext * textPtr, int argc, char **argv, int flags));
static void TextEventProc _ANSI_ARGS_ ((ClientData clientdata,
					XEvent * eventPtr));
static void EventuallyRedraw _ANSI_ARGS_ ((Hypertext * textPtr));
static void TextScanTo _ANSI_ARGS_ ((Hypertext * textPtr, int x, int y));
static int ParseText _ANSI_ARGS_ ((Tcl_Interp * interp, Hypertext * textPtr));
static int ReadFile _ANSI_ARGS_ ((Tcl_Interp * interp, Hypertext * textPtr));
static int AppendChild _ANSI_ARGS_ ((Hypertext * textPtr, char *childName,
				     int argc, char **argv));
static Child *CreateChild _ANSI_ARGS_ ((Tcl_Interp * interp,
				     Hypertext * textPtr, char *childName));
static void DestroyChild _ANSI_ARGS_ ((Child * childPtr));
static void ChildStructureProc _ANSI_ARGS_ ((ClientData clientdata,
					     XEvent * eventPtr));
static int ConfigureChild _ANSI_ARGS_ ((Hypertext * textPtr, Child * childPtr,
					int argc, char **argv, int flags));
static Child *FindChild _ANSI_ARGS_ ((Tcl_Interp * interp, Hypertext * textPtr,
				      char *childName));
static char *GetTclCommand _ANSI_ARGS_ ((Hypertext * textPtr, int *curPos,
					 char *command));
static Line *GetLine _ANSI_ARGS_ ((Hypertext * textPtr));
static void DestroyLine _ANSI_ARGS_ ((Line * linePtr));
static void SetLineText _ANSI_ARGS_ ((Line * linePtr, char *line, int size));
static void ComputeLayout _ANSI_ARGS_ ((Hypertext * textPtr, int *width,
					int *height));
static void GetLineExtents _ANSI_ARGS_ ((Hypertext * textPtr, Line * linePtr));
static void FreeLines _ANSI_ARGS_ ((Hypertext * textPtr));
static void AdjustLinesAllocated _ANSI_ARGS_ ((Hypertext * textPtr));
static void DisplayText _ANSI_ARGS_ ((ClientData clientData));
static void DrawPage _ANSI_ARGS_ ((Hypertext * textPtr, int deltaY));
static void MoveChild _ANSI_ARGS_ ((Child * childPtr, int x, int y));
static void TextUpdateScrollBar _ANSI_ARGS_ ((Tcl_Interp * interp, char *cmd,
			      int total, int window, int first, int units));
static int GetVisibleLines _ANSI_ARGS_ ((Hypertext * textPtr));
static int LineSearch _ANSI_ARGS_ ((Hypertext * textPtr, int position,
				    int low, int high));
static char *reallocate _ANSI_ARGS_ ((char *object, unsigned int newSize,
				      unsigned int oldSize));
static void CreateTraces _ANSI_ARGS_ ((Hypertext * textPtr));
static void DeleteTraces _ANSI_ARGS_ ((Hypertext * textPtr));
static void ChildGeometryProc _ANSI_ARGS_ ((ClientData clientData,
					    Tk_Window tkwin));
static void SendExposeEvent _ANSI_ARGS_ ((Tk_Window tkwin));

extern void TkDisplayChars _ANSI_ARGS_ ((Display * display, Drawable drawable,
	     GC gc, XFontStruct * fontStructPtr, char *string, int numChars,
					 int x, int y, int flags));
extern int TkMeasureChars _ANSI_ARGS_ ((XFontStruct * fontStructPtr,
		char *source, int maxChars, int startX, int maxX, int flags,
					int *nextXPtr));
extern void TkBindError _ANSI_ARGS_ ((Tcl_Interp * interp));

/* end of Forward Declarations */

extern char *sys_errlist[];

static int
OptionChanged (offset, specs)
    register int offset;
    Tk_ConfigSpec specs[];
{
    register Tk_ConfigSpec *specPtr;

    for (specPtr = specs; specPtr->type != TK_CONFIG_END; specPtr++) {
	if (offset == specPtr->offset)
	    return (specPtr->specFlags & TK_CONFIG_OPTION_SPECIFIED);
    }
    /* Can't be here */
    fprintf (stderr, "Unknown option specified\n");
    return (0);
}

/*
 * --------------------------------------------------------------
 *
 * HypertextCmd --
 *
 * 	This procedure is invoked to process the "htext" Tcl command.
 *	See the user documentation for details on what it does.
 *
 * Results:
 *	A standard Tcl result.
 *
 * Side effects:
 *	See the user documentation.
 *
 * --------------------------------------------------------------
 */

int
HypertextCmd (clientData, interp, argc, argv)
    ClientData clientData;   /* Main window associated with interpreter. */
    Tcl_Interp *interp;	     /* Current interpreter. */
    int argc;		     /* Number of arguments. */
    char **argv;	     /* Argument strings. */
{
    register Hypertext *textPtr;
    Tk_Window tkwin = (Tk_Window) clientData;

    if (argc < 2) {
	Tcl_AppendResult (interp, "wrong # args: should be \"", argv[0],
			  " pathName ?options?\"", NULL);
	return TCL_ERROR;
    }
    textPtr = CreateText (interp, tkwin, argv[1]);
    if (textPtr == NULL) {
	return TCL_ERROR;
    }
    if (ConfigureText (interp, textPtr, argc - 2, argv + 2, 0) != TCL_OK) {
	Tk_DestroyWindow (textPtr->tkwin);
	return TCL_ERROR;
    }
    interp->result = Tk_PathName (textPtr->tkwin);
    return TCL_OK;
}

/*
 * --------------------------------------------------------------
 *
 * TextWidgetCmd --
 *
 * 	This procedure is invoked to process the Tcl command that
 *	corresponds to a widget managed by this module. See the user
 * 	documentation for details on what it does.
 *
 * Results:
 *	A standard Tcl result.
 *
 * Side effects:
 *	See the user documentation.
 *
 * --------------------------------------------------------------
 */

static int
TextWidgetCmd (clientData, interp, argc, argv)
    ClientData clientData;   /* Information about hypertext widget. */
    Tcl_Interp *interp;	     /* Current interpreter. */
    int argc;		     /* Number of arguments. */
    char **argv;	     /* Argument strings. */
{
    register Hypertext *textPtr = (Hypertext *) clientData;
    Tk_Window tkwin = textPtr->tkwin;
    int result = TCL_OK;
    int length;
    char c;

    if (argc < 2) {
	Tcl_AppendResult (interp, "wrong # args: should be \"", argv[0],
			  " option ?arg arg ...?\"", NULL);
	return TCL_ERROR;
    }
    Tk_Preserve ((ClientData) textPtr);
    c = argv[1][0];
    length = strlen (argv[1]);

    if ((c == 'a') && (strncmp (argv[1], "append", length) == 0)) {
	if (argc < 3) {
	    Tcl_AppendResult (interp, "wrong # args: should be \"", argv[0],
			      " append pathName ?options?\"", NULL);
	    goto error;
	}
	if (AppendChild (textPtr, argv[2], argc - 3, argv + 3) != TCL_OK)
	    goto error;
	goto redisplay;
    } else if ((c == 'c') && (length > 1) &&
	       (strncmp (argv[1], "childconfigure", length) == 0)) {
	Child *childPtr;

	if (argc < 3) {
	    Tcl_AppendResult (interp, "wrong # args: should be \"", argv[0],
			      " childconfigure childName ?args...?\"", NULL);
	    goto error;
	}
	childPtr = FindChild (interp, textPtr, argv[2]);
	if (childPtr == NULL) {
	    Tcl_AppendResult (interp,
	     "Can't find any child window matching \"", argv[2], "\" in \"",
			      Tk_PathName (tkwin), "\"", NULL);
	    goto error;
	}
	if (argc == 3) {
	    return (Tk_ConfigureInfo (interp, tkwin, childConfigSpecs,
				      (char *)childPtr, (char *)NULL, 0));
	} else if (argc == 4) {
	    return (Tk_ConfigureInfo (interp, tkwin, childConfigSpecs,
				      (char *)childPtr, argv[3], 0));
	} else {
	    result = ConfigureChild (textPtr, childPtr, argc - 3, argv + 3,
				     TK_CONFIG_ARGV_ONLY);
	}
	goto redisplay;

    } else if ((c == 'c') && (length > 1) &&
	       (strncmp (argv[1], "configure", length) == 0)) {
	if (argc == 2) {
	    result = Tk_ConfigureInfo (interp, tkwin, configSpecs,
				       (char *)textPtr, (char *)NULL, 0);
	} else if (argc == 3) {
	    result = Tk_ConfigureInfo (interp, tkwin, configSpecs,
				       (char *)textPtr, argv[2], 0);
	} else {
	    result = ConfigureText (interp, textPtr, argc - 2, argv + 2,
				    TK_CONFIG_ARGV_ONLY);
	    goto redisplay;
	}
    } else if ((c == 'g') && (strncmp (argv[1], "gotoline", length) == 0)) {
        char buf[80];
	int lineNumber;

        if (argc > 3) {
	    Tcl_AppendResult (interp, "wrong # args: should be \"", argv[0],
			      " gotoline lineNumber\"", NULL);
	    goto error;
	} 
	lineNumber = textPtr->first;
	if (argc == 3) {
	    if (Tcl_GetInt (interp, argv[2], &lineNumber) != TCL_OK)
	        goto error;
	    if (lineNumber <= 0)
	        lineNumber = 0;
	    else if (lineNumber > textPtr->numLines)
	        lineNumber = textPtr->numLines - 1;
	    else 
	        lineNumber--;
	}
	sprintf (buf, "%d", lineNumber + 1);
	Tcl_SetResult (interp, buf, TCL_VOLATILE);
	result = TCL_OK;
	if ((textPtr->flags & GOTO_PENDING) || lineNumber != textPtr->first) {
	  /*
	   * Defer performing the actual scroll to later since the layout may
	   * may not be correct or the window may be unmapped.
	   */
	   textPtr->lineRequested = lineNumber;
	   textPtr->flags |= (GOTO_PENDING | VIEWPORT_MOVED);
	   goto redisplay;
	}
    } else if ((c == 'x') && (strncmp (argv[1], "xview", length) == 0)) {
        char buf[80];
	int newX;

	if (argc > 3) {
	    Tcl_AppendResult (interp, "wrong # args: should be \"", argv[0],
			      " xview ?position?\"", NULL);
	    goto error;
	} 
	newX = textPtr->x;
	if (argc == 3) {
	    if (Tk_GetPixels (interp, tkwin, argv[2], &newX) != TCL_OK) 
		goto error;
	    newX *= textPtr->xScrollUnits;	/* Convert to pixels */
	    if (newX > textPtr->width)
	        newX = textPtr->width - 1;
	    else if (newX < 0)
	        newX = 0;
	}
	sprintf (buf, "%d", newX / textPtr->xScrollUnits);
	Tcl_SetResult (interp, buf, TCL_VOLATILE);
	result = TCL_OK;
	if (newX != textPtr->x) {
	    textPtr->newX = newX;
	    textPtr->flags |= VIEWPORT_MOVED;
	    goto redisplay;
	}
    } else if ((c == 'y') && (strncmp (argv[1], "yview", length) == 0)) {
        char buf[80];
	int newY;

	if (argc > 3) {
	    Tcl_AppendResult (interp, "wrong # args: should be \"", argv[0],
			      " yview ?position?\"", NULL);
	    goto error;
	}
	newY = textPtr->y;
	if (argc == 3) {
	    if (Tk_GetPixels (interp, tkwin, argv[2], &newY) != TCL_OK)
		goto error;
	    newY *= textPtr->yScrollUnits;
	    if (newY > textPtr->height)
	        newY = textPtr->height - 1;
	    else if (newY < 0)
	        newY = 0;
	}
	sprintf (buf, "%d", newY / textPtr->yScrollUnits);
	Tcl_SetResult (interp, buf, TCL_VOLATILE);
	result = TCL_OK;
	if (newY != textPtr->y) {
	    textPtr->newY = newY;
	    textPtr->flags |= VIEWPORT_MOVED;
	    goto redisplay;
	}
    } else if ((c == 'm') && (strncmp (argv[1], "map", length) == 0)) {
	Child *childPtr;

	if (argc != 3) {
	    Tcl_AppendResult (interp, "wrong # args: should be \"", argv[0],
			      " map childName\"", NULL);
	    goto error;
	}
	childPtr = FindChild (interp, textPtr, argv[2]);
	if (childPtr == NULL) {
	    Tcl_AppendResult (interp,
	     "Can't find any child window matching \"", argv[2], "\" in \"",
			      Tk_PathName (tkwin), "\"", NULL);
	    goto error;
	}
	if (childPtr->tkwin != NULL) {
	    Tk_MapWindow (childPtr->tkwin);
	    childPtr->flags |= MAPPED;
	}
    } else if ((c == 'u') && (strncmp (argv[1], "unmap", length) == 0)) {
	Child *childPtr;

	if (argc != 3) {
	    Tcl_AppendResult (interp, "wrong # args: should be \"", argv[0],
			      " unmap childName\"", NULL);
	    goto error;
	}
	childPtr = FindChild (interp, textPtr, argv[2]);
	if (childPtr == NULL) {
	    Tcl_AppendResult (interp,
	     "Can't find any child window matching \"", argv[2], "\" in \"",
			      Tk_PathName (tkwin), "\"", NULL);
	    goto error;
	}
	if (childPtr->tkwin != NULL) {
	    Tk_UnmapWindow (childPtr->tkwin);
	    childPtr->flags &= ~MAPPED;
	}
    } else if ((c == 's') && (length > 1)
	       && (strncmp (argv[1], "scan", length) == 0)) {
	int x, y;

	if (argc != 5) {
	    Tcl_AppendResult (interp, "wrong # args: should be \"",
			  argv[0], " scan mark|dragto x y\"", (char *)NULL);
	    goto error;
	}
	if (Tcl_GetInt (interp, argv[3], &x) != TCL_OK ||
	    Tcl_GetInt (interp, argv[4], &y) != TCL_OK) {
	    goto error;
	}
	c = argv[2][0];
	length = strlen (argv[2]);
	if ((c == 'm') && (strncmp (argv[2], "mark", length) == 0)) {
	    textPtr->scanMarkX = x;
	    textPtr->scanMarkY = y;
	    textPtr->scanPtX = textPtr->x;
	    textPtr->scanPtY = textPtr->y;
	} else if ((c == 'd') && (strncmp (argv[2], "dragto", length) == 0)) {
	    TextScanTo (textPtr, x, y);
	} else {
	    Tcl_AppendResult (interp, "bad scan option \"", argv[2],
			      "\":  must be mark or dragto", (char *)NULL);
	    goto error;
	}
#ifdef notdef
    } else if ((c == 's') && (length > 1) &&
	       strncmp (argv[1], "select", length) == 0) {
	int index;

	if (argc < 3) {
	    Tcl_AppendResult (interp, "too few args: should be \"",
			 argv[0], " select option ?index?\"", (char *)NULL);
	    goto error;
	}
	length = strlen (argv[2]);
	c = argv[2][0];
	if ((c == 'c') && (strncmp (argv[2], "clear", length) == 0)) {
	    if (argc != 3) {
		Tcl_AppendResult (interp, "wrong # args: should be \"",
				  argv[0], " select clear\"", (char *)NULL);
		goto error;
	    }
	    if (textPtr->selectFirst != -1) {
		textPtr->selectFirst = textPtr->selectLast = -1;
		goto redisplay;
	    }
	    goto error;
	}
	if (argc >= 4) {
	    if (GetTextIndex (interp, textPtr, argv[3], &index) != TCL_OK) {
		goto error;
	    }
	}
	if ((c == 'a') && (strncmp (argv[2], "adjust", length) == 0)) {
	    if (argc != 4) {
		Tcl_AppendResult (interp, "wrong # args: should be \"",
				  argv[0], " select adjust index\"",
				  (char *)NULL);
		goto error;
	    }
	    TextSelectTo (textPtr, index);
	} else if ((c == 'f') && (strncmp (argv[2], "from", length) == 0)) {
	    if (argc != 4) {
		Tcl_AppendResult (interp, "wrong # args: should be \"",
				  argv[0], " select from index\"",
				  (char *)NULL);
		goto error;
	    }
	    textPtr->selectAnchor = index;
	} else if ((c == 't') && (strncmp (argv[2], "to", length) == 0)) {
	    if (argc != 4) {
		Tcl_AppendResult (interp, "wrong # args: should be \"",
				  argv[0], " select to index\"",
				  (char *)NULL);
		goto error;
	    }
	    TextSelectTo (textPtr, index);
	} else {
	    Tcl_AppendResult (interp, "bad select option \"", argv[2],
		    "\": must be adjust, clear, from, or to", (char *)NULL);
	    goto error;
	}
#endif
    } else {
	Tcl_AppendResult (interp, "bad option \"", argv[1], "\":",
			  " should be append, configure, childconfigure, ",
			  "gotoline, map, unmap, xview, or yview", NULL);
	goto error;
    }
    Tk_Release ((ClientData) textPtr);
    return result;

  redisplay:
    EventuallyRedraw (textPtr);
    Tk_Release ((ClientData) textPtr);
    return TCL_OK;

  error:
    Tk_Release ((ClientData) textPtr);
    return TCL_ERROR;
}

/*
 * ----------------------------------------------------------------------
 *
 * CreateText --
 *
 * 	This procedure creates and initializes a new hypertext widget.
 *
 * Results:
 *	The return value is a pointer to a structure describing the new
 * 	widget.  If an error occurred, then the return value is NULL and
 *	an error message is left in interp->result.
 *
 * Side effects:
 *	Memory is allocated, a Tk_Window is created, etc.
 *
 * ----------------------------------------------------------------------
 */

static Hypertext *
CreateText (interp, tkwin, pathName)
    Tcl_Interp *interp;	     /* Used for error reporting. */
    Tk_Window tkwin;	     /* Window to use for resolving pathName. */
    char *pathName;	     /* Name for new window. */
{
    register Hypertext *textPtr;
    Tk_Window new;

    /*
     * Create the new window.
     */
    new = Tk_CreateWindowFromPath (interp, tkwin, pathName, (char *)NULL);
    if (new == NULL) {
	return (NULL);
    }
    Tk_SetClass (new, "Hypertext");

    /*
     * Initialize the data structure for the Hypertext.
     */
    textPtr = (Hypertext *) calloc (1, sizeof (Hypertext));
    if (textPtr == NULL) {
	return (NULL);
    }
    textPtr->tkwin = new;
    textPtr->interp = interp;
    textPtr->numLines = textPtr->arraySize = 0;

    Tk_CreateEventHandler (new, ExposureMask | StructureNotifyMask,
			   TextEventProc, (ClientData) textPtr);
    Tcl_CreateCommand (interp, pathName, TextWidgetCmd, (ClientData) textPtr,
		       (Tcl_CmdDeleteProc *) NULL);
    return textPtr;
}

/*
 * ----------------------------------------------------------------------
 *
 * DestroyText --
 *
 * 	This procedure is invoked by Tk_EventuallyFree or Tk_Release
 *	to clean up the internal structure of a Hypertext at a safe time
 *	(when no-one is using it anymore).
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Everything associated with the widget is freed up.
 *
 * ----------------------------------------------------------------------
 */
static void
DestroyText (clientData)
    ClientData clientData;   /* Info about hypertext widget. */
{
    register Hypertext *textPtr = (Hypertext *) clientData;

    /* Free allocated memory for the following: */
    if (textPtr->gc != None) /* Graphics context */
	Tk_FreeGC (textPtr->gc);
    if (textPtr->border)     /* 3D Border */
	Tk_Free3DBorder (textPtr->border);
    if (textPtr->normalFg)   /* Foreground color */
	Tk_FreeColor (textPtr->normalFg);
    if (textPtr->geometry)   /* Geometry */
	ckfree (textPtr->geometry);
    if (textPtr->yScrollCmd) /* Y scroll command */
	ckfree (textPtr->yScrollCmd);
    if (textPtr->xScrollCmd) /* X scroll command */
	ckfree (textPtr->xScrollCmd);
    if (textPtr->fontPtr)    /* Font */
	Tk_FreeFontStruct (textPtr->fontPtr);
    if (textPtr->fileName)   /* Filename */
	ckfree (textPtr->fileName);
    if (textPtr->text != NULL)	/* Text string */
	ckfree (textPtr->text);
    if (textPtr->cursor != None)	/* Cursor */
	Tk_FreeCursor (textPtr->cursor);
    FreeLines (textPtr);
    ckfree ((char *)textPtr);/* */
}

/*
 * ----------------------------------------------------------------------
 *
 * ConfigureText --
 *
 * 	This procedure is called to process an argv/argc list, plus
 *	the Tk option database, in order to configure (or reconfigure)
 *	a hypertext widget.
 *
 * 	The layout of the text must be calculated (by ComputeLayout)
 *	whenever particular options change; -font, -filename, -linespacing
 *	and -text options. If the user has changes one of these options,
 *	it must be detected so that the layout can be recomputed. Since the
 *	coordinates of the layout are virtual, there is no need to adjust
 *	them if physical window attributes (window size, etc.)
 *	change.
 *
 * Results:
 *	The return value is a standard Tcl result.  If TCL_ERROR is
 * 	returned, then interp->result contains an error message.
 *
 * Side effects:
 *	Configuration information, such as text string, colors, font,
 * 	etc. get set for textPtr;  old resources get freed, if there were any.
 * 	The hypertext is redisplayed.
 *
 * ----------------------------------------------------------------------
 */

static int
ConfigureText (interp, textPtr, argc, argv, flags)
    Tcl_Interp *interp;	     /* Used for error reporting. */
    Hypertext *textPtr;	     /* Information about widget; may or may not
			      * already have values for some fields. */
    int argc;		     /* Number of valid entries in argv. */
    char **argv;	     /* Arguments. */
    int flags;		     /* Flags to pass to Tk_ConfigureWidget. */
{
    XGCValues gcValues;
    unsigned long valueMask;
    GC newGC;
    Tk_Window tkwin = textPtr->tkwin;

    if (Tk_ConfigureWidget (interp, tkwin, configSpecs, argc, argv,
			    (char *)textPtr, flags) != TCL_OK) {
	return TCL_ERROR;
    }
    Tk_SetBackgroundFromBorder (tkwin, textPtr->border);
    if (OptionChanged (Tk_Offset (Hypertext, fontPtr), configSpecs) ||
	OptionChanged (Tk_Offset (Hypertext, lineSpacing), configSpecs)) {
	textPtr->flags |= LAYOUT_NEEDED;
    }
    gcValues.font = textPtr->fontPtr->fid;
    gcValues.foreground = textPtr->normalFg->pixel;

    valueMask = GCForeground | GCFont;
    newGC = Tk_GetGC (tkwin, valueMask, &gcValues);
    if (textPtr->gc != None)
	Tk_FreeGC (textPtr->gc);
    textPtr->gc = newGC;

    /* Kill the -file option, if the -text option exists */
    if (textPtr->text != NULL) {
	if (textPtr->fileName != NULL)
	    ckfree (textPtr->fileName);
	textPtr->fileName = NULL;
    } else if (OptionChanged (Tk_Offset (Hypertext, fileName), configSpecs)) {
	if (ReadFile (interp, textPtr) != TCL_OK)
	    return (TCL_ERROR);
    }
    /* If new text is available, read it into the widget */
    if (textPtr->text != NULL) {
	if (ParseText (interp, textPtr) != TCL_OK)
	    return (TCL_ERROR);
	textPtr->flags |= LAYOUT_NEEDED;	/* Mark for layout update */
    }
    if (textPtr->geometry != NULL) {
	int height, width;

	if (sscanf (textPtr->geometry, "%dx%d", &width, &height) != 2) {
	    Tcl_AppendResult (interp, "bad geometry \"", textPtr->geometry,
			      "\": expected widthxheight", (char *)NULL);
	    return (TCL_ERROR);
	}
	Tk_GeometryRequest (tkwin, width, height);
    }
    /* Lastly, arrange for the hypertext to be redisplayed. */
    EventuallyRedraw (textPtr);
    return TCL_OK;
}

/*
 * --------------------------------------------------------------
 *
 * TextEventProc --
 *
 * 	This procedure is invoked by the Tk dispatcher for various
 * 	events on hypertext widgets.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	When the window gets deleted, internal structures get
 *	cleaned up.  When it gets exposed, it is redisplayed.
 *
 * --------------------------------------------------------------
 */

static void
TextEventProc (clientData, eventPtr)
    ClientData clientData;   /* Information about window. */
    XEvent *eventPtr;	     /* Information about event. */
{
    Hypertext *textPtr = (Hypertext *) clientData;

    switch (eventPtr->type) {

    case ConfigureNotify:
	textPtr->flags |= VIEWPORT_RESIZED;
	EventuallyRedraw (textPtr);
	break;

    case Expose:
	if (eventPtr->xexpose.send_event) {
	    textPtr->flags ^= IGNORE_EXPOSURES;
	    return;
	}
	if ((eventPtr->xexpose.count == 0) &&
	    !(textPtr->flags & IGNORE_EXPOSURES)) {
	    EventuallyRedraw (textPtr);
	}
	break;

    case DestroyNotify:
	Tcl_DeleteCommand (textPtr->interp, Tk_PathName (textPtr->tkwin));
	textPtr->tkwin = NULL;
	if (textPtr->flags & REDRAW_PENDING)
	    Tk_CancelIdleCall (DisplayText, (ClientData) textPtr);
	Tk_EventuallyFree ((ClientData) textPtr, DestroyText);
	break;

    }
}

/*
 *----------------------------------------------------------------------
 *
 * EventuallyRedraw --
 *
 *	Ensure that an entry is eventually redrawn on the display.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Information gets redisplayed.  Right now we don't do selective
 *	redisplays:  the whole window will be redrawn.  This doesn't
 *	seem to hurt performance noticeably, but if it does then this
 *	could be changed.
 *
 *----------------------------------------------------------------------
 */

static void
EventuallyRedraw (textPtr)
    register Hypertext *textPtr;	/* Information about widget. */
{
    if ((textPtr->tkwin != NULL) && (Tk_IsMapped (textPtr->tkwin)) &&
	!(textPtr->flags & REDRAW_PENDING)) {
	textPtr->flags |= REDRAW_PENDING;
	Tk_DoWhenIdle (DisplayText, (ClientData) textPtr);
    }
}

/*
 *----------------------------------------------------------------------
 *
 * TextScanTo --
 *
 *	Given a XY coordinates (presumably of the curent mouse location)
 *	drag the view in the window to implement the scan operation.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	The view in the window may change and the window redrawn.
 *
 *----------------------------------------------------------------------
 */

static void
TextScanTo (textPtr, x, y)
    register Hypertext *textPtr;	/* Information about widget. */
    int x, y;		     /* Coordinate to use for scan operation. */
{
    int newX, newY;

    /* Amplify X distance from point to mark by step of horizontal units */
    newX = textPtr->scanPtX - (x - textPtr->scanMarkX) * textPtr->xScrollUnits;
    /* Amplify Y distance from point to mark by 10x vertical units */
    newY = (textPtr->scanPtY - (10 * (y - textPtr->scanMarkY)) *
	    textPtr->yScrollUnits);
    if (newX < 0) {
	newX = textPtr->scanPtX = 0;
	textPtr->scanMarkX = x;
    } else if (newX >= textPtr->width) {
	newX = textPtr->scanPtX = textPtr->width - textPtr->xScrollUnits;
	textPtr->scanMarkX = x;
    }
    if (newY < 0) {
	newY = textPtr->scanPtY = 0;
	textPtr->scanMarkY = y;
    } else if (newY >= textPtr->height) {
	newY = textPtr->scanPtY = textPtr->height - textPtr->yScrollUnits;
	textPtr->scanMarkY = y;
    }
    if (newY != textPtr->newY || newX != textPtr->newX) {
	textPtr->newX = newX, textPtr->newY = newY;
	textPtr->flags |= VIEWPORT_MOVED;
	EventuallyRedraw (textPtr);
    }
}

/*
 * ----------------------------------------------------------------------
 *
 * GetLine --
 *
 * 	This procedure creates and initializes a new line of text.
 *
 * Results:
 *	The return value is a pointer to a structure describing the new
 * 	line of text.  If an error occurred, then the return value is NULL
 *	and an error message is left in interp->result.
 *
 * Side effects:
 *	Memory is allocated.
 *
 * ----------------------------------------------------------------------
 */
static Line *
GetLine (textPtr)
    Hypertext *textPtr;
{
    Line *linePtr;

    if (textPtr->numLines >= textPtr->arraySize) {
	Line **newPtr;

	/* reallocate the array of lines */
	if (textPtr->arraySize == 0) {
	    textPtr->arraySize = LINES_ALLOC_CHUNK;
	} else {
	    /* Double the size of the array */
	    textPtr->arraySize += textPtr->arraySize;
	}
	newPtr = (Line **) reallocate ((char *)textPtr->lineArr,
				       textPtr->arraySize * sizeof (Line *),
				       textPtr->numLines * sizeof (Line *));
	textPtr->lineArr = newPtr;
    }
    /* Create new line entry and add to table */
    linePtr = (Line *) calloc (1, sizeof (Line));
    if (linePtr == NULL) {
	Tcl_AppendResult (textPtr->interp, "calloc: ", sys_errlist[errno],
			  ": Can't allocate new line ", NULL);
	return (NULL);
    }
    textPtr->lineArr[textPtr->numLines++] = linePtr;
    return (linePtr);
}

/*
 * ----------------------------------------------------------------------
 *
 * DestroyLine --
 *
 * 	This procedure is invoked by FreeLines to clean up the
 * 	internal structure of a line.
 *
 * Results: None.
 *
 * Side effects:
 *	Everything associated with the line (text and children) is
 *	freed up.
 *
 * ----------------------------------------------------------------------
 */

static void
DestroyLine (linePtr)
    register Line *linePtr;
{
    register Child *childPtr = linePtr->children;
    register Child *oldPtr;

    /* Free the list of child structures */
    while (childPtr != NULL) {
	oldPtr = childPtr;
	childPtr = childPtr->nextPtr;
	DestroyChild (oldPtr);
    }
    /* Deallocate the text array */
    if (linePtr->text != NULL)
	ckfree (linePtr->text);
    ckfree ((char *)linePtr);
}

/*
 * ----------------------------------------------------------------------
 *
 * AppendChild --
 *
 * 	This procedure creates and initializes a new hyper text child.
 *
 * Results:
 *	The return value is a standard Tcl result.
 *
 * Side effects:
 *	Memory is allocated.  Child gets configured.
 *
 * ----------------------------------------------------------------------
 */

static int
AppendChild (textPtr, childName, argc, argv)
    register Hypertext *textPtr;
    char *childName;
    int argc;		     /* Number of arguments. */
    char **argv;	     /* Argument strings. */
{
    Line *linePtr;
    Child *childPtr;

    childPtr = CreateChild (textPtr->interp, textPtr, childName);
    if (childPtr == NULL)
	return TCL_ERROR;
    if (ConfigureChild (textPtr, childPtr, argc, argv, 0) != TCL_OK)
	return (TCL_ERROR);

    /* Append child to list of subwindows of the last line */
    /* Check that there is a line to append the window */
    if (textPtr->numLines == 0)
	GetLine (textPtr);
    linePtr = textPtr->lineArr[textPtr->numLines - 1];
    if (linePtr->children == NULL) {
	linePtr->lastChild = linePtr->children = childPtr;
    } else {
	linePtr->lastChild->nextPtr = childPtr;
	linePtr->lastChild = childPtr;
    }
    linePtr->width += childPtr->width;
    childPtr->precedingTextEnd = linePtr->textLength;
    textPtr->flags |= LAYOUT_NEEDED;

    return (TCL_OK);
}

/*
 * ----------------------------------------------------------------------
 *
 * CreateChild --
 *
 * 	This procedure creates and initializes a new child subwindow
 *	in the hyper text widget.
 *
 * Results:
 *	The return value is a pointer to a structure describing the
 *	new child.  If an error occurred, then the return value is
 *      NULL and an error message is left in interp->result.
 *
 * Side effects:
 *	Memory is allocated. Child window is mapped. Callbacks are set
 *	up for subwindow resizes and geometry requests.
 *
 * ----------------------------------------------------------------------
 */

static Child *
CreateChild (interp, textPtr, childName)
    Tcl_Interp *interp;	     /* Used for error reporting. */
    Hypertext *textPtr;	     /* Hypertext widget */
    char *childName;	     /* Name of child window */
{
    register Child *childPtr;
    Tk_Window tkwin;
    char buf[BUFSIZ];

    if (*childName != '.') { /* Relative path, make absolute */
	sprintf (buf, "%s.%s", Tk_PathName (textPtr->tkwin), childName);
	childName = buf;
    }
    /* Get the Tk window and parent Tk window associated with the child */
    tkwin = Tk_NameToWindow (interp, childName, textPtr->tkwin);
    if (tkwin == NULL) {
	Tcl_AppendResult (interp, "Can't find a window \"", childName, NULL);
	return (NULL);
    }
    if (FindChild (interp, textPtr, childName) != NULL) {
	Tcl_AppendResult (interp, "\"", childName,
			  "\" is already appended to ",
			  Tk_PathName (textPtr->tkwin));
	return (NULL);
    }
    if (textPtr->tkwin != Tk_Parent (tkwin)) {
	Tcl_AppendResult (interp, "\"", childName, "\" is not a child of `%s'",
			  Tk_PathName (textPtr->tkwin));
	return (NULL);
    }
    childPtr = (Child *) calloc (1, sizeof (Child));
    if (childPtr == NULL) {
	Tcl_AppendResult (interp, "calloc: ", sys_errlist[errno],
			  ": Can't create child structure", NULL);
	return (NULL);
    }
    childPtr->tkwin = tkwin;
    childPtr->parent = textPtr;

    /* Map the window so that we can query its width and height */
    Tk_MapWindow (tkwin);
    childPtr->width = Tk_ReqWidth (tkwin);
    childPtr->height = Tk_ReqHeight (tkwin);

    /* Set up callbacks for geometry requests and window structure changes */
    Tk_ManageGeometry (tkwin, ChildGeometryProc, (ClientData) childPtr);
    Tk_CreateEventHandler (tkwin, StructureNotifyMask, ChildStructureProc,
			   (ClientData) childPtr);
    return (childPtr);
}

/*
 * ----------------------------------------------------------------------
 *
 * DestroyChild --
 *
 * 	This procedure is invoked by DestroyLine to clean up the
 * 	internal structure of a child.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Everything associated with the widget is freed up.
 *
 * ----------------------------------------------------------------------
 */

static void
DestroyChild (childPtr)
    register Child *childPtr;
{
    /* Destroy the child window if it still exists */
    if (childPtr->tkwin != NULL)
	Tk_DestroyWindow (childPtr->tkwin);
    free ((char *)childPtr);
}

/*
 * ----------------------------------------------------------------------
 *
 * ConfigureChild --
 *
 * 	This procedure is called to process an argv/argc list, plus
 *	the Tk option database, in order to configure (or reconfigure)
 *	a hypertext child.
 *
 * Results:
 *	The return value is a standard Tcl result.  If TCL_ERROR is
 * 	returned, then interp->result contains an error message.
 *
 * Side effects:
 *	Configuration information, such as text string, colors, font,
 * 	etc. get set for the child; old resources get freed, if there
 *	were any. The child marked for redisplay.
 *
 * ----------------------------------------------------------------------
 */

static int
ConfigureChild (textPtr, childPtr, argc, argv, flags)
    Hypertext *textPtr;	     /* Parent hypertext widget. */
    Child *childPtr;	     /* Information about child; may or may not
			      * already have values for some fields. */
    int argc;		     /* Number of valid entries in argv. */
    char **argv;	     /* Arguments. */
    int flags;
{
    int oldAnchor;
    int oldPadX, oldPadY;

    oldAnchor = childPtr->anchor;
    oldPadX = childPtr->padX;
    oldPadY = childPtr->padY;

    if (Tk_ConfigureWidget (textPtr->interp, textPtr->tkwin, childConfigSpecs,
			    argc, argv, (char *)childPtr, flags) != TCL_OK)
	return (TCL_ERROR);
    /* If non-zero use the user-defined space constraints. */
    childPtr->width = (childPtr->widthWanted > 0)
	? childPtr->widthWanted : Tk_ReqWidth (childPtr->tkwin);
    childPtr->height = (childPtr->heightWanted > 0)
	? childPtr->heightWanted : Tk_ReqHeight (childPtr->tkwin);

    /*
     * If the requested new width or height of the child is different from
     * the current, we need to recompute the layout.
     */
    if (childPtr->width != Tk_Width (childPtr->tkwin) ||
	childPtr->height != Tk_Height (childPtr->tkwin) ||
	childPtr->padX != oldPadX || childPtr->padY != oldPadY ||
	childPtr->anchor != oldAnchor)
	textPtr->flags |= LAYOUT_NEEDED;
    return (TCL_OK);
}

/*
 * --------------------------------------------------------------
 *
 * TextEventProc --
 *
 * 	This procedure is invoked by the Tk dispatcher for various
 * 	events on hypertext widgets.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	When the window gets deleted, internal structures get
 *	cleaned up.  When it gets exposed, it is redisplayed.
 *
 * --------------------------------------------------------------
 */

static void
ChildStructureProc (clientData, eventPtr)
    ClientData clientData;   /* Information about window. */
    XEvent *eventPtr;	     /* Information about event. */
{
    register Child *childPtr = (Child *) clientData;

    if (childPtr != NULL && childPtr->tkwin != NULL) {
	Hypertext *textPtr;

	textPtr = childPtr->parent;

	switch (eventPtr->type) {
	case DestroyNotify:

	    /*
	     * Mark the child as deleted by dereferencing the Tk window
	     * pointer. Zero out the height and width to collapse the area
	     * used by the child.  Redraw the screen only if the child is
	     * currently visible and mapped.
	     */
	    childPtr->tkwin = NULL;
	    childPtr->width = childPtr->height = 0;
	    childPtr->parent->flags |= LAYOUT_NEEDED;
	    if ((childPtr->flags & (VISIBLE | MAPPED)) == (VISIBLE | MAPPED)) {
		EventuallyRedraw (textPtr);
	    }
	    break;

	case ConfigureNotify:

	    /*
	     * Children can't request new XY positions by themselves, so
	     * worry only about resizing.
	     */
	    if (childPtr->width != Tk_Width (childPtr->tkwin) ||
		childPtr->height != Tk_Height (childPtr->tkwin)) {
		EventuallyRedraw (textPtr);
		textPtr->flags |= LAYOUT_NEEDED;
	    }
	    break;
	}
    }
}

/*
 *----------------------------------------------------------------------
 *
 * ComputeLayout --
 *
 *	This procedure computes the total width and height needed
 *      to contain the text and children from all the lines of text.
 *      It merely sums the heights and finds the maximum width of
 *	all the lines.  The width and height are needed for scrolling.
 *
 * Results:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static void
ComputeLayout (textPtr, layoutWidth, layoutHeight)
    Hypertext *textPtr;
    int *layoutWidth;
    int *layoutHeight;

{
    register int cnt;
    register Line *linePtr;
    register int height, width;

    width = height = 0;
    for (cnt = 0; cnt < textPtr->numLines; cnt++) {
	linePtr = textPtr->lineArr[cnt];
	linePtr->offset = height;
	GetLineExtents (textPtr, linePtr);
	height += linePtr->height;
	if (linePtr->width > width)
	    width = linePtr->width;
    }
    /* Save new height and width */
    *layoutHeight = height;
    *layoutWidth = width;

    textPtr->flags &= ~LAYOUT_NEEDED;
    /* Indicate if new layout changed size of world */
    if (height != textPtr->height || width != textPtr->width)
	textPtr->flags |= LAYOUT_CHANGED;
}

/*
 *----------------------------------------------------------------------
 *
 * GetLineExtents --
 *
 *	This procedure computes the total width and height needed
 *      to contain the text and children for a particular line.
 *      It also calculates the baseline of the text on the line with
 *	respect to the other children on the line.
 *
 * Results:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static void
GetLineExtents (textPtr, linePtr)
    Hypertext *textPtr;
    Line *linePtr;
{
    register Child *childPtr;
    register int width;
    register int baseline;
    int textLength;
    int maxAscent, maxDescent, maxHeight;
    int ascent, descent, height;
    register int curPos = 0;
    int median;		     /* Difference of font ascent/descent values */

    /*
     * Pass 1: Determine the maximum ascent (baseline) and descent needed for
     * the line.  We'll need this for figuring the top/bottom/center anchors.
     */

    /* Initialize line defaults */
    maxAscent = textPtr->fontPtr->ascent;
    maxDescent = textPtr->fontPtr->descent;
    baseline = textPtr->fontPtr->ascent;
    median = textPtr->fontPtr->ascent - textPtr->fontPtr->descent;

    for (childPtr = linePtr->children;
	 childPtr != NULL; childPtr = childPtr->nextPtr) {

	height = childPtr->height + 2 * childPtr->padY;
	switch (childPtr->anchor) {
	case TK_ANCHOR_N:
	case TK_ANCHOR_NE:
	case TK_ANCHOR_NW:
	    ascent = textPtr->fontPtr->ascent + childPtr->padY;
	    descent = height - textPtr->fontPtr->ascent;
	    break;
	case TK_ANCHOR_E:
	case TK_ANCHOR_W:
	case TK_ANCHOR_CENTER:
	    ascent = (height + median) / 2;
	    descent = (height - median) / 2;
	    break;
	case TK_ANCHOR_S:
	case TK_ANCHOR_SE:
	case TK_ANCHOR_SW:
	    ascent = height - textPtr->fontPtr->descent;
	    descent = textPtr->fontPtr->descent;
	    break;
	}
	if (descent > maxDescent)
	    maxDescent = descent;
	if (ascent > maxAscent)
	    maxAscent = ascent;
    }

    baseline = maxAscent + linePtr->offset;
    maxHeight = maxAscent + maxDescent + textPtr->lineSpacing;
    width = 0;		     /* Always starts from x=0 */

    /*
     * Pass 2:  Find the placements of the text and children along each line.
     */
    for (childPtr = linePtr->children; childPtr != NULL;
	 childPtr = childPtr->nextPtr) {

	/* Get the width of the text leading to the child */
	textLength = (childPtr->precedingTextEnd - curPos);
	if (textLength > 0) {
	    int newWidth = 0;

	    /* Text extents of normal text */
	    TkMeasureChars (textPtr->fontPtr, linePtr->text + curPos,
			    textLength, width, 10000,
			    TK_PARTIAL_OK | TK_AT_LEAST_ONE, &newWidth);
	    childPtr->precedingTextWidth = newWidth - width;
	    width = newWidth;
	}
	width += childPtr->padX;

	/* Save the world XY coordinates of the child */
	childPtr->x = width;
	switch (childPtr->anchor) {
	case TK_ANCHOR_N:
	case TK_ANCHOR_NE:
	case TK_ANCHOR_NW:
	    childPtr->y = baseline - textPtr->fontPtr->ascent;
	    break;
	case TK_ANCHOR_E:
	case TK_ANCHOR_W:
	case TK_ANCHOR_CENTER:
	    childPtr->y = baseline - (childPtr->height + median) / 2;
	    break;
	case TK_ANCHOR_S:
	case TK_ANCHOR_SE:
	case TK_ANCHOR_SW:
	    childPtr->y = (baseline -
			   (childPtr->height - textPtr->fontPtr->descent));
	    break;
	}
	width += childPtr->width + childPtr->padX;
	curPos = childPtr->precedingTextEnd;
    }

    /*
     * This may be piece of line after last child and  will also pick up the
     * entire line if no children occured on it
     */
    textLength = (linePtr->textLength - curPos);
    if (textLength > 0) {
	int newWidth = 0;

	/* Text extents of normal text */
	TkMeasureChars (textPtr->fontPtr, linePtr->text + curPos, textLength,
			width, 10000, TK_PARTIAL_OK | TK_AT_LEAST_ONE,
			&newWidth);
	width = newWidth;
    }
    /* Update line parameters */
    linePtr->width = width;
    linePtr->height = maxHeight;
    linePtr->baseline = maxAscent;
}

/*
 * ----------------------------------------------------------------------
 *
 * DisplayText --
 *
 * 	This procedure is invoked to display a hypertext widget.
 *	Many of the operations which might ordinarily be performed
 *	elsewhere (e.g. in a configuration routine) are done here
 *	because of the somewhat unusual interactions occuring between
 *	the parent and child windows.
 *
 *      Recompute the layout of the text if necessary. This is
 *	necessary if the world coordinate system has changed.
 *	Specifically, the following may have occurred:
 *
 *	  -  a text attribute has changed (font, linespacing, etc.).
 *	  -  child option changed (anchor, width, height).
 *        -  actual child window was resized.
 *	  -  new text string or file.
 *
 *      This is defered to the display routine since potentially
 *      many of these may occur (especially child window changes).
 *
 *	Set the vertical and horizontal scrollbars (if they are
 *	designated) by issuing a Tcl command.  Done here since
 *	the text window width and height are needed.
 *
 *	If the viewport position or contents have changed in the
 *	vertical direction,  the now out-of-view child windows
 *	must be moved off the viewport.  Since child windows will
 *	obscure the text window, it is imperative that the children
 *	are moved off before we try to redraw text in the same area.
 *      This is necessary only for vertical movements.  Horizontal
 *	child window movements are handled automatically in the
 *	page drawing routine.
 *
 *      Get the new first and last line numbers for the viewport.
 *      These line numbers may have changed because either a)
 *      the viewport changed size or position, or b) the text
 *	(child window sizes or text attributes) have changed.
 *
 *	If the viewport has changed vertically (i.e. the first or
 *      last line numbers have changed), move the now out-of-view
 *	child windows off the viewport.
 *
 *      Potentially many expose events may be generated when the
 *	the individual child windows are moved and/or resized.
 *	These events need to be ignored.  Since (I think) expose
 * 	events are guarenteed to happen in order, we can bracket
 *	them by sending phony events (via XSendEvent). The phony
 *      event turn on and off flags which indicate if the events
 *	should be ignored.
 *
 *	Finally, the page drawing routine is called.
 *
 * Results:
 *	None.
 *
 * Side effects:
 * 	Commands are output to X to display the hypertext in its
 *	current mode.
 *
 * ----------------------------------------------------------------------
 */

static void
DisplayText (clientData)
    ClientData clientData;   /* Information about widget. */
{
    Hypertext *textPtr = (Hypertext *) clientData;
    register Tk_Window tkwin;
    int oldFirst;	     /* First line of old viewport */
    int oldLast;	     /* Last line of old viewport */
    int deltaY;		     /* Change in viewport in Y direction */

    textPtr->flags &= ~REDRAW_PENDING;

    tkwin = textPtr->tkwin;
    if ((tkwin == NULL) || !Tk_IsMapped (tkwin) || (textPtr->numLines <= 0)) {
	return;
    }

    /*
     * Recalculate the layout. Do this when child positions or sizes have
     * changed, or the text attributes (font, linespacing, etc) have changed.
     * And when a initially using new file or text string, the child
     * positions can't be trusted.
     */
    if (textPtr->flags & LAYOUT_NEEDED) {
	int width, height;

	ComputeLayout (textPtr, &width, &height);
	textPtr->width = width, textPtr->height = height;
    }
    /* Is there a pending gotoline request? */
    if (textPtr->flags & GOTO_PENDING) {
	textPtr->newY = textPtr->lineArr[textPtr->lineRequested]->offset;
	textPtr->flags &= ~GOTO_PENDING;
    }
    deltaY = textPtr->newY - textPtr->y;
    oldFirst = textPtr->first, oldLast = textPtr->last;

    /*
     * If the viewport has changed size or position, or the text and/or child
     * subwindows have changed, adjust the scrollbars to new positions.
     */
    if (textPtr->flags & (VIEWPORT_MOVED | VIEWPORT_RESIZED | LAYOUT_CHANGED)) {
	/* Reset viewport origin and world extents */
	textPtr->x = textPtr->newX, textPtr->y = textPtr->newY;
	/* Horizontal scrollbar */
	if (!NULLSTR (textPtr->xScrollCmd))
	    TextUpdateScrollBar (textPtr->interp, textPtr->xScrollCmd,
			       textPtr->width, Tk_Width (tkwin), textPtr->x,
				 textPtr->xScrollUnits);
	/* Vertical scrollbar */
	if (!NULLSTR (textPtr->yScrollCmd))
	    TextUpdateScrollBar (textPtr->interp, textPtr->yScrollCmd,
				 textPtr->height, Tk_Height (tkwin),
				 textPtr->y, textPtr->yScrollUnits);
	/*
	 * Given a new viewport or text height, find the first and last line
	 * numbers of the new viewport.
	 */
	GetVisibleLines (textPtr);
    }

    /*
     * (This is a kludge.) Send an expose event before and after drawing the
     * page of text.  Since moving and resizing of the subwindows will cause
     * redundant expose events in the parent window, the phony events will
     * bracket them indicating no action should be taken.
     */
    SendExposeEvent (tkwin);

    /*
     * If either the position of the viewport has changed or the size of
     * width or height of the entire text have changed, move the children
     * from the previous viewport out of the current viewport. Worry only
     * about the vertical child window movements.  The horizontal moves are
     * handled by the when drawing the page of text.
     */
    if (textPtr->first != oldFirst || textPtr->last != oldLast) {
	register int cnt;
	int first, last;
	register Child *childPtr;

	/* Figure out which lines are now *out* of the viewport */
	if (textPtr->first > oldFirst && textPtr->first <= oldLast)
	    first = oldFirst, last = textPtr->first;
	else if (textPtr->last < oldLast && textPtr->last >= oldFirst)
	    first = textPtr->last, last = oldLast;
	else
	    first = oldFirst, last = oldLast;
	for (cnt = first; cnt <= last; cnt++) {
	    for (childPtr = textPtr->lineArr[cnt]->children;
		 childPtr != NULL; childPtr = childPtr->nextPtr) {
		MoveChild (childPtr, textPtr->x, textPtr->y);
		childPtr->flags &= ~VISIBLE;
	    }
	}
    }
    DrawPage (textPtr, deltaY);
    SendExposeEvent (tkwin);

    /* Reset flags */
    textPtr->flags &= ~(VIEWPORT_RESIZED | VIEWPORT_MOVED | LAYOUT_CHANGED);
}

/*
 * ----------------------------------------------------------------------
 *
 * DrawPage --
 *
 * 	This procedure displays the lines of text and moves the child
 *      windows to their new positions.  It draws lines with regard to
 *	the direction of the scrolling.  The idea here is to make the
 *	text and buttons appear to move together. Otherwise you will
 *	get a "jiggling" effect where the window appear to bump into
 *	the next line before that line is moved.  At worst case, where
 *	every line has a bottom you can get an aquarium effect (lines
 *      appear to ripple up).
 *
 * 	The text area may start between line boundaries (to accommodate `
 *	both variable height lines and constant scrolling). Subtract the
 *	difference of the page offset and the line offset from the starting
 *	coordinates. For horizontal scrolling, simply substract the offset
 *	of the viewport. The window will clip the top of the first line,
 *	the bottom of the last line, whatever text extends to the left
 *	or right of the viewport on any line.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Commands are output to X to display the line in its current
 * 	mode.
 *
 * ----------------------------------------------------------------------
 */

static void
DrawPage (textPtr, deltaY)
    Hypertext *textPtr;
    int deltaY;		     /* Change from previous Y coordinate */
{
    Line *linePtr;
    Child *childPtr;
    Tk_Window tkwin = textPtr->tkwin;
    int textLength;
    int curPos;
    int baseline;
    Pixmap pixMap;
    int forceCopy = FALSE;
    register int cnt;
    int curLine, lastY;
    register int x, y;

    /* Setup: Clear the display */
    /* Create an off-screen pixmap for semi-smooth scrolling. */
    pixMap = XCreatePixmap (Tk_Display (tkwin), Tk_WindowId (tkwin),
			    Tk_Width (tkwin), Tk_Height (tkwin),
			    DefaultDepthOfScreen (Tk_Screen (tkwin)));
    Tk_Fill3DRectangle (Tk_Display (tkwin), pixMap, textPtr->border,
			0, 0, Tk_Width (tkwin), Tk_Height (tkwin),
			0, TK_RELIEF_FLAT);

    x = -(textPtr->x);
    y = -(textPtr->y);

    if (deltaY >= 0) {
	y += textPtr->lineArr[textPtr->first]->offset;
	curLine = textPtr->first;
	lastY = 0;
    } else {
	y += textPtr->lineArr[textPtr->last]->offset;
	curLine = textPtr->last;
	lastY = Tk_Height (tkwin);
    }
    forceCopy = FALSE;
    /* Draw each line */
    for (cnt = textPtr->first; cnt <= textPtr->last; cnt++) {

	/* Initialize character position in text buffer to start */
	curPos = 0;
	/* Initialize X position */
	x = -(textPtr->x);

	linePtr = textPtr->lineArr[curLine];
	baseline = y + linePtr->baseline;	/* Base line in screen
						 * coordinates */

	for (childPtr = linePtr->children; childPtr != NULL;
	     childPtr = childPtr->nextPtr) {

	    MoveChild (childPtr, textPtr->x, textPtr->y);
	    childPtr->flags |= VISIBLE;

	    textLength = (childPtr->precedingTextEnd - curPos);
	    if (textLength > 0) {
		TkDisplayChars (Tk_Display (tkwin), pixMap, textPtr->gc,
				textPtr->fontPtr, linePtr->text + curPos,
				textLength, x, baseline, 0);
		x += childPtr->precedingTextWidth;
	    }
	    curPos = childPtr->precedingTextEnd;
	    x += childPtr->width + 2 * childPtr->padX;
	    forceCopy++;
	}

	/*
	 * This may be the text trailing the last child or the entire line if
	 * no children occur on it.
	 */
	textLength = (linePtr->textLength - curPos);
	if (textLength > 0) {
	    TkDisplayChars (Tk_Display (tkwin), pixMap, textPtr->gc,
			    textPtr->fontPtr, linePtr->text + curPos,
			    textLength, x, baseline, 0);
	}
	/* Go to the top of the next line */
	if (deltaY >= 0) {
	    y += textPtr->lineArr[curLine++]->height;
	}
	if (forceCopy > 0 && !(textPtr->flags & VIEWPORT_RESIZED)) {
	    if (deltaY >= 0) {
		XCopyArea (Tk_Display (tkwin), pixMap, Tk_WindowId (tkwin),
			 textPtr->gc, 0, lastY, Tk_Width (tkwin), y - lastY,
			   0, lastY);
	    } else {
		XCopyArea (Tk_Display (tkwin), pixMap, Tk_WindowId (tkwin),
			   textPtr->gc, 0, y, Tk_Width (tkwin), lastY - y,
			   0, y);
	    }
	    forceCopy = 0;   /* Reset drawing flag */
	    lastY = y;	     /* Record last Y position */
	}
	if ((deltaY < 0) && (curLine > 0)) {
	    y -= textPtr->lineArr[--curLine]->height;
	}
    }
    /* Prologue */
    if (textPtr->flags & VIEWPORT_RESIZED) {
	XCopyArea (Tk_Display (tkwin), pixMap, Tk_WindowId (tkwin),
	      textPtr->gc, 0, 0, Tk_Width (tkwin), Tk_Height (tkwin), 0, 0);
    } else if (lastY != y) {
	if (deltaY >= 0) {
	    XCopyArea (Tk_Display (tkwin), pixMap, Tk_WindowId (tkwin),
		       textPtr->gc, 0, lastY, Tk_Width (tkwin),
		       Tk_Height (tkwin) - lastY, 0, lastY);
	} else {
	    XCopyArea (Tk_Display (tkwin), pixMap, Tk_WindowId (tkwin),
		       textPtr->gc, 0, 0, Tk_Width (tkwin), lastY, 0, 0);
	}
    }
    XFreePixmap (Tk_Display (tkwin), pixMap);
}

/*
 * ----------------------------------------------------------------------
 *
 * MoveChild --
 *
 * 	Move a child subwindow to a new location in the hypertext
 *	parent window.  If the window has no geometry (i.e. width,
 *	or height is 0), simply unmap to window.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Each subwindow is moved to its new location, generating
 *      Expose events in the parent for each child window moved.
 *
 * ----------------------------------------------------------------------
 */

static void
MoveChild (childPtr, newX, newY)
    register Child *childPtr;
    int newX;		     /* X-coordinate from left of text */
    int newY;		     /* Y-coordinate from top of text */
{
    register Tk_Window tkwin = childPtr->tkwin;

    if (tkwin == NULL)
	return;

    if (childPtr->width > 0 && childPtr->height > 0) {
	register int x, y;

	x = childPtr->x - newX, y = childPtr->y - newY;

	if (x != Tk_X (tkwin) || y != Tk_Y (tkwin) ||
	    childPtr->width != Tk_Width (tkwin) ||
	    childPtr->height != Tk_Height (tkwin)) {
	    Tk_MoveResizeWindow (tkwin, x, y,
				 (unsigned int)childPtr->width,
				 (unsigned int)childPtr->height);
	    if (!Tk_IsMapped (tkwin)) {
		Tk_MapWindow (tkwin);
		childPtr->flags |= MAPPED;
	    }
	}
    } else {
	if (Tk_IsMapped (tkwin)) {
	    Tk_UnmapWindow (tkwin);
	    childPtr->flags &= ~MAPPED;
	}
    }
}

/*
 * ----------------------------------------------------------------------
 *
 * GetVisibleLines --
 *
 * 	Calculates which lines are visible using the height
 *      of the viewport and y offset from the top of the text.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Only those line between first and last inclusive are
 * 	redrawn.
 *
 * ----------------------------------------------------------------------
 */

static int
GetVisibleLines (textPtr)
    Hypertext *textPtr;
{
    int first, last;
    int top, bottom;

    top = textPtr->newY;

    /* First line */
    first = LineSearch (textPtr, top, 0, textPtr->numLines - 1);
    if (first < 0) {
	/* This can't be. The newY offset must be corrupted. */
	fprintf (stderr, "First position not found `%d'", top);
	return (TCL_ERROR);
    }
    textPtr->first = first;

    /*
     * If there is less text than window space, the bottom line is the last
     * line of text.  Otherwise search for the line located at the bottom of
     * the window.
     */
    bottom = top + Tk_Height (textPtr->tkwin) - 1;
    if (bottom > textPtr->height) {
	last = textPtr->numLines - 1;
    } else {
	last = LineSearch (textPtr, bottom, first, textPtr->numLines - 1);
    }
    if (last < 0) {
	/* This can't be. The newY offset must be corrupted. */
	fprintf (stderr, "Last position not found `%d'", bottom);
	return (TCL_ERROR);
    }
    textPtr->last = last;
    return (TCL_OK);
}

/*
 * ----------------------------------------------------------------------
 *
 * LineSearch --
 *
 * 	Performs a binary search for the line located at some world
 *	Y coordinate. The search is limited to those lines between
 *	*low* and *high* inclusive.
 *
 * Results:
 *	Returns the line number at the given Y coordinate. If *position*
 *	does not correspond to any of the lines in the given the set,
 *	-1 is returned.
 *
 * ----------------------------------------------------------------------
 */
static int
LineSearch (textPtr, position, low, high)
    Hypertext *textPtr;
    int position;
    register int low;
    register int high;
{
    register int mid;
    register Line *linePtr;

    while (low <= high) {
	mid = (low + high) >> 1;
	linePtr = textPtr->lineArr[mid];

	if (position < linePtr->offset)
	    high = mid - 1;
	else if (position >= (linePtr->offset + linePtr->height))
	    low = mid + 1;
	else
	    return (mid);
    }
    return (-1);
}

/*
 * ----------------------------------------------------------------------
 *
 * TextUpdateScrollBar --
 *
 * 	Invoke a Tcl command to the scrollbar, defining the new position
 *	and length of the scroll. See the Tk documentation for further
 *	information on the scrollbar.  It is assumed the scrollbar command
 *	prefix is valid.
 *
 * Results:
 *	None.
 *
 * Side Effects:
 *	Scrollbar is commanded to change position and/or size.
 * ----------------------------------------------------------------------
 */
static void
TextUpdateScrollBar (interp, command, total, window, first, units)
    Tcl_Interp *interp;
    char *command;	     /* scrollbar command */
    int total;		     /* Total distance */
    int window;		     /* Window distance */
    int first;		     /* Position of viewport */
    int units;		     /* Unit distance */
{
    char cmdbuf[BUFSIZ];
    int totalUnits, windowUnits;
    int firstUnit, lastUnit;

    totalUnits = (total / units) + 1;
    windowUnits = window / units;
    firstUnit = first / units;
    lastUnit = (firstUnit + windowUnits);
    if (firstUnit >= totalUnits)
	firstUnit = totalUnits;
    if (lastUnit > totalUnits)
	lastUnit = totalUnits;
    sprintf (cmdbuf, "%s %d %d %d %d", command, totalUnits, windowUnits,
	     firstUnit, lastUnit);
    if (Tcl_Eval (interp, cmdbuf, 0, NULL) != TCL_OK) {
	TkBindError (interp);
    }
}

/*
 * ----------------------------------------------------------------------
 *
 * ParseText --
 *
 * 	Parse the characters in the text field of the hypertext structure
 *	into an array of lines.
 *
 * Results:
 *	Returns TCL_OK or error depending if the file was read correctly.
 *
 * ----------------------------------------------------------------------
 */
static int
ParseText (interp, textPtr)
    Tcl_Interp *interp;
    Hypertext *textPtr;
{
    register Line *linePtr;
    int c;

#define HUGE_LINE_SIZE 1024
    char buf[HUGE_LINE_SIZE];

#define HUGE_COMMAND_SIZE 10000
    char cmdBuf[HUGE_COMMAND_SIZE];
    int curPos;
    register int cnt;
    register int state;
    int result = TCL_ERROR;

    FreeLines (textPtr);     /* Delete any previous lines */
    CreateTraces (textPtr);  /* Create variable traces */

    linePtr = GetLine (textPtr);
    if (linePtr == NULL)
	goto error;	     /* Error allocating line */

    state = cnt = 0;
    curPos = 0;
    while ((c = textPtr->text[curPos++]) != '\0') {
	if (c == textPtr->specChar) {
	    state++;
	} else if (c == '\n') {
	    state = -1;
	} else if ((state == 0) && (c == '\\')) {
	    state = 3;
	} else {
	    state = 0;
	}

	switch (state) {
	case 2:	     /* Tcl Command block found */
	    cnt--;
	    if (GetTclCommand (textPtr, &curPos, cmdBuf) == NULL)
		goto error;
	    linePtr->textLength = cnt;
	    if (Tcl_Eval (interp, cmdBuf, 0, NULL) != TCL_OK)
		goto error;
	    state = 0;
	    break;

	case 4:	     /* Escaped block designator */
	    buf[cnt - 1] = c;
	    state = 0;
	    break;

	case -1:	     /* End of text line  */
	    buf[cnt] = '\0';
	    SetLineText (linePtr, buf, cnt);
	    linePtr = GetLine (textPtr);
	    if (linePtr == NULL)
		goto error;
	    cnt = state = 0;
	    break;

	default:	     /* Default action, add to text buffer */
	    buf[cnt++] = c;
	    break;
	}
	if (cnt == HUGE_LINE_SIZE) {
	    interp->result = "Text line is too long";
	    goto error;
	}
    }
    if (cnt > 0) {
	buf[cnt] = '\0';
	SetLineText (linePtr, buf, cnt);
    }
    result = TCL_OK;
  error:
    if (textPtr->text != NULL)
	free (textPtr->text);
    textPtr->text = NULL;
    DeleteTraces (textPtr);
    if (result == TCL_ERROR) {
	FreeLines (textPtr);
	return (TCL_ERROR);
    } else {
	AdjustLinesAllocated (textPtr);

	textPtr->first = 0;
	textPtr->last = textPtr->numLines - 1;
	textPtr->newX = textPtr->newY = 0;
	textPtr->width = textPtr->height = textPtr->x = textPtr->y = 0;
	return (TCL_OK);
    }
}


static int
ReadFile (interp, textPtr)
    Tcl_Interp *interp;
    Hypertext *textPtr;
{
    FILE *fp;
    register int arraySize = BUFSIZ;
    register int numBytes = 0;
    register char *charArr;
    int numBytesRead = 0;

    fp = fopen (textPtr->fileName, "r");
    if (fp == NULL) {
	Tcl_AppendResult (interp, "fopen: ", sys_errlist[errno],
			  ": Can't open \"", textPtr->fileName,
			  "\" for reading", NULL);
	return (TCL_ERROR);
    }
    charArr = malloc (arraySize);
    if (charArr == NULL) {
	Tcl_AppendResult (interp, "malloc: ", sys_errlist[errno],
			  ": Can't alloc space for \"", textPtr->fileName,
			  "\" charArr", NULL);
	return (TCL_ERROR);
    }
    for (;;) {
	/* Read in next block of text */
	numBytes = fread (&charArr[numBytesRead], sizeof (char), BUFSIZ, fp);

	if (numBytes < 0)
	    goto error;
	else if (numBytes == 0)
	    break;
	numBytesRead += numBytes;
	if (numBytesRead == arraySize) {
	    /* Reallocate with double the buffer size */
	    arraySize += arraySize;
	    charArr = reallocate (charArr, arraySize, numBytesRead);
	    if (charArr == NULL)
		goto error;
	}
    }
    charArr[numBytesRead] = '\0';
    textPtr->text = charArr;
    fclose (fp);
    return (TCL_OK);
  error:
    fclose (fp);
    return (TCL_ERROR);
}


static char *
GetTclCommand (textPtr, curPos, newCommand)
    Hypertext *textPtr;
    int *curPos;
    char *newCommand;
{
    register int c;
    register int state;
    register int src, dest;

    state = 0;
    dest = 0;
    src = *curPos;

    /* Simply collect the all the characters until %% into a buffer */
    while ((c = textPtr->text[src++]) != '\0') {
	if (c == textPtr->specChar) {
	    state++;
	} else if ((state == 0) && (c == '\\')) {
	    state = 3;
	} else {
	    state = 0;
	}

	switch (state) {
	case 2:	     /* End of command block found */
	    newCommand[dest - 1] = '\0';
	    *curPos = src;
	    return (newCommand);

	case 4:	     /* Escaped block designator */
	    newCommand[dest] = c;
	    state = 0;
	    break;

	default:	     /* Add to command buffer */
	    newCommand[dest++] = c;
	    break;
	}
	if (dest == HUGE_COMMAND_SIZE) {
	    textPtr->interp->result = "Command block is too long";

	    return (NULL);
	}
    }
    textPtr->interp->result = "Premature end of TCL command block";
    return (NULL);
}


static void
FreeLines (textPtr)
    Hypertext *textPtr;
{
    register int i;

    for (i = 0; i < textPtr->numLines; i++) {
	DestroyLine (textPtr->lineArr[i]);
    }
    if (textPtr->lineArr != NULL)
	free ((char *)textPtr->lineArr);
    textPtr->lineArr = NULL;
    textPtr->arraySize = textPtr->numLines = 0;
}


static void
AdjustLinesAllocated (textPtr)
    Hypertext *textPtr;
{
    if (textPtr->arraySize > 0) {
	Line **newPtr;

	newPtr = (Line **) reallocate ((char *)textPtr->lineArr,
				       textPtr->numLines * sizeof (Line *),
				       textPtr->arraySize * sizeof (Line *));
	textPtr->arraySize = textPtr->numLines;
	textPtr->lineArr = newPtr;
    }
}

static void
SetLineText (linePtr, text, size)
    Line *linePtr;
    char *text;
    int size;
{
    linePtr->textLength = size;
    linePtr->text = (char *)malloc (size + 1);
    strcpy (linePtr->text, text);
}

/* ARGSUSED */
static char *
FileVarProc (clientData, interp, name1, name2, flags)
    ClientData clientData;   /* Information about widget. */
    Tcl_Interp *interp;	     /* Interpreter containing variable. */
    char *name1;	     /* Name of variable. */
    char *name2;	     /* Second part of variable name. */
    int flags;		     /* Information about what happened. */
{
    Hypertext *textPtr = (Hypertext *) clientData;
    Hypertext *lastTextPtr;

    /* Check to see of this is the most recent trace */
    lastTextPtr = (Hypertext *) Tcl_VarTraceInfo (interp, name1, flags,
						  FileVarProc,
						  (ClientData) NULL);
    if (lastTextPtr != textPtr)
	return (NULL);	     /* Ignore all but most current trace */

    if (flags & TCL_TRACE_READS) {
	if (strcmp (name1, "thisFile") == 0) {
	    if (textPtr->fileName == NULL)
		Tcl_SetVar (interp, name1, "", flags);
	    else
		Tcl_SetVar (interp, name1, textPtr->fileName, flags);
	} else if (strcmp (name1, "thisLine") == 0) {
	    char buf[80];

	    sprintf (buf, "%d", textPtr->numLines);
	    Tcl_SetVar (interp, name1, buf, flags);
	} else if (strcmp (name1, "this") == 0) {
	    Tcl_SetVar (interp, name1, Tk_PathName (textPtr->tkwin), flags);
	} else {
	    return ("Unknown variable");
	}
    }
    return (NULL);
}

static void
CreateTraces (textPtr)
    Hypertext *textPtr;
{
    register Tcl_Interp *interp = textPtr->interp;
    int flags = (TCL_GLOBAL_ONLY | TCL_TRACE_READS);

    Tcl_TraceVar (interp, "this", flags, FileVarProc, (ClientData) textPtr);
    Tcl_TraceVar (interp, "thisLine", flags, FileVarProc, (ClientData) textPtr);
    Tcl_TraceVar (interp, "thisFile", flags, FileVarProc, (ClientData) textPtr);
    /* Make the traced variables global to the widget */
    Tcl_Eval (interp, "global this thisFile thisLine", 0, (char **)NULL);
}

static void
DeleteTraces (textPtr)
    Hypertext *textPtr;
{
    register Tcl_Interp *interp = textPtr->interp;
    int flags = (TCL_GLOBAL_ONLY | TCL_TRACE_READS);

    /* Destroy the current variable traces */
    Tcl_UntraceVar (interp, "thisFile", flags, FileVarProc,
		    (ClientData) textPtr);
    Tcl_UntraceVar (interp, "thisLine", flags, FileVarProc,
		    (ClientData) textPtr);
    Tcl_UntraceVar (interp, "this", flags, FileVarProc,
		    (ClientData) textPtr);

}

/*
 * ----------------------------------------------------------------------
 *
 * FindChild --
 *	Searches for a child widget matching the pattern given by
 *	*childName*.  If found, the pointer to the child structure is
 *	returned, otherwise NULL.
 *
 * Results:
 *	The pointer to the child structure. If not found, NULL.
 *
 * ----------------------------------------------------------------------
 */

static Child *
FindChild (interp, textPtr, pathName)
    Tcl_Interp *interp;
    Hypertext *textPtr;
    char *pathName;
{
    register Child *childPtr;
    register Line *linePtr;
    register int cnt;
    int relative;

    relative = (*pathName != '.');

    /* Try matching pattern *pathName* to child widget name */
    for (cnt = 0; cnt < textPtr->numLines; cnt++) {

	linePtr = textPtr->lineArr[cnt];
	for (childPtr = linePtr->children; childPtr != NULL;
	     childPtr = childPtr->nextPtr) {
	    if (childPtr->tkwin != NULL) {
		char *name;

		name = (relative) ? Tk_Name (childPtr->tkwin)
		    : Tk_PathName (childPtr->tkwin);
		if (Tcl_StringMatch (name, pathName))
		    return (childPtr);
	    }
	}
    }
    return (NULL);
}

/*
 *--------------------------------------------------------------
 *
 * ChildGeometryProc --
 *
 *	This procedure is invoked by Tk_GeometryRequest for
 *	subwindows managed by the hypertext widget.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Arranges for tkwin, and all its managed siblings, to
 *	be repacked and drawn at the next idle point.
 *
 *--------------------------------------------------------------
 */

 /* ARGSUSED */
static void
ChildGeometryProc (clientData, tkwin)
    ClientData clientData;   /* Information about window that got new
			      * preferred geometry.  */
    Tk_Window tkwin;	     /* Other Tk-related information about the
			      * window. */
{
    register Child *childPtr = (Child *) clientData;

    if (childPtr->widthWanted == 0)
	childPtr->width = Tk_ReqWidth (childPtr->tkwin);
    if (childPtr->heightWanted == 0)
	childPtr->height = Tk_ReqHeight (childPtr->tkwin);

    if (childPtr->width != Tk_Width (childPtr->tkwin) ||
	childPtr->height != Tk_Height (childPtr->tkwin)) {
	EventuallyRedraw (childPtr->parent);
	childPtr->parent->flags |= LAYOUT_NEEDED;
    }
}



static void
SendExposeEvent (tkwin)
    register Tk_Window tkwin;
{
    enum {
	DontPropagate = 0
    };
    XEvent event;

    event.xexpose.type = Expose;
    event.type = Expose;
    event.xexpose.window = Tk_WindowId (tkwin);
    event.xexpose.display = Tk_Display (tkwin);
    event.xexpose.count = 0;
    event.xexpose.x = 0;
    event.xexpose.y = 0;
    event.xexpose.width = Tk_Width (tkwin);
    event.xexpose.height = Tk_Height (tkwin);
    XSendEvent (Tk_Display (tkwin), Tk_WindowId (tkwin), DontPropagate,
		ExposureMask, &event);
}


static char *
reallocate (oldPtr, newSize, oldSize)
    char *oldPtr;
    unsigned int newSize;
    unsigned int oldSize;
{
    register char *newPtr = NULL;

    if (newSize > 0) {

	/* Allocate a new chunk of memory */
	newPtr = (char *)malloc (newSize);
	if (newPtr == NULL) {
	    fprintf (stderr, "reallocate: line %d of `%s': %s\n\
Can't allocate object\n", __LINE__, __FILE__, sys_errlist[errno]);
	    exit (1);
	}
	/* Copy whatever the old contents are */
	if (oldPtr != NULL && oldSize > 0)
	    bcopy (oldPtr, newPtr, MIN (oldSize, newSize));

	/* and clear the new contents */
	if (newSize > oldSize)
	    bzero (newPtr + oldSize, newSize - oldSize);
    }
    free (oldPtr);
    return (newPtr);
}
