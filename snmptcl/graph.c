/*
 * graph.c --
 *
 *	This module implements a graph widget for
 *	the Tk toolkit.
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
 * tortuous action, arising out of or in connection with the use or
 * performance of this software.
 *
 * Graph widget created by Sani Nassif and George Howlett.
 */

/* To do:
 *
 * 1) Fix log autoscale routines to use data min/max as limits
 *    instead of the next unit largest/smallest unit.
 *
 * 2) Rotated PS text doesn't display background color
 *
 * 3) Add PS monochrome and centering option. Kill automatic scaling?
 *
 * 3) Scale fonts with graph (Scale by width and/or height?)
 *
 * 4) No PS for bitmaps.
 *
 * 6) Update manual page.
 *
 * 7) piechart
 *
 * 8) Account for roundoff error when calculating bar widths
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#ifndef HUGE_VAL
#include <limits.h>
#endif
#ifndef NO_ALLOCA
#include <alloca.h>
#endif

#include <stdlib.h>
#include <tk.h>
#include <tclHash.h>
#include <X11/Xutil.h>
#include <X11/Xatom.h>

#ifdef DEBUG
#include <malloc.h>
#endif

#ifdef sun
/* Override defines in Sun's <sys/sysmacros.h> */
#  undef minor
#  undef major
# endif /*sun*/

#define TRUE  1
#define FALSE 0
#define NULLSTR(s)	((s)==NULL || *(s)=='\0')

#if defined (__GNUC__) && defined (__STDC__)
#define INLINE inline
#else
#define INLINE
#endif /* GNUC && STDC */


#define BLACK		"#000000"
#define WHITE		"#ffffff"
#define BISQUE2		"#eed5b7"
#define BISQUE3		"#cdb79e"
#define LIGHTBLUE2	"#b2dfee"
#define LIGHTPINK1	"#ffaeb9"
#define MAROON		"#b03060"

/*
 * Orthogonal rotations for drawing text strings
 */
enum RightAngles {
    ROTATE_0, ROTATE_90, ROTATE_180, ROTATE_270
};

/*
 * Line attributes: either symbol types or line styles
 */
#define SOLID_LINESTYLE		0x01
#define DASHED_LINESTYLE	0x02
#define DOTTED_LINESTYLE	0x04
#define POINT_SYMBOL		0x08
#define SQUARE_SYMBOL		0x10
#define CIRCLE_SYMBOL		0x20
#define DIAMOND_SYMBOL		0x40
#define PLUS_SYMBOL		0x80
#define CROSS_SYMBOL		0x100

#define LINESTYLE(s) ((s)&0x07)

/* Types and classes of graphs: */
enum GraphTypes { XYGRAPH_TYPE, BARCHART_TYPE, PIECHART_TYPE };
static char *classNames[]  = { "XYGraph", "Barchart", "Piechart" };
static char *configNames[] = { "line",    "bar",      "slice" };

/*
 * Mask values used to selectively enable entries in the
 * configuration specs:
 */
#define XYGRAPH_MASK	TK_CONFIG_USER_BIT
#define BARCHART_MASK	TK_CONFIG_USER_BIT << 1
#define PIECHART_MASK	TK_CONFIG_USER_BIT << 2
#define ALL_MASK	(XYGRAPH_MASK | BARCHART_MASK | PIECHART_MASK)

static int configFlags[]=
{
    XYGRAPH_MASK, BARCHART_MASK, PIECHART_MASK
};

#define MIN(a,b)	(((a)<(b))?(a):(b))
#define MAX(a,b)	(((a)>(b))?(a):(b))
#define ROUND(x,u)	(rint((x)/(u))*(u))
#define CEIL(x,u)	(ceil((x)/(u))*(u))
#define FLOOR(x,u)	(floor((x)/(u))*(u))
#ifdef NO_EXP10
#define exp10(n) 	pow(10.0,(n))
#endif /* NO_EXP10 */

#ifdef NO_RINT
#define rint(x)	((int)((x) + (((x)<0.0) ? -0.5 : 0.5)))
#endif /* NO_RINT */

#define PADX		2    /* Padding between labels/titles */
#define PADY    	2    /* Padding between labels */
#define FONTHEIGHT(f) 	((f)->ascent + (f)->descent)

#define MAJOR_TICK 0.025     /* Length of a major tick */
#define MINOR_TICK 0.015     /* Length of a minor (sub) tick */
#define LABEL_TICK 0.030     /* Distance from graph to start of label */

/* 
 * Sun's bundled and unbundled C compilers can't grok static 
 * function typedefs (it can handle extern) like
 *
 * 	static Tk_OptionParseProc parseProc; 
 *  	static Tk_OptionPrintProc printProc; 
 *
 * Provide forward declarations here:
 */
static int SymbolParseProc _ANSI_ARGS_((ClientData clientData, 
 Tcl_Interp *interp, Tk_Window tkwin, char *value, char *widgRec, int offset));
static char *SymbolPrintProc _ANSI_ARGS_((ClientData clientData, 
 Tk_Window tkwin, char *widgRec, int offset, Tcl_FreeProc **freeProcPtr));
static int LimitParseProc _ANSI_ARGS_((ClientData clientData, 
 Tcl_Interp *interp, Tk_Window tkwin, char *value, char *widgRec, int offset));
static char *LimitPrintProc _ANSI_ARGS_((ClientData clientData, 
 Tk_Window tkwin, char *widgRec, int offset, Tcl_FreeProc **freeProcPtr));
static int VectorParseProc _ANSI_ARGS_((ClientData clientData, 
 Tcl_Interp *interp, Tk_Window tkwin, char *value, char *widgRec, int offset));
static char *VectorPrintProc _ANSI_ARGS_((ClientData clientData, 
 Tk_Window tkwin, char *widgRec, int offset, Tcl_FreeProc **freeProcPtr));
static int TwinVectorParseProc _ANSI_ARGS_((ClientData clientData, 
 Tcl_Interp *interp, Tk_Window tkwin, char *value, char *widgRec, int offset));
static char *TwinVectorPrintProc _ANSI_ARGS_((ClientData clientData, 
 Tk_Window tkwin, char *widgRec, int offset, Tcl_FreeProc **freeProcPtr));
static int ExprParseProc _ANSI_ARGS_((ClientData clientData, 
 Tcl_Interp *interp, Tk_Window tkwin, char *value, char *widgRec, int offset));
static char *ExprPrintProc _ANSI_ARGS_((ClientData clientData, 
 Tk_Window tkwin, char *widgRec, int offset, Tcl_FreeProc **freeProcPtr));
static int LegendParseProc _ANSI_ARGS_((ClientData clientData, 
 Tcl_Interp *interp, Tk_Window tkwin, char *value, char *widgRec, int offset));
static char *LegendPrintProc _ANSI_ARGS_((ClientData clientData, 
 Tk_Window tkwin, char *widgRec, int offset, Tcl_FreeProc **freeProcPtr));


typedef struct ListEntry {
    struct ListEntry *prevPtr;	/* Link to the previous entry */
    struct ListEntry *nextPtr;	/* Link to the next entry (not used) */
    char *keyPtr;		/* Pointer to the (character string) key */
    ClientData clientData;	/* Pointer to the data object */
} ListEntry;

typedef struct LinkedList {
    ListEntry *headPtr;	     /* Pointer to first element in list */
    ListEntry *tailPtr;	     /* Pointer to last element in list */
    int numEntries;	     /* Number of elements in list */
} LinkedList;

/*
 * Structure containing Postscript options
 */
typedef struct {
    char *fileName;	     /* Name of generated postscript file */
    char *geometry;	     /* Geometry of postscript plot */
    int isCentered;	     /* If non-zero, center the plot on the page */
    int isMonochrome;	     /* If non-zero, use BW color scheme */
    int isLandscape;	     /* If non-zero, rotate into landscape */
} PSOption;

/*
 * The data structure below contains information pertaining to a line
 * vector.  It consists of an array of double precision data values and
 * for convenience, the number and minimum/maximum values.
 */
typedef struct Vector {
    double *valueArr;	     /* Array of values */
    int numValues;	     /* Number of elements in the array */
    double minValue;	     /* Smallest value in the array */
    double maxValue;	     /* Largest value in the array */
} Vector;

/*
 * A line is a vector plus several attributes, such as line style, thickness,
 * color, and symbol type.  It has a name which associates it among the list
 * of lines.
 */
typedef struct Line {
    struct Graph *parent;    /* Plotting surface associated with vector */
    char *label;	     /* Line label */
    char *name;		     /* Key name to refer the line. Used in the
			      * "insert", "delete", or "show", commands. */
    int isVisible;	     /* If true, line is currently visible. */
    int showRetrace;	     /* If true, draw line retrace. */
    int symbol;		     /* Integer value representing line symbol
			      * attribute. */
    double symSizePct;	     /* Size of symbol as a percentage of the drawing
			      * area. */
    int symbolSize;	     /* Computed size of symbol in pixels. */
    Pixmap stipple;	     /* Bitmap for barchart/piechart patterns */
    int lineWidth;	     /* Line width for XY graphs */
    XColor *fgColor;	     /* Line color */
    XColor *bgColor;	     /* Background color for barcharts/piecharts */
    GC gc;		     /* Private graphics context of line */
    Vector x, y;	     /* Contains array of numeric values */
} Line;

static Tk_CustomOption SymbolOption =
{
    SymbolParseProc, SymbolPrintProc, NULL
};

static double NegativeInfinity;
static double PositiveInfinity;

static Tk_CustomOption MinLimitOption =
{
    LimitParseProc, LimitPrintProc, (ClientData) & NegativeInfinity,
};
static Tk_CustomOption MaxLimitOption =
{
    LimitParseProc, LimitPrintProc, (ClientData) & PositiveInfinity,
};
static Tk_CustomOption VectorOption =
{
    VectorParseProc, VectorPrintProc, NULL
};
static Tk_CustomOption TwinVectorOption =
{
    TwinVectorParseProc, TwinVectorPrintProc, NULL
};
static Tk_CustomOption ExprOption =
{
    ExprParseProc, ExprPrintProc, NULL
};

#define DEF_LINE_BG_COLOR	 WHITE
#define DEF_LINE_BG_MONO	 WHITE
#define DEF_LINE_FG_COLOR	 BLACK
#define DEF_LINE_FG_MONO	 BLACK
#define DEF_LINE_WIDTH		 "0"
#define DEF_LINE_STYLE		 "solid"
#define DEF_LINE_STIPPLE	 (char *)NULL
#define DEF_LINE_VISIBLE	 "true"
#define DEF_LINE_NAME		 "unknown"
#define DEF_LINE_SYMBOL_SIZE	 "1.5"

static Tk_ConfigSpec lineConfigSpecs[]=
{
    {TK_CONFIG_COLOR, "-background", "background", "Background",
     DEF_LINE_BG_COLOR, Tk_Offset(Line, bgColor),
     TK_CONFIG_COLOR_ONLY | PIECHART_MASK | BARCHART_MASK},
    {TK_CONFIG_COLOR, "-background", "background", "Background",
     DEF_LINE_BG_MONO, Tk_Offset(Line, bgColor),
     TK_CONFIG_MONO_ONLY | PIECHART_MASK | BARCHART_MASK},
    {TK_CONFIG_SYNONYM, "-bg", "background", (char *)NULL, (char *)NULL, 0,
     PIECHART_MASK | BARCHART_MASK},
    {TK_CONFIG_COLOR, "-color", "color", "Color",
     DEF_LINE_FG_COLOR, Tk_Offset(Line, fgColor),
     TK_CONFIG_COLOR_ONLY | XYGRAPH_MASK},
    {TK_CONFIG_COLOR, "-color", "color", "Color",
     DEF_LINE_FG_MONO, Tk_Offset(Line, fgColor),
     TK_CONFIG_MONO_ONLY | XYGRAPH_MASK},
    {TK_CONFIG_SYNONYM, "-fg", "foreground", (char *)NULL,
     (char *)NULL, 0, BARCHART_MASK | PIECHART_MASK},
    {TK_CONFIG_COLOR, "-foreground", "foreground", "Foregound",
     DEF_LINE_FG_COLOR, Tk_Offset(Line, fgColor),
     TK_CONFIG_COLOR_ONLY | BARCHART_MASK | PIECHART_MASK},
    {TK_CONFIG_COLOR, "-foreground", "foreground", "Foreground",
     DEF_LINE_FG_MONO, Tk_Offset(Line, fgColor),
     TK_CONFIG_MONO_ONLY | BARCHART_MASK | PIECHART_MASK},
    {TK_CONFIG_PIXELS, "-linewidth", "lineWidth", "LineWidth",
     DEF_LINE_WIDTH, Tk_Offset(Line, lineWidth), XYGRAPH_MASK},
    {TK_CONFIG_DOUBLE, "-symbolsize", "symbolSize", "SymbolSize",
     DEF_LINE_SYMBOL_SIZE, Tk_Offset(Line, symSizePct), ALL_MASK},
    {TK_CONFIG_CUSTOM, "-symbol", "symbol", "Symbol",
     DEF_LINE_STYLE, Tk_Offset(Line, symbol), XYGRAPH_MASK, &SymbolOption},
    {TK_CONFIG_BITMAP, "-stipple", "stipple", "Stipple",
     DEF_LINE_STIPPLE, Tk_Offset(Line, stipple), 
     BARCHART_MASK | PIECHART_MASK},
    {TK_CONFIG_CUSTOM, "-xdata", "xData", (char *)NULL,
     NULL, Tk_Offset(Line, x), ALL_MASK, &VectorOption},
    {TK_CONFIG_CUSTOM, "-ydata", "yData", (char *)NULL,
     NULL, Tk_Offset(Line, y), ALL_MASK, &VectorOption},
    {TK_CONFIG_CUSTOM, "-xydata", "xyData", (char *)NULL,
     NULL, 0, XYGRAPH_MASK, &TwinVectorOption},
    {TK_CONFIG_STRING, "-label", "label", "Label",
     NULL, Tk_Offset(Line, label), ALL_MASK},
    {TK_CONFIG_STRING, "-showretrace", (char *)NULL, (char *)NULL,
     NULL, Tk_Offset(Line, showRetrace), ALL_MASK},
/* remaining configuration options go here */
    {TK_CONFIG_END, NULL, NULL, NULL, NULL, 0, 0}
};

/* Tags */
typedef struct {
    char *name;		     /* Tag identifier */
    char *text;		     /* Tag text */
    char *lineName;	     /* Line associated with tag */
    double x, y;	     /* Coordinate values */
    int anchor;		     /* Anchor of text around point */
    int rotation;	     /* Rotation of text around point */
    Pixmap bitmap;	     /* If not None, use bitmap instead of text */
    XColor *fgColor;	     /* Foreground color of tag */
    XColor *bgColor;	     /* Background color of tag */
    XFontStruct *fontPtr;    /* Font to use for text */
    GC gc;		     /* Private graphics context */
} Tag;

#define DEF_TAG_ROTATION 	"0"
#define DEF_TAG_FONT		"*-Helvetica-Bold-R-Normal-*-120-*"
#define DEF_TAG_BG_MONO		WHITE
#define DEF_TAG_BG_COLOR	WHITE
#define DEF_TAG_FG_MONO		BLACK
#define DEF_TAG_FG_COLOR	BLACK

#define DEF_TAG_ANCHOR		"center"

static Tk_ConfigSpec tagConfigSpecs[]=
{
    {TK_CONFIG_ANCHOR, "-anchor", "anchor", "Anchor",
     DEF_TAG_ANCHOR, Tk_Offset(Tag, anchor), ALL_MASK},
    {TK_CONFIG_COLOR, "-background", "background", "Background",
     DEF_TAG_BG_COLOR, Tk_Offset(Tag, bgColor),
     TK_CONFIG_COLOR_ONLY | ALL_MASK},
    {TK_CONFIG_COLOR, "-background", "background", "Background",
     DEF_TAG_BG_MONO, Tk_Offset(Tag, bgColor),
     TK_CONFIG_MONO_ONLY | ALL_MASK},
    {TK_CONFIG_SYNONYM, "-bg", "background", (char *)NULL,
     (char *)NULL, 0, ALL_MASK},
    {TK_CONFIG_BITMAP, "-bitmap", "bitmap", "Bitmap",
     (char *)NULL, Tk_Offset(Tag, bitmap), ALL_MASK | TK_CONFIG_NULL_OK},
    {TK_CONFIG_SYNONYM, "-fg", "foreground", (char *)NULL,
     (char *)NULL, 0, ALL_MASK},
    {TK_CONFIG_FONT, "-font", "font", "Font",
     DEF_TAG_FONT, Tk_Offset(Tag, fontPtr), ALL_MASK},
    {TK_CONFIG_COLOR, "-foreground", "foreground", "Foregound",
     DEF_TAG_FG_COLOR, Tk_Offset(Tag, fgColor),
     TK_CONFIG_COLOR_ONLY | ALL_MASK},
    {TK_CONFIG_COLOR, "-foreground", "foreground", "Foreground",
     DEF_LINE_FG_MONO, Tk_Offset(Tag, fgColor),
     TK_CONFIG_MONO_ONLY | ALL_MASK},
    {TK_CONFIG_STRING, "-line", (char *)NULL, (char *)NULL,
     (char *)NULL, Tk_Offset(Tag, lineName), XYGRAPH_MASK},
    {TK_CONFIG_STRING, "-bar", (char *)NULL, (char *)NULL,
     (char *)NULL, Tk_Offset(Tag, lineName), BARCHART_MASK},
    {TK_CONFIG_INT, "-rotation", "rotation", "Rotation",
     DEF_TAG_ROTATION, Tk_Offset(Tag, rotation), ALL_MASK},
    {TK_CONFIG_STRING, "-text", "text", "Text",
     (char *)NULL, Tk_Offset(Tag, text), ALL_MASK},
    {TK_CONFIG_CUSTOM, "-xcoordinate", "xCoordinate", "Coordinate",
     (char *)NULL, Tk_Offset(Tag, x), ALL_MASK, &ExprOption},
    {TK_CONFIG_CUSTOM, "-ycoordinate", "yCoordinate", "Coordinate",
     (char *)NULL, Tk_Offset(Tag, y), ALL_MASK, &ExprOption},
    {TK_CONFIG_END, NULL, NULL, NULL, NULL, 0, 0}
};

/*
 * Tick contains information of where and how many ticks are
 * to be displayed on an axis.
 */
typedef struct {
    int numSteps;	     /* Number of ticks */
    double stepSize;	     /* Stepping distance for ticks */
    double low;		     /* Smallest tick */
    double high;	     /* Largest tick */
} Tick;

/* An axis is a set of options controlling how the axis will be
 * displayed.
 */
typedef struct {
    double minLimit;	     /* Smallest axis value */
    double maxLimit;	     /* Largest axis value */
    double range;	     /* Range of values (maxLimit-minLimit) */
    int offset;		     /* Offset of plotting region from screen origin */
    double scale;	     /* Scale factor to convert values to pixels */
    int manualConfig;	     /* If non-zero, do not automatically configure
			      * the graph axis. Use user-specified limits. */
    Tick major, minor;	     /* Information about major and minor ticks */
    int logScale;	     /* If non-zero, use logarithmic scale for axis */
    char *label;	     /* Axis label */
    double reqStepSize;	     /* User defined step size  */
    double reqMinimum;	     /* User defined minimum value */
    double reqMaximum;	     /* User defined maximum value */
} Axis;

/*
 * The data structure below holds information specific to
 * how the legend will be displayed.
 */
typedef struct {
    int isVisible;	     /* If non-zero, legend is displayed */
    int borderWidth;	     /* Width of legend 3-D border */
    Tk_3DBorder border;	     /* 3-D border and background. */
    int relief;		     /* 3-d effect: TK_RELIEF_RAISED etc. */
    int x, y;		     /* Position of legend in screen coordinates */
    int usePosition;	     /* If non-zero, use user-specified position */
    int width;		     /* Legend width */
    int height;		     /* Legend height */
    int maxSymSize;	     /* Size of largest symbol to be displayed */
    int numEntries;	     /* Number of symbols/labels to display */
} Legend;


static Tk_CustomOption LegendOption =
{
    LegendParseProc, LegendPrintProc, NULL
};

/*
 * A data structure of the following type is kept for each graph that
 * exists within a given instance of a Tcl interpreter
 */
typedef struct Graph {
    Tk_Window tkwin;	     /* Window that embodies the widget */
    Tcl_Interp *interp;	     /* Interpreter associated with widget */
    Tk_3DBorder border;	     /* 3-D border and background. */
    int borderWidth;	     /* Width of 3-D border (if any). */
    int relief;		     /* 3-d effect: TK_RELIEF_RAISED etc. */
    char *geometry;	     /* Geometry that user requested. */
    int flags;		     /* Flags;  see below for definitions. */
    GC gc;		     /* Private graphic context */
    ClientData output;	     /* PS file, pixmap, or window to draw into */
    int psWidth;	     /* PS plot width */
    int psHeight;	     /* PS plot height */
    int width;		     /* Graph window width */
    int height;		     /* Graph window height */
    int type;		     /* Type of graph: XYGRAPH_TYPE, BARCHART_TYPE,
			      * or PIECHART_TYPE. */
    int xrotation;	     /* Rotation of X axis tick label for barcharts */
    int maxValues;	     /* Size of largest vector of data */
    int showRetrace;	     /* Draw all line segments, even when the next
			      * x-coordinate value is less than the previous */
    int doubleBuffered;	     /* If non-zero, use an off-screen pixmap for
			      * drawing operations */
    char *title;	     /* Graph title */
    int leftMargin;	     /* # pixels padding for left margin */
    int rightMargin;	     /* # pixels padding for right margin */
    int topMargin;	     /* # pixels padding for top margin */
    int bottomMargin;	     /* # pixels padding for bottom margin */
    int axisThickness;	     /* Axis line thickness */
    double barWidthPct;	     /* Width of bar as a percentage of the unit
			      * distance */
    XFontStruct *fontPtr;    /* Information about the text font */
    XFontStruct *numberFontPtr;	/* Number font. */
    XColor *numberFg;	     /* Number color */
    GC numberGC;	     /* Graphic context for numbers/axis */
    XColor *fgColor;	     /* Text color */
    Cursor cursor;	     /* Graph X11 Cursor */
    Axis X, Y;		     /* X and Y Axis information */
    Legend legend;	     /* Legend information */
    LinkedList allLines;     /* Table of lines */
    LinkedList drawnLines;   /* Table of visible lines */
    LinkedList tags;	     /* Table of tags */
} Graph;

/* Flag bits for graphs:
 *
 * REDRAW_PENDING:		Non-zero means a DoWhenIdle handler has
 *				already been queued to redraw this window.
 *
 * LAYOUT_NEEDED:		Non-zero means that a graph configuration
 *				has changed (line, tag, axis, legend, etc)
 *				and the layout of the graph (position of the
 *				graph in the window) needs to be recalculated.
 */
#define REDRAW_PENDING		1
#define LAYOUT_NEEDED		2

#define DEF_BAR_WIDTH_PCT	 "80.0"
#define DEF_GRAPH_BG_COLOR	 WHITE
#define DEF_GRAPH_BG_MONO	 WHITE
#define DEF_GRAPH_BUFFERING 	 "true"
#define DEF_GRAPH_CURSOR  	 "crosshair"
#define DEF_GRAPH_FG_COLOR	 BLACK
#define DEF_GRAPH_FG_MONO	 BLACK
#define DEF_GRAPH_FONT		 "*-Helvetica-Bold-R-Normal-*-120-*"
#define DEF_GRAPH_GEOMETRY	 "400x400"
#define DEF_GRAPH_RELIEF	 "flat"
#define DEF_GRAPH_TITLE		 "Graph Title"
#define DEF_LEGEND_BG_COLOR	 WHITE
#define DEF_LEGEND_BG_MONO	 WHITE
#define DEF_LEGEND_BORDER_WIDTH  "2"
#define DEF_LEGEND_POSITION	 ""
#define DEF_LEGEND_RELIEF	 "raised"
#define DEF_LEGEND_SHOW		 "true"
#define DEF_NUMBER_FG_COLOR	 BLACK
#define DEF_NUMBER_FG_MONO	 BLACK
#define DEF_NUMBER_FONT	 	 "*-Courier-Bold-R-Normal-*-100-*"
#define DEF_NUM_MINOR_TICKS	 "5"
#define DEF_X_AXIS_LABEL         "X"
#define DEF_X_AXIS_ROTATION	 "90"
#define DEF_X_AXIS_STEP		 "0.0"
#define DEF_X_AXIS_TICKS	 "true"
#define DEF_Y_AXIS_LABEL         "Y"
#define DEF_Y_AXIS_STEP		 "0.0"
#define DEF_Y_AXIS_TICKS	 "true"

static Tk_ConfigSpec configSpecs[]=
{
    {TK_CONFIG_BORDER, "-background", "background", "Background",
     DEF_GRAPH_BG_COLOR, Tk_Offset(Graph, border),
     TK_CONFIG_COLOR_ONLY | ALL_MASK},
    {TK_CONFIG_BORDER, "-background", "background", "Background",
     DEF_GRAPH_BG_MONO, Tk_Offset(Graph, border),
     TK_CONFIG_MONO_ONLY | ALL_MASK},
    {TK_CONFIG_PIXELS, "-borderwidth", "borderWidth", "BorderWidth",
     (char *)NULL, Tk_Offset(Graph, borderWidth), ALL_MASK},
    {TK_CONFIG_SYNONYM, "-bd", "borderWidth", (char *)NULL, (char *)NULL, 0,
     ALL_MASK},
    {TK_CONFIG_SYNONYM, "-bg", "background", (char *)NULL, (char *)NULL, 0,
     ALL_MASK},
    {TK_CONFIG_DOUBLE, "-barwidthpct", "barWidthPct", "BarWidthPct",
     DEF_BAR_WIDTH_PCT, Tk_Offset(Graph, barWidthPct), BARCHART_MASK},
    {TK_CONFIG_ACTIVE_CURSOR, "-cursor", "cursor", "Cursor",
     DEF_GRAPH_CURSOR, Tk_Offset(Graph, cursor),
     ALL_MASK | TK_CONFIG_NULL_OK},
    {TK_CONFIG_BOOLEAN, "-doublebuffered", "doubleBuffered", (char *)NULL,
     DEF_GRAPH_BUFFERING, Tk_Offset(Graph, doubleBuffered), ALL_MASK},
    {TK_CONFIG_SYNONYM, "-dbl", "doubleBuffered", (char *)NULL,
     (char *)NULL, 0, ALL_MASK},
    {TK_CONFIG_FONT, "-font", "font", "Font",
     DEF_GRAPH_FONT, Tk_Offset(Graph, fontPtr), ALL_MASK},
    {TK_CONFIG_COLOR, "-numbercolor", "numberColor", "Foreground",
     DEF_NUMBER_FG_COLOR, Tk_Offset(Graph, numberFg),
     TK_CONFIG_COLOR_ONLY | ALL_MASK},
    {TK_CONFIG_COLOR, "-numbercolor", "numberColor", "Foreground",
     DEF_NUMBER_FG_MONO, Tk_Offset(Graph, numberFg),
     TK_CONFIG_MONO_ONLY | ALL_MASK},
    {TK_CONFIG_FONT, "-numberfont", "numberFont", "Font",
     DEF_NUMBER_FONT, Tk_Offset(Graph, numberFontPtr), ALL_MASK},
    {TK_CONFIG_SYNONYM, "-fg", "foreground", (char *)NULL, (char *)NULL, 0,
     ALL_MASK},
    {TK_CONFIG_COLOR, "-foreground", "foreground", "Foreground",
     DEF_GRAPH_FG_COLOR, Tk_Offset(Graph, fgColor),
     TK_CONFIG_COLOR_ONLY | ALL_MASK},
    {TK_CONFIG_COLOR, "-foreground", "foreground", "Foreground",
     DEF_GRAPH_FG_MONO, Tk_Offset(Graph, fgColor),
     TK_CONFIG_MONO_ONLY | ALL_MASK},
    {TK_CONFIG_STRING, "-geometry", "geometry", "Geometry",
     DEF_GRAPH_GEOMETRY, Tk_Offset(Graph, geometry), ALL_MASK},
    {TK_CONFIG_RELIEF, "-relief", "relief", "Relief",
     DEF_GRAPH_RELIEF, Tk_Offset(Graph, relief), ALL_MASK},
    {TK_CONFIG_STRING, "-title", "title", "Title",
     DEF_GRAPH_TITLE, Tk_Offset(Graph, title), ALL_MASK},
    {TK_CONFIG_STRING, "-xlabel", "xLabel", "Label",
     DEF_X_AXIS_LABEL, Tk_Offset(Graph, X.label), ALL_MASK},
    {TK_CONFIG_STRING, "-ylabel", "yLabel", "Label",
     DEF_Y_AXIS_LABEL, Tk_Offset(Graph, Y.label), ALL_MASK},
    {TK_CONFIG_CUSTOM, "-legendposition", "legendPosition", "LegendPosition",
     DEF_LEGEND_POSITION, Tk_Offset(Graph, legend),
     TK_CONFIG_NULL_OK | ALL_MASK, &LegendOption},
    {TK_CONFIG_SYNONYM, "-lpos", "legendPosition", "LegendPosition",
     (char *)NULL, 0, ALL_MASK},
    {TK_CONFIG_BOOLEAN, "-showlegend", "showLegend", "ShowLegend",
     DEF_LEGEND_SHOW, Tk_Offset(Graph, legend.isVisible), ALL_MASK},
    {TK_CONFIG_INT, "-legendborderwidth", "legendBorderWidth", "BorderWidth",
   DEF_LEGEND_BORDER_WIDTH, Tk_Offset(Graph, legend.borderWidth), ALL_MASK},
    {TK_CONFIG_SYNONYM, "-lbd", "legendBorderWidth", (char *)NULL,
     (char *)NULL, 0, ALL_MASK},
    {TK_CONFIG_RELIEF, "-legendrelief", "legendRelief", "Relief",
     DEF_LEGEND_RELIEF, Tk_Offset(Graph, legend.relief), ALL_MASK},
    {TK_CONFIG_SYNONYM, "-lrelief", "legendRelief", (char *)NULL,
     (char *)NULL, 0, ALL_MASK},
    {TK_CONFIG_BORDER, "-legendbackground", "legendBackground", "Background",
     DEF_LEGEND_BG_MONO, Tk_Offset(Graph, legend.border),
     TK_CONFIG_MONO_ONLY | ALL_MASK},
    {TK_CONFIG_BORDER, "-legendbackground", "legendBackground", "Background",
     DEF_LEGEND_BG_COLOR, Tk_Offset(Graph, legend.border),
     TK_CONFIG_COLOR_ONLY | ALL_MASK},
    {TK_CONFIG_SYNONYM, "-lbg", "legendBackground", (char *)NULL,
     (char *)NULL, 0, ALL_MASK},
    {TK_CONFIG_CUSTOM, "-xmin", "xMin", "Minimum",
     (char *)NULL, Tk_Offset(Graph, X.reqMinimum),
     XYGRAPH_MASK | TK_CONFIG_NULL_OK, &MinLimitOption},
    {TK_CONFIG_CUSTOM, "-xmax", "xMax", "Maximum",
     (char *)NULL, Tk_Offset(Graph, X.reqMaximum),
     XYGRAPH_MASK | TK_CONFIG_NULL_OK, &MaxLimitOption},
    {TK_CONFIG_CUSTOM, "-ymin", "yMin", "Minimum",
     (char *)NULL, Tk_Offset(Graph, Y.reqMinimum),
     ALL_MASK | TK_CONFIG_NULL_OK, &MinLimitOption},
    {TK_CONFIG_CUSTOM, "-ymax", "yMax", "Maximum",
     (char *)NULL, Tk_Offset(Graph, Y.reqMaximum),
     ALL_MASK | TK_CONFIG_NULL_OK, &MaxLimitOption},
    {TK_CONFIG_BOOLEAN, "-xlogscale", "xLogScale", "LogScale",
     (char *)NULL, Tk_Offset(Graph, X.logScale), XYGRAPH_MASK},
    {TK_CONFIG_BOOLEAN, "-ylogscale", "yLogScale", "LogScale",
     (char *)NULL, Tk_Offset(Graph, Y.logScale), ALL_MASK},
    {TK_CONFIG_PIXELS, "-axisthickness", "axisThickness", "Thickness",
     (char *)NULL, Tk_Offset(Graph, axisThickness), ALL_MASK},
    {TK_CONFIG_DOUBLE, "-xstepsize", "xStepSize", "StepSize",
     DEF_X_AXIS_STEP, Tk_Offset(Graph, X.reqStepSize), XYGRAPH_MASK},
    {TK_CONFIG_DOUBLE, "-ystepsize", "yStepSize", "StepSize",
     DEF_Y_AXIS_STEP, Tk_Offset(Graph, Y.reqStepSize), ALL_MASK},
    {TK_CONFIG_INT, "-xrotation", "xRotation", "Rotation",
     DEF_X_AXIS_ROTATION, Tk_Offset(Graph, xrotation), BARCHART_MASK},
    {TK_CONFIG_INT, "-xsubticks", "xSubTicks", "SubTicks",
     DEF_NUM_MINOR_TICKS, Tk_Offset(Graph, X.minor.numSteps), XYGRAPH_MASK},
    {TK_CONFIG_INT, "-ysubticks", "ySubticks", "SubTicks",
     DEF_NUM_MINOR_TICKS, Tk_Offset(Graph, Y.minor.numSteps), ALL_MASK},
    {TK_CONFIG_BOOLEAN, "-xticks", "xTicks", "Ticks",
     DEF_X_AXIS_TICKS, Tk_Offset(Graph, X.major.numSteps), ALL_MASK},
    {TK_CONFIG_BOOLEAN, "-yticks", "yTicks", "Ticks",
     DEF_Y_AXIS_TICKS, Tk_Offset(Graph, Y.major.numSteps), ALL_MASK},
    {TK_CONFIG_BOOLEAN, "-retrace", "retrace", "Retrace",
     (char *)NULL, Tk_Offset(Graph, showRetrace), XYGRAPH_MASK},
    {TK_CONFIG_PIXELS, "-bottommargin", "bottomMargin", "BottomMargin",
     (char *)NULL, Tk_Offset(Graph, bottomMargin), ALL_MASK},
    {TK_CONFIG_PIXELS, "-leftmargin", "leftMargin", "LeftMargin",
     (char *)NULL, Tk_Offset(Graph, leftMargin), ALL_MASK},
    {TK_CONFIG_PIXELS, "-rightmargin", "rightMargin", "RightMargin",
     (char *)NULL, Tk_Offset(Graph, rightMargin), ALL_MASK},
    {TK_CONFIG_PIXELS, "-topmargin", "topMargin", "TopMargin",
     (char *)NULL, Tk_Offset(Graph, topMargin), ALL_MASK},
    {TK_CONFIG_END, NULL, NULL, NULL, NULL, 0, 0}
};

static void DisplayGraph _ANSI_ARGS_((ClientData clientData));
static void DestroyGraph _ANSI_ARGS_((ClientData clientData));
static int GraphWidgetCmd _ANSI_ARGS_((ClientData clientData,
			       Tcl_Interp * interp, int argc, char **argv));
extern void TkBindError _ANSI_ARGS_((Tcl_Interp * interp));

extern char *sys_errlist[];

/* Graph to screen coordinate transformations  */
#define GX(g,x)    ((int)rint((x)*(g)->X.scale)+(g)->X.offset)
#define GY(g,y)    ((g)->Y.offset-(int)rint((y)*(g)->Y.scale))

INLINE static void
FormatLabel(logScale, value, label)	/* Convert a value to a label */
    int logScale;
    double value;
    char *label;
{
    if (logScale)
	sprintf(label, "1E%d", (int)rint(value));
    else
	sprintf(label, "%.10g", value);
}

INLINE static XPoint
Gr_Point(graphPtr, x, y)
    Graph *graphPtr;
    double x, y;
{
    XPoint point;

    point.x = GX(graphPtr, x), point.y = GY(graphPtr, y);
    return (point);
}

INLINE static XSegment
Gr_Segment(graphPtr, x1, y1, x2, y2)
    Graph *graphPtr;
    double x1, y1, x2, y2;
{
    XSegment seg;

    seg.x1 = GX(graphPtr, x1), seg.y1 = GY(graphPtr, y1);
    seg.x2 = GX(graphPtr, x2), seg.y2 = GY(graphPtr, y2);
    return (seg);
}

INLINE static double
ScaleX(graphPtr, x)
    register Graph *graphPtr;
    register double x;
{
    if (x == PositiveInfinity)
	return (1.0);
    else if (x == NegativeInfinity)
	return (0.0);
    if (graphPtr->X.logScale) {
	if (x > 0.0)
	    x = log10(x);
	else 
	    return (-1.0);		/* out of range */
    }
    return ((x - graphPtr->X.minLimit) / graphPtr->X.range);
}

INLINE static double
ScaleY(graphPtr, y)
    register Graph *graphPtr;
    register double y;
{
    if (y == PositiveInfinity)
	return (1.0);
    else if (y == NegativeInfinity)
	return (0.0);
    if (graphPtr->Y.logScale) {
	if (y > 0.0)
	    y = log10(y);
	else 
	    return (-1.0);		/* out of range */
    }
    return ((y - graphPtr->Y.minLimit) / graphPtr->Y.range);
}

INLINE static double
UnscaleX(graphPtr, x)
    register Graph *graphPtr;
    register double x;
{
    x = (x * graphPtr->X.range) + graphPtr->X.minLimit;
    return ((graphPtr->X.logScale) ? exp10(x) : x);
}

INLINE static double
UnscaleY(graphPtr, y)
    register Graph *graphPtr;
    register double y;
{
    y = (y * graphPtr->Y.range) + graphPtr->Y.minLimit;
    return ((graphPtr->Y.logScale) ? exp10(y) : y);
}

/* ----------------------------------------------------------------------
 * Generic list management routines.
 * ---------------------------------------------------------------------- */

/*
 *----------------------------------------------------------------------
 *
 * CreateListEntry --
 *
 *	Appends a pointer on the end of a generic list, using the character
 *	string given as its identifier.  The is no attempt to maintain
 *	consistency at this level.  For example, more than one object may
 *	use the same key.
 *
 * Results:
 *	The return value is a standard Tcl result.
 *
 * Side Effects:
 *	The key is not copied, only the pointer is kept.  It is assumed
 *	this key will remain static.
 *
 *----------------------------------------------------------------------
 */
static int
CreateListEntry(listPtr, key, clientData)
    LinkedList *listPtr;     /* The list to append the object */
    char *key;		     /* Unique key to reference object */
    ClientData clientData;   /* Pointer to the object */
{
    register ListEntry *newPtr;

    newPtr = (ListEntry *) malloc(sizeof(ListEntry));
    if (newPtr == NULL)
	return TCL_ERROR;
    newPtr->clientData = clientData;
    newPtr->keyPtr = key;
    newPtr->prevPtr = newPtr->nextPtr = NULL;

    if (listPtr->headPtr == NULL)
	listPtr->tailPtr = listPtr->headPtr = newPtr;
    else {
	listPtr->tailPtr->nextPtr = newPtr;
	newPtr->prevPtr = listPtr->tailPtr;
	listPtr->tailPtr = newPtr;
    }
    listPtr->numEntries++;
    return TCL_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * DeleteListEntry --
 *
 *	Remove the first entry (contains pointers to object key and data),
 *	using the given name as the key.  Only the pointers to the object
 *	and key are deleted.
 *
 * Results:
 *	The return value is a standard Tcl result.  If no object matching
 *	the key given is found, then TCL_ERROR is returned.
 *
 *----------------------------------------------------------------------
 */
static int
DeleteListEntry(listPtr, name)
    LinkedList *listPtr;     /* List to delete entry from */
    char *name;		     /* Key to use in search */
{
    register ListEntry *entryPtr;
    char c = *name;

    for (entryPtr = listPtr->headPtr; entryPtr != NULL;
	 entryPtr = entryPtr->nextPtr) {
	if ((c == *entryPtr->keyPtr) && strcmp(name, entryPtr->keyPtr) == 0)
	    break;
    }
    if (entryPtr == NULL) {  /* Item is not in list */
	fprintf(stderr, "ListDelete: no such key `%s'\n", name);
	return TCL_ERROR;
    }
    if (listPtr->headPtr == listPtr->tailPtr) {
	listPtr->tailPtr = listPtr->headPtr = NULL;
    } else if (entryPtr == listPtr->tailPtr) {
	listPtr->tailPtr = entryPtr->prevPtr;
	entryPtr->prevPtr->nextPtr = NULL;
    } else if (entryPtr == listPtr->headPtr) {
	listPtr->headPtr = entryPtr->nextPtr;
	entryPtr->nextPtr->prevPtr = NULL;
    } else {
	entryPtr->prevPtr->nextPtr = entryPtr->nextPtr;
	entryPtr->nextPtr->prevPtr = entryPtr->prevPtr;
    }
    listPtr->numEntries--;
    free(entryPtr);
    return TCL_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * ClearList --
 *
 *	Removes all the entries from a list, removing pointers to the
 *	objects and keys (not the objects or keys themselves).
 *	The entry counter is reset to zero.
 *
 * Results:
 *	None.
 *
 *----------------------------------------------------------------------
 */
static void
ClearList(listPtr)
    LinkedList *listPtr;     /* List to clear */
{
    register ListEntry *oldPtr;
    register ListEntry *entryPtr = listPtr->headPtr;

    while (entryPtr != NULL) {
	oldPtr = entryPtr;
	entryPtr = entryPtr->nextPtr;
	ckfree((char *)oldPtr);
    }
    listPtr->numEntries = 0;
}

/*
 *----------------------------------------------------------------------
 *
 * FindListEntry --
 *
 *	Find the first entry (containing pointers to object key and data),
 *	using the given name as the key.
 *
 * Results:
 *	Returns the pointer to the object.  If no object matching
 *	the key given is found, then NULL is returned.
 *
 *----------------------------------------------------------------------
 */
static ClientData
FindListEntry(listPtr, name)
    LinkedList *listPtr;     /* List to search */
    char *name;		     /* Key to match */
{
    register ListEntry *entryPtr;
    char c = *name;

    for (entryPtr = listPtr->headPtr;
	 entryPtr != NULL; entryPtr = entryPtr->nextPtr) {
	if ((c == *entryPtr->keyPtr) && strcmp(name, entryPtr->keyPtr) == 0)
	    return (entryPtr->clientData);
    }
    return (NULL);
}

/*
 *----------------------------------------------------------------------
 *
 * FirstListEntry --
 *
 *	Find the first entry in the list and return the pointer to
 *	the data object.  In addition, update the given search pointer.
 *
 * Results:
 *	A pointer to the first object in the list is returned. If the
 *      list is empty, NULL is returned.  The search pointer (used in
 *	subsequent searches) is set to the appropriate value.
 *
 *----------------------------------------------------------------------
 */
static ClientData
FirstListEntry(listPtr, entryPtr)
    LinkedList *listPtr;     /* The list we are searching */
    ListEntry **entryPtr;    /* Search pointer to set */
{
    if (listPtr == NULL)
	return (NULL);
    *entryPtr = listPtr->headPtr;
    if (listPtr->headPtr == NULL)
	return (NULL);
    return (listPtr->headPtr->clientData);
}

/*
 *----------------------------------------------------------------------
 *
 * NextListEntry --
 *
 *	Find the next entry in the list using the given search pointer
 *	as the current location and return the pointer to
 *	its data object.  In addition, update the given search pointer.
 *
 * Results:
 *	A pointer to the next object in the list is returned. If the
 *      list is at end, NULL is returned.  The search pointer (used in
 *	subsequent searches) is set to the appropriate value.
 *
 *----------------------------------------------------------------------
 */
static ClientData
NextListEntry(entryPtr)
    ListEntry **entryPtr;    /* Search pointer indicates current position */
{
    if (entryPtr == NULL || *entryPtr == NULL)
	return (NULL);
    *entryPtr = (*entryPtr)->nextPtr;
    if (*entryPtr == NULL)
	return (NULL);
    return ((*entryPtr)->clientData);
}

/* ----------------------------------------------------------------------
 * Custom Option Procs
 * ----------------------------------------------------------------------
 */

/*
 *----------------------------------------------------------------------
 *
 * LimitParseProc --
 *
 *	Convert the string representation of an axis limit into its 
 *	numeric form.
 *
 * Results:
 *	The return value is a standard Tcl result.  The symbol type is
 *	written into the widget record.
 *
 *----------------------------------------------------------------------
 */
static int
LimitParseProc(clientData, interp, tkwin, value, widgRec, offset)
    ClientData clientData;   /* Default value for limit */
    Tcl_Interp *interp;	     /* Interpreter to send results back to */
    Tk_Window tkwin;	     /* not used */
    char *value;	     /* */
    char *widgRec;	     /* */
    int offset;		     /* */
{
    double *limitPtr = (double *)(widgRec + offset);

    if (NULLSTR(value)) {
	double absLimit = *(double *)clientData;

	*limitPtr = absLimit;
    } else {
	double newLimit;

	if (Tcl_ExprDouble(interp, value, &newLimit) != TCL_OK)
	    return TCL_ERROR;
	*limitPtr = newLimit;
    }
    return TCL_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * LimitParseProc --
 *
 *	Convert the floating point axis limit into a string.
 *
 * Results:
 *	The string representation fo the limit is returned.
 *
 *----------------------------------------------------------------------
 */
static char *
LimitPrintProc(clientData, tkwin, widgRec, offset, freeProcPtr)
    ClientData clientData;   /* Either -Inf or Inf */
    Tk_Window tkwin;	     /* not used */
    char *widgRec;	     /* */
    int offset;
    Tcl_FreeProc **freeProcPtr;
{
    double limit = *(double *)(widgRec + offset);
    double absLimit = *(double *)clientData;
    char *result;

    result = "";
    if (limit != absLimit) {
	char buf[80];

	sprintf(buf, "%g", limit);
	result = (char *)malloc(strlen(buf) + 1);
	if (result == NULL)
	    return "";
	*freeProcPtr = TCL_DYNAMIC;
	strcpy(result, buf);
    }
    return result;
}

static struct SymbolInfo {
    char *name;
    int value;

} symInfo[]= {

    "solid", SOLID_LINESTYLE,
    "dashed", DASHED_LINESTYLE,
    "dotted", DOTTED_LINESTYLE,
    "point", POINT_SYMBOL,
    "square", SQUARE_SYMBOL,
    "circle", CIRCLE_SYMBOL,
    "diamond", DIAMOND_SYMBOL,
    "plus", PLUS_SYMBOL,
    "cross", CROSS_SYMBOL
};
static int numSymbols = sizeof(symInfo) / sizeof(struct SymbolInfo);

/*
 *----------------------------------------------------------------------
 *
 * SymbolParseProc --
 *
 *	Convert the string representation of a line style or symbol name
 *	into its numeric form.
 *
 * Results:
 *	The return value is a standard Tcl result.  The symbol type is
 *	written into the widget record.
 *
 *----------------------------------------------------------------------
 */
static int
SymbolParseProc(clientData, interp, tkwin, value, widgRec, offset)
    ClientData clientData;   /* not used */
    Tcl_Interp *interp;	     /* Interpreter to send results back to */
    Tk_Window tkwin;	     /* not used */
    char *value;	     /* String representing symbol type */
    char *widgRec;	     /* Line information record */
    int offset;		     /* Offset of symbol type field in record */
{
    register char c;
    int *symbolPtr = (int *)(widgRec + offset);
    register int i;

    c = *value;
    for (i = 0; i < numSymbols; i++) {
	if (c == *(symInfo[i].name) && strcmp(value, symInfo[i].name) == 0) {
	    *symbolPtr = symInfo[i].value;
	    return TCL_OK;
	}
    }
    Tcl_AppendResult(interp, "Bad symbol name \"", value, "\"", NULL);
    return TCL_ERROR;
}

/*
 *----------------------------------------------------------------------
 *
 * NameOfSymbol --
 *
 *	Convert the symbol value into a string.
 *
 * Results:
 *	The string representing the symbol type or line style is returned.
 *
 *----------------------------------------------------------------------
 */
static char *
NameOfSymbol(symbol)
    int symbol;	
{
    register int i;

    for (i = 0; i < numSymbols; i++) {
	if (symbol == symInfo[i].value)
	    return (symInfo[i].name);
    }
    return NULL;
}

/*
 *----------------------------------------------------------------------
 *
 * SymbolParseProc --
 *
 *	Convert the symbol value into a string.
 *
 * Results:
 *	The string representing the symbol type or line style is returned.
 *
 *----------------------------------------------------------------------
 */
static char *
SymbolPrintProc(clientData, tkwin, widgRec, offset, freeProcPtr)
    ClientData clientData;   /* not used */
    Tk_Window tkwin;	     /* not used */
    char *widgRec;	     /* Line information record */
    int offset;		     /* Offset of symbol type field in record */
    Tcl_FreeProc **freeProcPtr;	/* not used */
{
    int symbol = *(int *)(widgRec + offset);

    return (NameOfSymbol(symbol));
}


/*
 *----------------------------------------------------------------------
 *
 * GetExprValue --
 *
 *	Convert the expression string into a double precision value.
 *	The only reason we use this routine instead of Tcl_ExprDouble
 *	is to handle *elastic* bounds.  That is, convert the strings
 *	"-Inf", "Inf" into NegativeInfinity, PositiveInfinity respectively.
 *	Under Sun's libc.a this is handled automatically.
 *
 * Results:
 *	The return value is a standard Tcl result.  The value of the
 *	expression is passed back via valuePtr.
 *
 *----------------------------------------------------------------------
 */
static int
GetExprValue(interp, expr, valuePtr)
    Tcl_Interp *interp;	     /* Interpreter to send results back to */
    char *expr;		     /* Numeric expression string to parse */
    double *valuePtr;	     /* Real-valued result of expression */
{
    if (Tcl_ExprDouble(interp, expr, valuePtr) != TCL_OK) {
	if (strcmp(expr, "-Inf") == 0) {
	    *valuePtr = NegativeInfinity;	/* Elastic lower bound */
	} else if (strcmp(expr, "Inf") == 0) {
	    *valuePtr = PositiveInfinity;	/* Elastic upper bound */
	} else {
	    Tcl_AppendResult(interp, "Bad expression \"", expr, "\"", NULL);
	    return TCL_ERROR;
	}
    }
    return TCL_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * GetExprString --
 *
 *	Convert the expression  double precision value into a string.
 *	The only reason we use this routine instead of sprintf
 *	is to handle *elastic* bounds.  That is, convert the strings
 *	NegativeInfinity, PositiveInfinity into "-Inf", "Inf" respectively.
 *
 * Results:
 *	The return value is a standard Tcl result.  The string of the
 *	expression is passed back via string.
 *
 *----------------------------------------------------------------------
 */
static int
GetExprString(value, string)
    double value;	     /* Expression value */
    char *string;	     /* String representation of value */
{
  if (value == PositiveInfinity) 
      strcpy (string, "Inf");
  else if (value == NegativeInfinity)
      strcpy (string, "-Inf");
  else 
      sprintf (string, "%g", value);
  return TCL_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * VectorParseProc --
 *
 *	Given a Tcl list of numeric expression representing the line
 *	values, convert into an array of double precision values. In
 *	addition, the minimum and maximum values are saved.  Since
 *	elastic values are allow (values which translate to the
 *	min/max of the graph), we must try to get the non-elastic
 *	(not +-Infinity) minimum and maximum.
 *
 * Results:
 *	The return value is a standard Tcl result.  The vector is passed
 *	back via the vecPtr.
 *
 *----------------------------------------------------------------------
 */
static int
VectorParseProc(clientData, interp, tkwin, value, widgRec, offset)
    ClientData clientData;   /* not used */
    Tcl_Interp *interp;	     /* Interpreter to send results back to */
    Tk_Window tkwin;	     /* not used */
    char *value;	     /* Tcl list of expressions */
    char *widgRec;	     /* Line information record */
    int offset;		     /* Offset of vector in Line structure */
{
    register int i;
    register double max, min;
    register Vector *vecPtr = (Vector *) (widgRec + offset);
    register double *valuePtr;
    int numExpr;
    char **exprArr = NULL;
    double *valueArr = NULL;
    int firstMin, firstMax;

    /* Split the list of expressions and check the values */
    if (Tcl_SplitList(interp, value, &numExpr, &exprArr) != TCL_OK) {
	return TCL_ERROR;
    }
    if (numExpr < 1) {
	interp->result = "Empty list of numeric expressions";
	goto error;
    } else if (numExpr >= 65535) {
	interp->result = "Vector is too large";	/* XDrawLines limit */
	goto error;
    }
    /* Allocate an array of doubles to hold the values */
    valueArr = (double *)ckalloc(numExpr * sizeof(double));

    if (valueArr == NULL) {
	Tcl_AppendResult(interp, "Can't allocate data vector", (char *)NULL);
	Tcl_SetErrorCode(interp, "UNIX", "malloc", sys_errlist[errno], NULL);
	goto error;
    }
    /*
     * Parse list of numeric expressions and and evaluate into an array
     * real-valued numbers and Track the minimum and maximum values for the
     * line which are not elastic (i.e. +/- Infinity)
     */
    firstMin = firstMax = TRUE;
    max = min = 0.0;

    for (valuePtr = valueArr, i = 0; i < numExpr; i++, valuePtr++) {
	if (GetExprValue(interp, exprArr[i], valuePtr) != TCL_OK)
	    goto error;
	if (*valuePtr != NegativeInfinity && *valuePtr != PositiveInfinity) {
	    if (firstMin) {
		min = *valuePtr;
		firstMin = FALSE;
	    } else if (*valuePtr < min) {
		min = *valuePtr;
	    }
	    if (firstMax) {
		max = *valuePtr;
		firstMax = FALSE;
	    } else if (*valuePtr > max) {
		max = *valuePtr;
	    }
	}
    }
    interp->result = "";
    ckfree((char *)exprArr);
    vecPtr->minValue = min, vecPtr->maxValue = max;
    if (vecPtr->valueArr != NULL)
	free((char *)vecPtr->valueArr);
    vecPtr->valueArr = valueArr;
    vecPtr->numValues = numExpr;
    return TCL_OK;

  error:
    /* Clean up, release allocated storage */
    if (exprArr)
	ckfree((char *)exprArr);
    if (valueArr)
	ckfree((char *)valueArr);
    return TCL_ERROR;
}

/*
 *----------------------------------------------------------------------
 *
 * VectorPrintProc --
 *
 *	Convert the vector of double precision values into a Tcl list.
 *
 * Results:
 *	The string representation of the vector is returned.
 *
 *----------------------------------------------------------------------
 */
static char *
VectorPrintProc(clientData, tkwin, widgRec, offset, freeProcPtr)
    ClientData clientData;   /* not used */
    Tk_Window tkwin;	     /* not used */
    char *widgRec;	     /* Line information record */
    int offset;		     /* Offset of vector in Line structure */
    Tcl_FreeProc **freeProcPtr;	/* Memory deallocation scheme to use */
{
    register Vector *vecPtr = (Vector *) (widgRec + offset);
    register int i;
    register char *elemPtr;
    char **stringArr;
    char *result;
    char buf[80];

    result = "";
    if (vecPtr->numValues == 0)
	return result;
#ifdef NO_ALLOCA
    stringArr = (char **)malloc(vecPtr->numValues * sizeof(char *));
#else
    stringArr = (char **)alloca(vecPtr->numValues * sizeof(char *));
#endif /* NO_ALLOCA */
    if (stringArr == NULL)
	return NULL;
    for (i = 0; i < vecPtr->numValues; i++) {
        GetExprString (vecPtr->valueArr[i], buf);
#ifdef NO_ALLOCA
	elemPtr = (char *)malloc(strlen(buf) + 1);
#else
	elemPtr = (char *)alloca(strlen(buf) + 1);
#endif /* NO_ALLOCA */
	stringArr[i] = elemPtr;
	if (elemPtr == NULL)
	    goto error;
	strcpy(elemPtr, buf);
    }
    result = Tcl_Merge(vecPtr->numValues, stringArr);
    *freeProcPtr = TCL_DYNAMIC;

  error:
#ifdef NO_ALLOCA
    for (i = 0; i < vecPtr->numValues; i++) {
	if (stringArr[i] == NULL)
	    break;
	free(stringArr[i]);
    }
    free((char *)stringArr);
#endif /* NO_ALLOCA */
    return (result);
}

/*
 *----------------------------------------------------------------------
 *
 * TwinVectorParseProc --
 *
 *	This procedure is like VectorParseProc except that it
 *	interprets the list of numeric expressions as X Y coordinate
 *	pairs.  The minimum and maximum for both the X and Y vectors are
 *	determined.
 *
 * Results:
 *	The return value is a standard Tcl result.  The vectors are passed
 *	back via the widget record (linePtr).
 *
 *----------------------------------------------------------------------
 */
static int
TwinVectorParseProc(clientData, interp, tkwin, value, widgRec, offset)
    ClientData clientData;   /* not used */
    Tcl_Interp *interp;	     /* Interpreter to send results back to */
    Tk_Window tkwin;	     /* not used */
    char *value;	     /* Tcl list of expressions */
    char *widgRec;	     /* Line information record */
    int offset;		     /* not used */
{
    register int i;
    register double *valuePtr;
    Line *linePtr = (Line *) widgRec;
    int numExpr;
    char **exprArr = NULL;
    double *xValueArr = NULL, *yValueArr = NULL;
    double min, max;
    int firstMin, firstMax;
    int arraySize;

    /* Split the list of numbers and check the values */
    if (Tcl_SplitList(interp, value, &numExpr, &exprArr) != TCL_OK) {
	return TCL_ERROR;
    }
    if (numExpr < 1) {
	interp->result = "Empty list of numeric expressions";
	goto error;
    } else if (numExpr >= 131070) {
	interp->result = "Vector is too large";	/* XDrawLines limit */
	goto error;
    } else if (numExpr & 1) {
	interp->result = "Odd number of values in -xydata option";
	goto error;
    }
    arraySize = numExpr / 2;
    /* Allocate an array of doubles to hold the values */
    xValueArr = (double *)ckalloc(arraySize * sizeof(double));

    if (xValueArr == NULL) {
	Tcl_AppendResult(interp, "Can't allocate X vector for ",
			 linePtr->name, (char *)NULL);
	Tcl_SetErrorCode(interp, "UNIX", "malloc", sys_errlist[errno], NULL);
	goto error;
    }
    /*
     * Parse list of numeric expressions and and evaluate into an array
     * real-valued numbers
     */
    firstMin = firstMax = TRUE;
    min = max = 0.0;
    for (valuePtr = xValueArr, i = 0; i < numExpr; i += 2, valuePtr++) {
	if (GetExprValue(interp, exprArr[i], valuePtr) != TCL_OK)
	    goto error;
	if (*valuePtr != NegativeInfinity && *valuePtr != PositiveInfinity) {
	    if (firstMin) {
		min = *valuePtr;
		firstMin = FALSE;
	    } else if (*valuePtr < min) {
		min = *valuePtr;
	    }
	    if (firstMax) {
		max = *valuePtr;
		firstMax = FALSE;
	    } else if (*valuePtr > max) {
		max = *valuePtr;
	    }
	}
    }
    linePtr->x.minValue = min;
    linePtr->x.maxValue = max;
    yValueArr = (double *)ckalloc(arraySize * sizeof(double));

    if (yValueArr == NULL) {
	Tcl_AppendResult(interp, "Can't allocate Y vector for ",
			 linePtr->name, (char *)NULL);
	Tcl_SetErrorCode(interp, "UNIX", "malloc", sys_errlist[errno], NULL);
	goto error;
    }
    /* Now parse and evaluate the Y values */
    firstMin = firstMax = TRUE;
    min = max = 0.0;
    for (valuePtr = yValueArr, i = 1; i < numExpr; i += 2, valuePtr++) {
	if (GetExprValue(interp, exprArr[i], valuePtr) != TCL_OK)
	    goto error;
	if (*valuePtr != NegativeInfinity && *valuePtr != PositiveInfinity) {
	    if (firstMin) {
		min = *valuePtr;
		firstMin = FALSE;
	    } else if (*valuePtr < min) {
		min = *valuePtr;
	    }
	    if (firstMax) {
		max = *valuePtr;
		firstMax = FALSE;
	    } else if (*valuePtr > max) {
		max = *valuePtr;
	    }
	}
    }
    linePtr->y.minValue = min;
    linePtr->y.maxValue = max;

    /* Save arrays and limits */
    linePtr->x.numValues = linePtr->y.numValues = arraySize;
    if (linePtr->x.valueArr != NULL)
	free((char *)linePtr->x.valueArr);
    linePtr->x.valueArr = xValueArr;
    if (linePtr->y.valueArr != NULL)
	free((char *)linePtr->y.valueArr);
    linePtr->y.valueArr = yValueArr;

    interp->result = "";
    ckfree((char *)exprArr);
    return TCL_OK;
  error:
    /* Clean up, release allocated storage */
    if (exprArr)
	ckfree((char *)exprArr);
    if (xValueArr)
	ckfree((char *)xValueArr);
    if (yValueArr)
	ckfree((char *)yValueArr);
    return TCL_ERROR;
}

/*
 *----------------------------------------------------------------------
 *
 * TwinVectorPrintProc --
 *
 *	Given a Tcl list of numeric expression representing the line
 *	values, convert into an array of double precision values, saving
 *	the high and low values found.
 *
 * Results:
 *	The return value is a standard Tcl result.  The vector is passed
 *	back via the vecPtr.
 *
 *----------------------------------------------------------------------
 */
static char *
TwinVectorPrintProc(clientData, tkwin, widgRec, offset, freeProcPtr)
    ClientData clientData;   /* not used */
    Tk_Window tkwin;	     /* not used */
    char *widgRec;	     /* Line information record */
    int offset;		     /* not used */
    Tcl_FreeProc **freeProcPtr;	/* Memory deallocation scheme to use */
{
    register Line *linePtr = (Line *) widgRec;
    register int i, cnt;
    char *elemPtr;
    char **stringArr;
    int arraySize;
    char *result;
    char buf[80];

    result = "";
    if (linePtr->x.numValues == 0 || linePtr->y.numValues == 0)
	return result;
    arraySize = linePtr->x.numValues + linePtr->y.numValues;
#ifdef NO_ALLOCA
    stringArr = (char **)malloc(arraySize * sizeof(char *));
#else
    stringArr = (char **)alloca(arraySize * sizeof(char *));
#endif /* NO_ALLOCA */

    if (stringArr == NULL)
	return NULL;
    for (cnt = i = 0; i < linePtr->x.numValues; i++) {
	GetExprString (linePtr->x.valueArr[i], buf);
#ifdef NO_ALLOCA
	elemPtr = (char *)malloc(strlen(buf) + 1);
#else
	elemPtr = (char *)alloca(strlen(buf) + 1);
#endif /* NO_ALLOCA */
	stringArr[cnt++] = elemPtr;
	if (elemPtr == NULL)
	    goto error;
	strcpy(elemPtr, buf);
	GetExprString (linePtr->y.valueArr[i], buf);
#ifdef NO_ALLOCA
	elemPtr = (char *)malloc(strlen(buf) + 1);
#else
	elemPtr = (char *)alloca(strlen(buf) + 1);
#endif /* NO_ALLOCA */
	stringArr[cnt++] = elemPtr;
	if (elemPtr == NULL)
	    goto error;
	strcpy(elemPtr, buf);
    }
    result = Tcl_Merge(arraySize, stringArr);
    *freeProcPtr = TCL_DYNAMIC;

  error:
#ifdef NO_ALLOCA
    for (i = 0; i < arraySize; i++) {
	if (stringArr[i] == NULL)
	    break;
	free(stringArr[i]);
    }
    free((char *)stringArr);
#endif /* NO_ALLOCA */
    return (result);
}

/*
 *----------------------------------------------------------------------
 *
 * LegendParseProc --
 *
 *	Convert the string representation of a legend XY position into
 *	screen coordinates.  The form of the string must be "@x,y" or
 *	none.
 *
 * Results:
 *	The return value is a standard Tcl result.  The symbol type is
 *	written into the widget record.
 *
 * Side Effects:
 *	If no legend position is given, the right margin of the graph
 *	will be automatically increased to hold the legend.
 *
 *----------------------------------------------------------------------
 */
static int
LegendParseProc(clientData, interp, tkwin, value, widgRec, offset)
    ClientData clientData;   /* not used */
    Tcl_Interp *interp;	     /* Interpreter to send results back to */
    Tk_Window tkwin;	     /* not used */
    char *value;	     /* New legend position string */
    char *widgRec;	     /* Graph widget record */
    int offset;		     /* Offset of legend in widget record */
{
    Legend *legendPtr = (Legend *) (widgRec + offset);
    int x, y;

    if (NULLSTR(value)) {
	legendPtr->usePosition = FALSE;
	return TCL_OK;
    }
    if (*value != '@' || sscanf(value + 1, "%d,%d", &x, &y) != 2) {
	Tcl_AppendResult(interp, "Bad position: should be \"@x,y\"", NULL);
	return TCL_ERROR;
    }
    legendPtr->usePosition = TRUE;
    legendPtr->x = x;
    legendPtr->y = y;
    return TCL_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * LegendPrintProc --
 *
 *	Convert the legend XY position into a string.
 *
 * Results:
 *	The string representing the legend position is returned.
 *
 *----------------------------------------------------------------------
 */
static char *
LegendPrintProc(clientData, tkwin, widgRec, offset, freeProcPtr)
    ClientData clientData;   /* not used */
    Tk_Window tkwin;	     /* not used */
    char *widgRec;	     /* Graph widget record */
    int offset;		     /* Offset of legend in widget record */
    Tcl_FreeProc **freeProcPtr;	/* Memory deallocation scheme to use */
{
    char *result;
    Legend *legendPtr = (Legend *) (widgRec + offset);

    result = "";
    if (legendPtr->usePosition) {
	char buf[80];

	sprintf(buf, "@%d,%d", legendPtr->x, legendPtr->y);
	result = (char *)malloc(strlen(buf) + 1);
	if (result == NULL)
	    return ("");
	strcpy(result, buf);
	*freeProcPtr = TCL_DYNAMIC;
    }
    return (result);
}

/*
 *----------------------------------------------------------------------
 *
 * ExprParseProc --
 *
 *	Convert the string representation of a floating point expression 
 *	into its double precision value.  The only difference here is
 *	that "Inf" and "-Inf" are translated into HUGE_VAL and -HUGE_VAL
 *	respectively.
 *
 * Results:
 *	The return value is a standard Tcl result.  The value  is
 *	written into the widget record.
 *
 *----------------------------------------------------------------------
 */
static int
ExprParseProc(clientData, interp, tkwin, value, widgRec, offset)
    ClientData clientData;   /* not used */
    Tcl_Interp *interp;	     /* Interpreter to send results back to */
    Tk_Window tkwin;	     /* not used */
    char *value;	     /* Floating point expression */
    char *widgRec;	     /* Widget record */
    int offset;		     /* Offset of double in widget record */
{
    double *resultPtr = (double *) (widgRec + offset);

    return (GetExprValue (interp, value, resultPtr));
}

/*
 *----------------------------------------------------------------------
 *
 * ExprPrintProc --
 *
 *	Convert the legend XY position into a string.
 *
 * Results:
 *	The string representing the legend position is returned.
 *
 *----------------------------------------------------------------------
 */
static char *
ExprPrintProc(clientData, tkwin, widgRec, offset, freeProcPtr)
    ClientData clientData;   /* not used */
    Tk_Window tkwin;	     /* not used */
    char *widgRec;	     /* Graph widget record */
    int offset;		     /* Offset of legend in widget record */
    Tcl_FreeProc **freeProcPtr;	/* Memory deallocation scheme to use */
{
    char *result;
    char buf [80];
    double value = *(double *)(widgRec + offset);

    GetExprString (value, buf);
    result = (char *)malloc(strlen(buf) + 1);
    if (result == NULL)
        return ("");
    strcpy(result, buf);
    *freeProcPtr = TCL_DYNAMIC;
    return (result);
}

/*
 * -----------------------------------------------------------------
 * General
 * -----------------------------------------------------------------
 */

INLINE static int
Quadrant(rotation)	     /* Compute quadrant */
    int rotation;
{
    rotation %= 360;
    if (rotation < 0)
	rotation += 360;
    return (rotation / 90);
}

/*
 * -----------------------------------------------------------------
 *
 * GetTextCoords --
 *
 * 	Translate the coordinates of a given text string based upon
 *	the anchor specified.  The anchor indicates where the given
 *	xy position are in relation to the text bounding box.
 *
 *  		nw --- n --- ne
 *  		|            |
 *  		w   center   e
 *  		|            |
 *  		sw --- s --- se
 *
 * 	The coordinates returned are translated to the baseline
 * 	origin of the text bounding box (suitable for giving to
 * 	XDrawString, XDrawText, etc).
 *
 * Results:
 *	The translated text coordinates are returned.
 *
 * -----------------------------------------------------------------
 */
static XPoint
GetTextCoords(fontPtr, text, x, y, anchor, quadrant)
    XFontStruct *fontPtr;    /* Font information */
    char *text;		     /* Text string */
    int x;		     /* X position of anchor */
    int y;		     /* Y position of anchor */
    Tk_Anchor anchor;	     /* Direction of the anchor */
    int quadrant;	     /* Quadrant of rotation  */
{
    register int width, height;
    XPoint pt;
    XCharStruct bbox;	     /* Bounding box for text string */
    int dummy;		     /* not used */

    /* Get the width and height of the text string to be created */
    XTextExtents(fontPtr, text, strlen(text), &dummy, &dummy, &dummy, &bbox);
    width = (bbox.rbearing - bbox.lbearing);
    height = (bbox.ascent + bbox.descent);

    pt.x = x, pt.y = y;
    switch (quadrant) {
    case ROTATE_0:
	switch (anchor) {
	case TK_ANCHOR_NW:
	    pt.y += bbox.ascent;
	    break;
	case TK_ANCHOR_W:
	    pt.y += (bbox.ascent - bbox.descent) / 2;
	    break;
	case TK_ANCHOR_SW:
	    pt.y -= bbox.descent;
	    break;
	case TK_ANCHOR_NE:
	    pt.x -= width;
	    pt.y += bbox.ascent;
	    break;
	case TK_ANCHOR_E:
	    pt.x -= width;
	    pt.y += (bbox.ascent - bbox.descent) / 2;
	    break;
	case TK_ANCHOR_SE:
	    pt.x -= width;
	    pt.y -= bbox.descent;
	    break;
	case TK_ANCHOR_N:
	    pt.y += bbox.ascent;
	    pt.x -= width / 2;
	    break;
	case TK_ANCHOR_S:
	    pt.y -= bbox.descent;
	    pt.x -= width / 2;
	    break;
	case TK_ANCHOR_CENTER:
	    pt.x -= width / 2;
	    pt.y += (bbox.ascent - bbox.descent) / 2;
	    break;
	}
	break;
    case ROTATE_90:
	switch (anchor) {
	case TK_ANCHOR_NW:
	    pt.x += bbox.ascent;
	    pt.y += width;
	    break;
	case TK_ANCHOR_W:
	    pt.x += bbox.ascent;
	    pt.y += width / 2;
	    break;
	case TK_ANCHOR_SW:
	    pt.x += bbox.ascent;
	    break;
	case TK_ANCHOR_N:
	    pt.x += (bbox.ascent - bbox.descent) / 2;
	    pt.y += width;
	    break;
	case TK_ANCHOR_CENTER:
	    pt.x += (bbox.ascent - bbox.descent) / 2;
	    pt.y += width / 2;
	    break;
	case TK_ANCHOR_S:
	    pt.x += (bbox.ascent - bbox.descent) / 2;
	    break;
	case TK_ANCHOR_NE:
	    pt.x -= bbox.descent;
	    pt.y += width;
	    break;
	case TK_ANCHOR_E:
	    pt.x -= bbox.descent;
	    pt.y += width / 2;
	    break;
	case TK_ANCHOR_SE:
	    pt.x -= bbox.descent;
	    break;
	}
	break;
    case ROTATE_180:
	switch (anchor) {
	case TK_ANCHOR_NW:
	    pt.x += width;
	    pt.y += bbox.descent;
	    break;
	case TK_ANCHOR_W:
	    pt.x += width;
	    pt.y += -(bbox.ascent - bbox.descent) / 2;
	    break;
	case TK_ANCHOR_SW:
	    pt.x += width;
	    pt.y += bbox.ascent;
	    break;
	case TK_ANCHOR_N:
	    pt.x += width / 2;
	    pt.y += bbox.descent;
	    break;
	case TK_ANCHOR_CENTER:
	    pt.x += width / 2;
	    pt.y -= (bbox.ascent - bbox.descent) / 2;
	    break;
	case TK_ANCHOR_S:
	    pt.x += width / 2;
	    pt.y += bbox.ascent;
	    break;
	case TK_ANCHOR_NE:
	    pt.y += bbox.descent;
	    break;
	case TK_ANCHOR_E:
	    pt.y -= (bbox.ascent - bbox.descent) / 2;
	    break;
	case TK_ANCHOR_SE:
	    pt.y += bbox.ascent;
	    break;
	}
	break;
    case ROTATE_270:
	switch (anchor) {
	case TK_ANCHOR_NW:
	    pt.x += bbox.descent;
	    break;
	case TK_ANCHOR_W:
	    pt.x += bbox.descent;
	    pt.y -= width / 2;
	    break;
	case TK_ANCHOR_SW:
	    pt.x += bbox.descent;
	    pt.y -= width;
	    break;
	case TK_ANCHOR_N:
	    pt.x -= (bbox.ascent - bbox.descent) / 2;
	    break;
	case TK_ANCHOR_CENTER:
	    pt.x -= (bbox.ascent - bbox.descent) / 2;
	    pt.y -= width / 2;
	    break;
	case TK_ANCHOR_S:
	    pt.x -= (bbox.ascent - bbox.descent) / 2;
	    pt.y -= width;
	    break;
	case TK_ANCHOR_NE:
	    pt.x -= bbox.ascent;
	    break;
	case TK_ANCHOR_E:
	    pt.x -= bbox.ascent;
	    pt.y -= width / 2;
	    break;
	case TK_ANCHOR_SE:
	    pt.x -= bbox.ascent;
	    pt.y -= width;
	    break;
	}
	break;
    }
    return (pt);
}

/*
 * -----------------------------------------------------------------
 *
 * GetBoxCoords --
 *
 * 	Translate the coordinates of a given bounding box based
 *	upon the anchor specified.  The anchor indicates where
 *	the given xy position is in relation to the bounding box.
 *
 *  		nw --- n --- ne
 *  		|            |
 *  		w   center   e
 *  		|            |
 *  		sw --- s --- se
 *
 * 	The coordinates returned are translated to the origin of the
 * 	bounding box (suitable for giving to XCopyArea, etc.)
 *
 * Results:
 *	The translated coordinates of the bounding box are returned.
 *
 * -----------------------------------------------------------------
 */
static XPoint
GetBoxCoords(x, y, width, height, anchor)
    int x;		     /* X screen coordinate of anchor */
    int y;		     /* Y screen coordinate of anchor */
    int width;		     /* Width of bounding box */
    int height;		     /* Height of bounding box */
    Tk_Anchor anchor;	     /* Direction of the anchor */
{
    XPoint pt;

    pt.x = x, pt.y = y;
    switch (anchor) {
    case TK_ANCHOR_NW:	     /* Upper left corner */
	break;
    case TK_ANCHOR_W:	     /* Left center */
	pt.y -= (height / 2);
	break;
    case TK_ANCHOR_SW:	     /* Lower left corner */
	pt.y -= height;
	break;
    case TK_ANCHOR_N:	     /* Top center */
	pt.x -= (width / 2);
	break;
    case TK_ANCHOR_CENTER:  /* Centered */
	pt.x -= (width / 2);
	pt.y -= (height / 2);
	break;
    case TK_ANCHOR_S:	     /* Bottom center */
	pt.x -= (width / 2);
	pt.y -= height;
	break;
    case TK_ANCHOR_NE:	     /* Upper right corner */
	pt.x -= width;
	break;
    case TK_ANCHOR_E:	     /* Right center */
	pt.x -= width;
	pt.y -= (height / 2);
	break;
    case TK_ANCHOR_SE:	     /* Lower right corner */
	pt.x -= width;
	pt.y -= height;
	break;
    }
    return (pt);
}

/*
 * -----------------------------------------------------------------
 *
 * RotateBitmap --
 *
 *	Create a new bitmap containing the rotated image of the given
 *	bitmap.  The only rotations currently allowed are 90 degree
 *	rotations.  We also need a special GC, so that we do not
 *	need to rotate more than one plane of the pixmap.
 *
 * Results:
 *	Returns a new bitmap containing the rotated image.
 *
 * -----------------------------------------------------------------
 */
static Pixmap
RotateBitmap(dpy, draw, bitmapGC, bitmap, w, h, quadrant)
    Display *dpy;	     /* X display */
    Drawable draw;	     /* Root window drawable */
    GC bitmapGC;	     /* GC created from bitmap where fg=1,bg=0 */
    Pixmap bitmap;	     /* Bitmap to be rotated */
    int w, h;		     /* Width and height of the bitmap */
    int quadrant;	     /* Right angle rotation to perform */
{
    XImage *src, *dest;
    Pixmap newBitmap;
    int bmWidth, bmHeight;
    register int dx, dy;
    register int x, y;

    /* Now create a bitmap and image to contain the rotated text */
    if (quadrant == ROTATE_90 || quadrant == ROTATE_270) {
	bmWidth = h, bmHeight = w;
    } else {
	bmWidth = w, bmHeight = h;
    }
    newBitmap = XCreatePixmap(dpy, draw, bmWidth, bmHeight, 1);
    src = XGetImage(dpy, bitmap, 0, 0, w, h, 1, ZPixmap);
    dest = XGetImage(dpy, newBitmap, 0, 0, bmWidth, bmHeight, 1, ZPixmap);
    for (x = 0; x < w; x++) {
	for (y = 0; y < h; y++) {
	    switch (quadrant) {
	    case ROTATE_90:
		dx = y, dy = w - x - 1;
		break;
	    case ROTATE_180:
		dx = w - x - 1, dy = h - y - 1;
		break;
	    case ROTATE_270:
		dx = h - y - 1, dy = x;
		break;
	    default:
	    case ROTATE_0:
		dx = x, dy = y;
		break;
	    }
	    XPutPixel(dest, dx, dy, XGetPixel(src, x, y));
	}
    }
    XPutImage(dpy, newBitmap, bitmapGC, dest, 0, 0, 0, 0, bmWidth, bmHeight);

    /* Clean up temporary resources used */
    XDestroyImage(src), XDestroyImage(dest);
    return (newBitmap);
}

/*-----------------------------------------------------------------
 * X-related drawing routines
 * -----------------------------------------------------------------*/

/*
 * -----------------------------------------------------------------
 *
 * DrawSymbol --
 *
 * 	Draw the symbol centered at the given xy screen coordinate
 *	based upon the line symbol type.
 *
 * Results:
 *	None.
 *
 * Problems:
 *	Most notable is the round-off errors generated when
 *	calculating the centered position of the symbol.
 * -----------------------------------------------------------------
 */
static void
DrawSymbol(linePtr, x, y)
    Line *linePtr;	     /* Symbol information */
    int x;		     /* X screen coordinate */
    int y;		     /* Y screen coordinate */
{
    register int dist = linePtr->symbolSize;
    Display *dpy;
    Drawable draw;
    register int radius;
    XPoint pts[5];

    radius = dist / 2;

    /* Get the display and drawable from the graph structure */
    dpy = Tk_Display(linePtr->parent->tkwin);
    draw = (Drawable) linePtr->parent->output;

    switch (linePtr->symbol) {
    case SOLID_LINESTYLE:
    case DOTTED_LINESTYLE:
    case DASHED_LINESTYLE:
	XDrawLine(dpy, draw, linePtr->gc, x - radius, y, x + radius, y);
	break;
    case CROSS_SYMBOL:
	XDrawLine(dpy, draw, linePtr->gc, x - radius, y - radius,
		  x + radius, y + radius);
	XDrawLine(dpy, draw, linePtr->gc, x - radius, y + radius,
		  x + radius, y - radius);
	break;
    case PLUS_SYMBOL:
	XDrawLine(dpy, draw, linePtr->gc, x - radius, y, x + radius, y);
	XDrawLine(dpy, draw, linePtr->gc, x, y - radius, x, y + radius);
	break;
    case SQUARE_SYMBOL:
	XFillRectangle(dpy, draw, linePtr->gc, x - radius, y - radius,
		       dist - 1, dist - 1);
	break;
    case CIRCLE_SYMBOL:
	XFillArc(dpy, draw, linePtr->gc, x - radius, y - radius,
		 dist, dist, 0, 23040);
	break;
    case DIAMOND_SYMBOL:
	pts[4].y = pts[0].y = pts[2].y = y;
	pts[1].x = pts[3].x = x;
	pts[4].x = pts[0].x = x - radius;
	pts[2].x = x + radius;
	pts[1].y = y - radius;
	pts[3].y = y + radius;
	XFillPolygon(dpy, draw, linePtr->gc, pts, 5, Convex,
		     CoordModeOrigin);
	break;
    case POINT_SYMBOL:
	XDrawPoint(dpy, draw, linePtr->gc, x, y);
	break;
    }
}

/*
 * -----------------------------------------------------------------
 *
 * DrawRotatedBitmap --
 *
 *	Draw a bitmap, using the the given screen coordinates
 *	as an anchor for the text bounding box.  In addition,
 *	consider orthogonal rotations.
 *
 * Results:
 *	None.
 *
 * Side Effects:
 *	Bitmap is drawn using the given font and GC on the graph
 *	window at the given coordinates, anchor, and rotation.
 * -----------------------------------------------------------------
 */
static void
DrawRotatedBitmap(graphPtr, bitmap, gc, w, h, x, y, rotation, anchor)
    Graph *graphPtr;	     /* Widget record */
    Pixmap bitmap;	     /* Text string to display */
    GC gc;		     /* Graphic context to use when drawing text */
    int w;		     /* */
    int h;		     /* */
    int x;		     /* Screen x coordinate */
    int y;		     /* Screen y coordinate */
    int rotation;	     /* Rotation of text string */
    Tk_Anchor anchor;	     /* Anchor of the rotated text string */
{
    Display *dpy;	     /* X display structure */
    Drawable draw;	     /* Window or pixmap to draw into */
    Pixmap newBitmap;	     /* Temporary pixmap to draw text string into */
    XGCValues gcValues;
    GC bitmapGC;	     /* Temporary GC for bitmaps */
    int bmHeight, bmWidth;   /* Bitmap width and height */
    XPoint newPt;	     /* Translated point based upon the anchor */
    int quadrant;	     /* Quadrant of rotation */

    quadrant = Quadrant(rotation);	/* Compute quadrant */
    if (quadrant == ROTATE_90 || quadrant == ROTATE_270) {
	bmWidth = h, bmHeight = w;
    } else {
	bmWidth = w, bmHeight = h;
    }
    draw = (Drawable) graphPtr->output;
    dpy = Tk_Display(graphPtr->tkwin);

    if (quadrant == ROTATE_0) {	/* No rotation. Handle simple case */
	newPt = GetBoxCoords(x, y, bmWidth, bmHeight, anchor);
	XCopyPlane(dpy, bitmap, draw, gc, 0, 0, bmWidth, bmHeight,
		   newPt.x, newPt.y, 1);
	return;
    }
    /* Create a temporary GC with a foreground pixel value of 0x01 */
    gcValues.foreground = 1, gcValues.background = 0;
    bitmapGC = XCreateGC(dpy, bitmap, (GCForeground | GCBackground),
			 &gcValues);

    newBitmap = RotateBitmap(dpy, draw, bitmapGC, bitmap, w, h, quadrant);
    newPt = GetBoxCoords(x, y, bmWidth, bmHeight, anchor);
    XCopyPlane(dpy, newBitmap, draw, gc, 0, 0, bmWidth, bmHeight,
	       newPt.x, newPt.y, 1);

    /* Clean up temporary resources used */
    XFreePixmap(dpy, newBitmap);
    XFreeGC(dpy, bitmapGC);
}

/*
 * -----------------------------------------------------------------
 *
 * DrawText --
 *
 *	Draw a text string, using the the given screen coordinates
 *	as an anchor for the text bounding box.
 *
 * Results:
 *	None.
 *
 * Side Effects:
 *	Text string is drawn using the given font and GC on the
 *	graph window at the given coordinates.
 * -----------------------------------------------------------------
 */
static void
DrawText(graphPtr, fontPtr, gc, text, x, y, anchor)
    Graph *graphPtr;	     /* Widget to draw into */
    XFontStruct *fontPtr;    /* Font to use */
    GC gc;		     /* Graphic context to use */
    char *text;		     /* Text string */
    int x;		     /* x position of text */
    int y;		     /* y position of text */
    Tk_Anchor anchor;	     /* Anchor of text string */
{
    XPoint newPt;

    newPt = GetTextCoords(fontPtr, text, x, y, anchor, ROTATE_0, NULL);
    XDrawString(Tk_Display(graphPtr->tkwin), (Drawable) graphPtr->output,
		gc, newPt.x, newPt.y, text, strlen(text));
}

/*
 * -----------------------------------------------------------------
 *
 * DrawRotatedText --
 *
 *	Draw a text string, using the the given screen coordinates
 *	as an anchor for the text bounding box.  In addition,
 *	consider orthogonal rotations.
 *
 * Results:
 *	None.
 *
 * Side Effects:
 *	Text string is drawn using the given font and GC on the
 *	graph window at the given coordinates, anchor, and rotation
 * -----------------------------------------------------------------
 */
static void
DrawRotatedText(graphPtr, fontPtr, gc, text, x, y, rotation, anchor)
    Graph *graphPtr;	     /* Widget record */
    XFontStruct *fontPtr;    /* Font to use when calculating text bbox */
    GC gc;		     /* Graphic context to use when drawing text */
    char *text;		     /* Text string to display */
    int x;		     /* Screen x coordinate */
    int y;		     /* Screen y coordinate */
    int rotation;	     /* Rotation of text string */
    Tk_Anchor anchor;	     /* Anchor of the rotated text string */
{
    int w, h;		     /* Width and height of text bounding box */
    Pixmap textBitmap;	     /* Temporary pixmap to draw text string into */
    Pixmap newBitmap;	     /* Newly rotated pixmap */
    XGCValues gcValues;
    unsigned long valueMask;
    GC bitmapGC;
    int rotHeight, rotWidth; /* Rotated bitmap width and height */
    XCharStruct bbox;	     /* Bounding box for text string */
    int dummy;		     /* not used */
    int numChar;	     /* Size of text string */
    XPoint newPt;	     /* Translated point based upon the anchor */
    int quadrant;	     /* Quadrant of rotation */
    Drawable draw = (Drawable) graphPtr->output;
    Display *dpy = Tk_Display(graphPtr->tkwin);

    if (NULLSTR(text))	     /* Null string, do nothing */
	return;
    numChar = strlen(text);

    quadrant = Quadrant(rotation);	/* Compute quadrant */
    if (quadrant == ROTATE_0) {	/* No rotation. Handle simple case */
	newPt = GetTextCoords(fontPtr, text, x, y, anchor, ROTATE_0, NULL);
	XDrawImageString(dpy, draw, gc, newPt.x, newPt.y, text, numChar);
	return;
    }
    /* Get the width and height of the text string to be created */
    XTextExtents(fontPtr, text, numChar, &dummy, &dummy, &dummy, &bbox);
    w = (bbox.rbearing - bbox.lbearing);
    h = (bbox.ascent + bbox.descent);

    /* Create temporary bitmap to draw the text string into */
    textBitmap = XCreatePixmap(dpy, draw, w, h, 1);

    /* Create a temporary GC with a foreground pixel value of 0x01 */
    gcValues.font = fontPtr->fid;
    gcValues.foreground = gcValues.background = 0;
    valueMask = GCFont | GCForeground | GCBackground;
    bitmapGC = XCreateGC(dpy, textBitmap, valueMask, &gcValues);
    XFillRectangle(dpy, textBitmap, bitmapGC, 0, 0, w, h);
    XSetForeground(dpy, bitmapGC, 1);

    /* Draw the text string into the bitmap */
    XDrawString(dpy, textBitmap, bitmapGC, -bbox.lbearing, bbox.ascent, text,
		numChar);
    /* Now create a rotated bitmap after determining its size */
    if (quadrant == ROTATE_90 || quadrant == ROTATE_270) {
	rotWidth = h, rotHeight = w;
    } else {
	rotWidth = w, rotHeight = h;
    }
    newBitmap = RotateBitmap(dpy, draw, bitmapGC, textBitmap, w, h, quadrant);
    /* Adjust x and y positions for bounding box dimensions */
    newPt = GetBoxCoords(x, y, rotWidth, rotHeight, anchor);
    XCopyPlane(dpy, newBitmap, draw, gc, 0, 0, rotWidth, rotHeight,
	       newPt.x, newPt.y, 1);

    /* Clean up temporary resources used */
    XFreePixmap(dpy, newBitmap);
    XFreePixmap(dpy, textBitmap);
    XFreeGC(dpy, bitmapGC);
}

/*
 *--------------------------------------------------------------
 *
 * EventuallyRedraw --
 *
 *	If the window is mapped and no other redraw request has been
 *	made, tell the Tk dispatcher to call the graph display routine.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	If window is eventually redisplayed.
 *
 *--------------------------------------------------------------
 */
static void
EventuallyRedraw(graphPtr)
    Graph *graphPtr;	     /* Graph widget record */
{
    if (Tk_IsMapped(graphPtr->tkwin)
	&& (graphPtr->flags & REDRAW_PENDING) == 0) {
	Tk_DoWhenIdle(DisplayGraph, (ClientData) graphPtr);
	graphPtr->flags |= REDRAW_PENDING;
    }
}

/*
 *--------------------------------------------------------------
 *
 * GraphEventProc --
 *
 *	This procedure is invoked by the Tk dispatcher for various
 *	events on graphs.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	When the window gets deleted, internal structures get
 *	cleaned up.  When it gets exposed, the graph is eventually
 *	redisplayed.
 *
 *--------------------------------------------------------------
 */
static void
GraphEventProc(clientData, eventPtr)
    ClientData clientData;   /* Graph widget record */
    register XEvent *eventPtr;	/* Event which triggered call to routine */
{
    register Graph *graphPtr = (Graph *) clientData;

    switch (eventPtr->type) {
    case Expose:
	if (eventPtr->xexpose.count == 0)
	    EventuallyRedraw(graphPtr);
	break;
    case DestroyNotify:
	Tcl_DeleteCommand(graphPtr->interp, Tk_PathName(graphPtr->tkwin));
	graphPtr->tkwin = NULL;
	if (graphPtr->flags & REDRAW_PENDING)
	    Tk_CancelIdleCall(DisplayGraph, (ClientData) graphPtr);
	Tk_EventuallyFree((ClientData) graphPtr, DestroyGraph);
	break;
    case ConfigureNotify:
	graphPtr->flags |= LAYOUT_NEEDED;
	EventuallyRedraw(graphPtr);
	break;
    }
}

/*
 *----------------------------------------------------------------------
 *
 * CreateLine --
 *
 *	This procedure creates and initializes a new line.
 *
 * Results:
 *	The return value is a pointer to a structure describing
 *	the new line.  If an error occurred, then the return
 *	value is NULL and an error message is left in interp->result.
 *
 * Side effects:
 *	Memory is allocated, etc.
 *
 *----------------------------------------------------------------------
 */
static Line *
CreateLine(graphPtr, lineName)
    Graph *graphPtr;	     /* Graph widget record */
    char *lineName;	     /* Name to associate with new line */
{
    Line *newPtr;	     /* Newly create line */
    Line *linePtr;	     /* */
    int nameSize;	     /* Length of name string */

    /* Reuse existing entries */
    linePtr = (Line *) FindListEntry(&(graphPtr->allLines), lineName);
    if (linePtr != NULL) {
	linePtr->isVisible = TRUE;
	return (linePtr);
    }
    newPtr = (Line *) calloc(1, sizeof(Line));
    if (newPtr == NULL)
	return (NULL);

    newPtr->parent = graphPtr;
    nameSize = strlen(lineName) + 1;
    newPtr->name = (char *)malloc(nameSize);
    strcpy(newPtr->name, lineName);
    newPtr->label = (char *)malloc(nameSize);
    strcpy(newPtr->label, lineName);
    newPtr->isVisible = TRUE;

    /*
     * Append the new line to both the line and visible line lists. By
     * default, all new lines are visible.
     */
    CreateListEntry(&(graphPtr->allLines), newPtr->name, newPtr);
    CreateListEntry(&(graphPtr->drawnLines), newPtr->name, newPtr);
    return (newPtr);
}

/*
 *----------------------------------------------------------------------
 *
 * DestroyLine --
 *
 *	This procedure is invoked by Tk_EventuallyFree or Tk_Release
 *	to clean up the internal structure of a line at a safe time
 *	(when no-one is using it anymore).
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Everything associated with the line is freed up.
 *
 *----------------------------------------------------------------------
 */
static void
DestroyLine(linePtr)
    Line *linePtr;
{
    if (linePtr->label != NULL)
	ckfree(linePtr->label);
    if (linePtr->name != NULL)
	ckfree(linePtr->name);
    if (linePtr->stipple != None)
	Tk_FreeBitmap(linePtr->stipple);
    if (linePtr->fgColor != NULL)
	Tk_FreeColor((XColor *) linePtr->fgColor);
    if (linePtr->bgColor != NULL)
	Tk_FreeColor((XColor *) linePtr->bgColor);
    if (linePtr->gc != None)
	Tk_FreeGC(linePtr->gc);
    if (linePtr->x.valueArr != NULL)
	ckfree((char *)linePtr->x.valueArr);
    if (linePtr->y.valueArr != NULL)
	ckfree((char *)linePtr->y.valueArr);
    free((char *)linePtr);
}

/*
 *----------------------------------------------------------------------
 *
 * ConfigureLine --
 *
 *	This procedure is called to process an argv/argc list, plus
 *	the Tk option database, in order to configure (or
 *	reconfigure) one line in a graph.
 *
 * Results:
 *	The return value is a standard Tcl result.  If TCL_ERROR is
 *	returned, then interp->result contains an error message.
 *
 * Side effects:
 *	Configuration information such as label and accelerator get
 *
 *----------------------------------------------------------------------
 */
static int
ConfigureLine(interp, linePtr, argc, argv, flags)
    Tcl_Interp *interp;
    register Line *linePtr;
    int argc;
    char **argv;
    int flags;
{
    GC newGC;
    XGCValues gcValues;
    unsigned int valueMask;
    Graph *graphPtr = linePtr->parent;
    Tk_Window tkwin = graphPtr->tkwin;

    if (Tk_ConfigureWidget(interp, tkwin, lineConfigSpecs, argc, argv,
			   (char *)linePtr, flags) != TCL_OK)
	return TCL_ERROR;

    gcValues.foreground = linePtr->fgColor->pixel;
    valueMask = GCForeground;
    if (graphPtr->type == XYGRAPH_TYPE) {
	gcValues.cap_style = CapRound;
	gcValues.join_style = JoinRound;
	gcValues.line_style = LineSolid;
	gcValues.dash_offset = 0;
	gcValues.line_width = linePtr->lineWidth;
	valueMask |= (GCLineWidth | GCLineStyle | GCCapStyle | GCJoinStyle);
	if (linePtr->symbol == DASHED_LINESTYLE) {
	    gcValues.line_style = LineOnOffDash;
	    gcValues.dashes = 7;
	    valueMask |= (GCDashList | GCDashOffset);
	} else if (linePtr->symbol == DOTTED_LINESTYLE) {
	    gcValues.line_style = LineOnOffDash;
	    gcValues.dashes = 2;
	    valueMask |= (GCDashList | GCDashOffset);
	}
    } else {
	linePtr->symbol = SQUARE_SYMBOL;	/* Use square for bar/pie
						 * charts */
	if (linePtr->stipple != None) {
	    gcValues.stipple = linePtr->stipple;
	    gcValues.fill_style = FillOpaqueStippled;
	    valueMask |= (GCStipple | GCFillStyle);
	}
	/* Patterns can have an individual background color */
	gcValues.background = linePtr->bgColor->pixel;
	valueMask |= GCBackground;
    }
    newGC = Tk_GetGC(tkwin, valueMask, &gcValues);
    if (linePtr->gc != None)
	Tk_FreeGC(linePtr->gc);
    linePtr->gc = newGC;
    return TCL_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * DeleteLine --
 *
 *	This procedure is called to delete the line whose name
 *	is given.  If the line name is not found, processing stops
 *	and an error message is returned via interp->result.
 *
 * Results:
 *	The return value is a standard Tcl result.  If TCL_ERROR is
 *	returned, then interp->result contains an error message.
 *
 * Side effects:
 *	Line attributes (GCs, colors, patterns, etc) get destroyed.
 *	Graph is redrawn if a deleted line was currently visible.
 *
 *----------------------------------------------------------------------
 */
static int
DeleteLine(interp, graphPtr, lineName, redrawFlag)
    Tcl_Interp *interp;
    Graph *graphPtr;
    char *lineName;
    int *redrawFlag;
{
    Line *linePtr;

    *redrawFlag = FALSE;
    linePtr = (Line *) FindListEntry(&(graphPtr->allLines), lineName);
    if (linePtr == NULL) {
	Tcl_AppendResult(interp, "Can't find \"", lineName, "\"", NULL);
	return TCL_ERROR;
    }
    DeleteListEntry(&(graphPtr->allLines), lineName);
    if (linePtr->isVisible) {
	DeleteListEntry(&(graphPtr->drawnLines), lineName);
	*redrawFlag = TRUE;
    }
    DestroyLine(linePtr);
    return TCL_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * CreateTag --
 *
 *	This procedure creates and initializes a new tag.
 *
 * Results:
 *	The return value is a pointer to a structure describing
 *	the new tag.  If an error occurred, then the return
 *	value is NULL and an error message is left in interp->result.
 *
 * Side effects:
 *	Memory is allocated, etc.
 *
 *----------------------------------------------------------------------
 */
static Tag *
CreateTag(graphPtr, tagName, x, y)
    Graph *graphPtr;
    char *tagName;
    double x, y;
{
    Tag *newPtr;
    Tag *tagPtr;

    /* Reuse existing entries */
    tagPtr = (Tag *) FindListEntry(&(graphPtr->tags), tagName);
    if (tagPtr != NULL) {
	tagPtr->x = x, tagPtr->y = y;
	return (tagPtr);
    }
    newPtr = (Tag *) calloc(1, sizeof(Tag));
    if (newPtr == NULL) {
	Tcl_AppendResult(graphPtr->interp, "Can't allocate new tag", NULL);
	Tcl_SetErrorCode(graphPtr->interp, "UNIX", "calloc",
			 sys_errlist[errno], NULL);
	return (NULL);
    }
    newPtr->name = (char *)malloc(strlen(tagName) + 1);
    strcpy(newPtr->name, tagName);
    newPtr->x = x, newPtr->y = y;
    CreateListEntry(&(graphPtr->tags), newPtr->name, newPtr);
    return (newPtr);
}

/*
 *----------------------------------------------------------------------
 *
 * DestroyTag --
 *
 *	This procedure is invoked by Tk_EventuallyFree or Tk_Release
 *	to clean up the internal structure of a tag at a safe time
 *	(when no-one is using it anymore).
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Everything associated with the tag is freed up.
 *
 *----------------------------------------------------------------------
 */
static void
DestroyTag(tagPtr)
    Tag *tagPtr;
{
    if (tagPtr->text)	     /* text */
	ckfree(tagPtr->text);
    if (tagPtr->name)	     /* name */
	ckfree(tagPtr->name);
    free((char *)tagPtr);
}

/*
 *----------------------------------------------------------------------
 *
 * ConfigureTag --
 *
 *	This procedure is called to process an argv/argc list, plus
 *	the Tk option database, in order to configure (or
 *	reconfigure) one tag in a graph.
 *
 * Results:
 *	The return value is a standard Tcl result.  If TCL_ERROR is
 *	returned, then interp->result contains an error message.
 *
 * Side effects:
 *	Configuration information is set.
 *
 *----------------------------------------------------------------------
 */
static int
ConfigureTag(interp, graphPtr, tagPtr, argc, argv, flags)
    Tcl_Interp *interp;
    Graph *graphPtr;
    register Tag *tagPtr;
    int argc;
    char **argv;
    int flags;
{
    GC newGC;
    XGCValues gcValues;
    unsigned int valueMask;

    if (Tk_ConfigureWidget(interp, graphPtr->tkwin, tagConfigSpecs,
			   argc, argv, (char *)tagPtr, flags) != TCL_OK)
	return TCL_ERROR;

    gcValues.foreground = tagPtr->fgColor->pixel;
    gcValues.background = tagPtr->bgColor->pixel;
    gcValues.font = tagPtr->fontPtr->fid;
    valueMask = (GCForeground | GCBackground | GCFont);
    newGC = Tk_GetGC(graphPtr->tkwin, valueMask, &gcValues);
    if (tagPtr->gc != None)
	Tk_FreeGC(tagPtr->gc);
    tagPtr->gc = newGC;
    return TCL_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * DeleteTag --
 *
 *	This procedure is called to delete the tag whose name
 *	is given.  If the tag name is not found, processing stops
 *	and an error message is returned via interp->result.
 *
 * Results:
 *	The return value is a standard Tcl result.  If TCL_ERROR is
 *	returned, then interp->result contains an error message.
 *
 * Side effects:
 *	Tag attributes (GCs, colors, patterns, etc) get destroyed.
 *	Graph is redrawn if a deleted tag was currently visible.
 *
 *----------------------------------------------------------------------
 */
static int
DeleteTag(interp, graphPtr, tagName, redrawFlag)
    Tcl_Interp *interp;
    Graph *graphPtr;
    char *tagName;
    int *redrawFlag;
{
    Tag *tagPtr;

    *redrawFlag = FALSE;
    tagPtr = (Tag *) FindListEntry(&(graphPtr->tags), tagName);
    if (tagPtr == NULL) {
	Tcl_AppendResult(interp, "Can't find a tag named \"", tagName,
			 "\"", NULL);
	return TCL_ERROR;
    }
    *redrawFlag = TRUE;
    DeleteListEntry(&(graphPtr->tags), tagName);
    DestroyTag(tagPtr);
    return TCL_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * GetLineNames --
 *
 *	Runs through the given list of line entries and builds a
 *	Tcl list of line names.  This procedure is used in the
 *	"names" and "show" commands.
 *
 * Results:
 *	The return value is a standard Tcl result.
 *	interp->result contains the list of line names.
 *
 *----------------------------------------------------------------------
 */
static int
GetLineNames(interp, listPtr)
    Tcl_Interp *interp;
    LinkedList *listPtr;
{
    register Line *linePtr;
    ListEntry *searchId;

    for (linePtr = (Line *) FirstListEntry(listPtr, &searchId);
	 linePtr != NULL; linePtr = (Line *) NextListEntry(&searchId)) {
	Tcl_AppendElement(interp, linePtr->name, FALSE);
    }
    return TCL_OK;
}

/*
 * -----------------------------------------------------------------
 *
 * GetDataExtents --
 *
 * Find the limits of the data, minimum and maximum values for both
 * the X and Y axes.  Also determine the most points required to
 * plot any one line.
 *
 * -----------------------------------------------------------------
 */
static void
GetDataExtents(graphPtr)
    Graph *graphPtr;
{
    register Line *linePtr;
    int numValues;
    int maxValues;
    int firstXmin, firstXmax, firstYmin, firstYmax;
    double xmin, xmax, ymin, ymax;
    ListEntry *searchId;

    maxValues = -1;
    firstXmin = firstXmax = firstYmin = firstYmax = TRUE;
    xmin = xmax = ymin = ymax = 0.0;	/* Suppress compiler warning */

    for (linePtr = (Line *) FirstListEntry(&(graphPtr->drawnLines), &searchId);
	 linePtr != NULL; linePtr = (Line *) NextListEntry(&searchId)) {
	if (linePtr->x.numValues > 0) {
	    if (linePtr->x.minValue != NegativeInfinity) {
		if (firstXmin) {
		    xmin = linePtr->x.minValue;
		    firstXmin = FALSE;
		} else if (xmin > linePtr->x.minValue) {
		    xmin = linePtr->x.minValue;
		}
	    }
	    if (linePtr->x.maxValue != PositiveInfinity) {
		if (firstXmax) {
		    xmax = linePtr->x.maxValue;
		    firstXmax = FALSE;
		} else if (xmax < linePtr->x.maxValue) {
		    xmax = linePtr->x.maxValue;
		}
	    }
	}
	if (linePtr->y.numValues > 0) {
	    if (linePtr->y.minValue != NegativeInfinity) {
		if (firstYmin) {
		    ymin = linePtr->y.minValue;
		    firstYmin = FALSE;
		} else if (ymin > linePtr->y.minValue) {
		    ymin = linePtr->y.minValue;
		}
	    }
	    if (linePtr->y.maxValue != PositiveInfinity) {
		if (firstYmax) {
		    ymax = linePtr->y.maxValue;
		    firstYmax = FALSE;
		} else if (ymax < linePtr->y.maxValue) {
		    ymax = linePtr->y.maxValue;
		}
	    }
	}
	numValues = MIN(linePtr->x.numValues, linePtr->y.numValues);
	if (maxValues < numValues)
	    maxValues = numValues;
    }
    /* Set artificial limits for non-limits */
    if (firstXmin)
	xmin = -1.0;
    if (firstXmax)
	xmax = 1.0;
    if (firstYmin)
	ymin = -1.0;
    if (firstYmax)
	ymax = 1.0;

    /*
     * Set both the X and Y axis limits. If the user has requested limits,
     * use those; otherwise the limits will be based on the data to be
     * plotted.
     */
    graphPtr->X.minLimit = ((graphPtr->X.reqMinimum == NegativeInfinity)
			    ? xmin : graphPtr->X.reqMinimum);
    graphPtr->X.maxLimit = ((graphPtr->X.reqMaximum == PositiveInfinity)
			    ? xmax : graphPtr->X.reqMaximum);
    graphPtr->Y.minLimit = ((graphPtr->Y.reqMinimum == NegativeInfinity)
			    ? ymin : graphPtr->Y.reqMinimum);
    graphPtr->Y.maxLimit = ((graphPtr->Y.reqMaximum == PositiveInfinity)
			    ? ymax : graphPtr->Y.reqMaximum);
    graphPtr->maxValues = maxValues;
}

/*
 * -----------------------------------------------------------------
 *
 * CalculateAxisLayout --
 *
 * Fill the Axis structure with the necessary information to
 * draw the axes.  Create a phony range when min equals max.
 *
 * Autoscale:
 *   This is the default behavior.
 *   Find the smallest number of units which contain the range of
 *   values.  The minimum and maximum major tick values will be
 *   represent the range of values for the axis. This greatest
 *   number of major ticks possible is 10.
 *
 * Manual Scaling:
 *   Make the minimum and maximum data values the represent the
 *   range of the values for the axis.  The minimum and maximum
 *   major ticks will be inclusive of this range.  This provides
 *   the largest area for plotting and the expected results when
 *   the axis min and max values have be set by the user (.e.g zooming).
 *   The maximum number of major ticks is 20.
 *
 *   For log scale, there is always the possibility that the minimum
 *   and maximum data values are the same magnitude.  To represent
 *   the points properly, at least one full decade should be shown.
 *   However, if you zoom a log scale plot, the results should be
 *   predictable. Therefore, in that case, show only minor ticks.
 *   Lastly, there should be an appropriate way to handle numbers <=0.
 *
 *          maxY
 *            |    units = magnitude (of least significant digit)
 *            |    high  = largest unit tick < max axis value
 *      high _|    low   = smallest unit tick > min axis value
 *            |
 *            |    range = high - low
 *            |    # ticks = greatest factor of range/units
 *           _|
 *        U   |
 *        n   |
 *        i   |
 *        t  _|
 *            |
 *            |
 *            |
 *       low _|
 *            |
 *            |_minX________________maxX__
 *            |   |       |      |       |
 *     minY  low                        high
 *           minY
 *
 *
 * numTicks = Number of ticks
 * minValue = Minimum value of axis
 * maxValue = Maximum value of axis
 * range    = Range of values (maxValue - minValue)
 * -----------------------------------------------------------------
 */
static void
CalculateAxisLayout(axisPtr)
    Axis *axisPtr;
{
    double temp, min, max;

    min = axisPtr->minLimit;
    max = axisPtr->maxLimit;

    if (max < min) {
	/* Swap min and max */
	temp = max, max = min, min = temp;
    } else if (min == max) {
	/* Set artificial min and max */
	min = (min * 0.9) - 1.0;
	max = (max * 1.1) + 1.0;
    }
    if (axisPtr->logScale) {
	/*
	 * If the range of values in less than or equal to zero, taking the
	 * log will fail.  Try to do the approximation, by using asinh.
	 * Caveat Emptor.
	 */
	double imin, imax;

	if (min <= 0.0) {
	    imin = floor(log10((min + sqrt(1 + (min * min))) / 2));
	    imax = ceil(log10((max + sqrt(1 + (max * max))) / 2));
	} else {
	    imin = floor(log10(min)), imax = ceil(log10(max));
	}
	if (imax == imin)
	    ++imax;
	axisPtr->minLimit = imin;
	axisPtr->maxLimit = imax;
	axisPtr->major.numSteps = (imax - imin) + 1;
	axisPtr->major.stepSize = 1.0;
	axisPtr->range = axisPtr->maxLimit - axisPtr->minLimit;
	axisPtr->minor.numSteps = 10;
	axisPtr->minor.low = axisPtr->major.low = axisPtr->minLimit;
	axisPtr->minor.high = axisPtr->major.high = axisPtr->maxLimit;
	return;
    } else {
	double maxTick, minTick;
	double units;
	double range;
	int numTicks;
	double newMin, newMax;

	if (axisPtr->major.numSteps <= 0) {
	    return;
	}
	range = max - min;
	if ((axisPtr->reqStepSize > 0.0) && (axisPtr->reqStepSize < range)) {
	    units = axisPtr->reqStepSize;
	} else {
	    units = exp10(floor(log10(range)));
	}
#ifdef notdef
	fprintf(stderr, "units=%.15g\n", units);
#endif
	if (axisPtr->reqMinimum != NegativeInfinity) {
	    minTick = CEIL(min, units);
	    newMin = min;
	} else {
	    minTick = FLOOR(min, units);
	    newMin = minTick;
	}
	if (axisPtr->reqMaximum != PositiveInfinity) {
	    maxTick = FLOOR(max, units);
	    newMax = max;
	} else {
	    maxTick = CEIL(max, units);
	    newMax = maxTick;
	}
	/* This happens only when either min and/or max is predefined */
	if (minTick >= maxTick) {
	    units /= 10.0;
	    maxTick = FLOOR(max, units);
	    minTick = CEIL(min, units);
	}
	range = (newMax - newMin);
	numTicks = (int)rint((maxTick - minTick) / units) + 1;
#ifdef notdef
	fprintf(stderr, "min/max=(%g,%g),lo/hi=(%g,%g),numTicks=%d,\
range=%g,units=%.15g\n", min, max, minTick, maxTick, numTicks, range, units);
#endif
	axisPtr->minLimit = newMin;
	axisPtr->maxLimit = newMax;

	/* Still possible to get -0, add 0.0 to clear sign bit */
	axisPtr->major.low = minTick + 0.0;
	axisPtr->major.high = maxTick + 0.0;

	axisPtr->major.stepSize = units;
	axisPtr->major.numSteps = numTicks;
	axisPtr->range = (newMax - newMin);
	if (axisPtr->minor.numSteps > 0)
	    units /= (double)(axisPtr->minor.numSteps);
	axisPtr->minor.stepSize = units;
	if (axisPtr->reqMinimum != NegativeInfinity) {
	    minTick = CEIL(min, units);
	} else {
	    minTick = axisPtr->major.low;
	}
	if (axisPtr->reqMaximum != PositiveInfinity) {
	    maxTick = FLOOR(max, units);
	} else {
	    maxTick = axisPtr->major.high;
	}
	axisPtr->minor.high = maxTick + 0.0;
	axisPtr->minor.low = minTick + 0.0;
    }
}

/*
 * -----------------------------------------------------------------
 *
 * ConfigureXAxis --
 *
 * -----------------------------------------------------------------
 */
static void
ConfigureXAxis(graphPtr)
    Graph *graphPtr;
{
    Axis *axisPtr = &(graphPtr->X);
    int numLines = graphPtr->drawnLines.numEntries;

    if (graphPtr->type == BARCHART_TYPE) {
	axisPtr->minLimit = 0.0;
	axisPtr->range = axisPtr->maxLimit = (numLines + 1.0);
	if (axisPtr->major.numSteps > 0)
	    axisPtr->major.numSteps = numLines;
	axisPtr->major.low = 1.0;
	axisPtr->major.high = (double)numLines;
	axisPtr->minor.numSteps = 0;
    } else {
	CalculateAxisLayout(axisPtr);
    }
}

/*
 * -----------------------------------------------------------------
 *
 * ConfigureYAxis --
 *
 * -----------------------------------------------------------------
 */
static void
ConfigureYAxis(graphPtr)
    Graph *graphPtr;
{
    Axis *axisPtr = &(graphPtr->Y);

    if (graphPtr->type == BARCHART_TYPE) {
	/* If no axis limits have been requested, check to make sure
	   that zero is included in the range */
	if ((axisPtr->reqMinimum == NegativeInfinity) &&
	    (axisPtr->minLimit > 0.0))
	    axisPtr->minLimit = 0.0;
	if ((axisPtr->reqMaximum == PositiveInfinity) &&
	    (axisPtr->maxLimit < 0.0))
	    axisPtr->maxLimit = 0.0;
    }
    CalculateAxisLayout(axisPtr);
}

/*
 * -----------------------------------------------------------------
 *
 * GetTickWidth --
 *
 * -----------------------------------------------------------------
 */
static int
GetTickWidth(axisPtr, fontPtr)
    Axis *axisPtr;
    XFontStruct *fontPtr;
{
    register int cnt;
    register int maxWidth;   /* Maximum tick label width found */
    int width;
    char tickLabel[80];
    double value;
    XCharStruct bbox;
    int dummy;

    maxWidth = 0;
    value = axisPtr->major.low;
    for (cnt = 0; cnt < axisPtr->major.numSteps; cnt++) {
	value = ROUND(value, axisPtr->major.stepSize);
	FormatLabel(axisPtr->logScale, value, tickLabel);
	XTextExtents(fontPtr, tickLabel, strlen(tickLabel), &dummy, &dummy,
		     &dummy, &bbox);
	width = bbox.rbearing + bbox.lbearing;
	if (width > maxWidth)
	    maxWidth = width;
	value += axisPtr->major.stepSize;
    }
    return (maxWidth);
}

/*
 * -----------------------------------------------------------------
 *
 * GetLegendExtents --
 *
 * Calculate the width and height needed for the legend
 *
 * Returns:
 *      Width of the longest label in pixels.
 *
 * Side effects:
 *   	The size of each line's symbol is calculated and set.
 * -----------------------------------------------------------------
 */
static int
GetLegendExtents(graphPtr, width, height)
    Graph *graphPtr;
    int width;		     /* Width of window/plot */
    int height;		     /* Height of window/plot */
{
    register Line *linePtr;
    register Legend *legendPtr = &(graphPtr->legend);
    int w;
    int symbolSize;
    int maxWidth;
    int numEntries;
    int maxSymbolSize;
    ListEntry *searchId;
    int fontHeight = FONTHEIGHT(graphPtr->fontPtr);

    legendPtr->width = legendPtr->height = 0;
    legendPtr->maxSymSize = 0;
    maxSymbolSize = numEntries = maxWidth = 0;

    /*
     * Run through the list of visible lines and determine the number of
     * entries in addition to the widest label.
     */
    for (linePtr = (Line *) FirstListEntry(&(graphPtr->drawnLines), &searchId);
	 linePtr != NULL; linePtr = (Line *) NextListEntry(&searchId)) {
	if (!NULLSTR(linePtr->label)) {
	    XCharStruct bbox;
	    int dummy;

	    XTextExtents(graphPtr->fontPtr, linePtr->label,
			 strlen(linePtr->label),
			 &dummy, &dummy, &dummy, &bbox);
	    w = bbox.rbearing + bbox.lbearing;
	    if (w > maxWidth)
		maxWidth = w;
	    numEntries++;
	    symbolSize = (int)rint(linePtr->symSizePct * 0.01 *
				   ((height < width) ? height : width));
	    symbolSize |= 0x01;	/* Must be an odd number size */
	    linePtr->symbolSize = symbolSize;
	    if (symbolSize > maxSymbolSize)
		maxSymbolSize = symbolSize;
	}
    }
    if (!legendPtr->isVisible) {
	return (maxWidth);
    }
    legendPtr->numEntries = numEntries;
    legendPtr->width = ((3 * PADX) + (2 * legendPtr->borderWidth)
			+ maxSymbolSize + maxWidth);
    legendPtr->maxSymSize = maxSymbolSize;
    legendPtr->height = (2 * (PADY + legendPtr->borderWidth) +
			 ((fontHeight) * numEntries));
    return (maxWidth);
}

/*
 * -----------------------------------------------------------------
 *
 * DrawTags --
 *
 * -----------------------------------------------------------------
 */
static void
DrawTags(graphPtr)
    Graph *graphPtr;
{
    ListEntry *searchID;
    register Tag *tagPtr;

    for (tagPtr = (Tag *) FirstListEntry(&(graphPtr->tags), &searchID);
	 tagPtr != NULL; tagPtr = (Tag *) NextListEntry(&searchID)) {
	if (!NULLSTR(tagPtr->text) || (tagPtr->bitmap != None)) {
	    double x, y;

	    /*
	     * If tag is associated with a particular line, see if that line
	     * is to be plotted. If not, skip the tag.
	     */
	    if (!NULLSTR(tagPtr->lineName) &&
		(FindListEntry(&(graphPtr->drawnLines),
			       tagPtr->lineName) == NULL))
		continue;
	    x = ScaleX(graphPtr, tagPtr->x);
	    if (x < 0.0 || x > 1.0)
	        continue;
	    y = ScaleY(graphPtr, tagPtr->y);
	    if (y < 0.0 || y > 1.0)
	        continue;
	    if (tagPtr->bitmap != None) {
		int w, h;

		Tk_SizeOfBitmap(tagPtr->bitmap, &w, &h);
		DrawRotatedBitmap(graphPtr, tagPtr->bitmap, tagPtr->gc, w, h,
				  GX(graphPtr, x), GY(graphPtr, y),
				  tagPtr->rotation, tagPtr->anchor);
	    } else {
		DrawRotatedText(graphPtr, tagPtr->fontPtr, tagPtr->gc,
				tagPtr->text,
				GX(graphPtr, x), GY(graphPtr, y),
				tagPtr->rotation, tagPtr->anchor);
	    }
	}
    }
}

/*
 * -----------------------------------------------------------------
 *
 * DrawLegend --
 *
 * -----------------------------------------------------------------
 */
static void
DrawLegend(graphPtr)
    Graph *graphPtr;
{
    register int x, y;
    register Line *linePtr;
    ListEntry *searchId;
    Legend *legendPtr;
    XPoint newPt;
    Tk_Anchor anchor;	     /* Anchor of legend */
    int fontHeight;

    legendPtr = &(graphPtr->legend);
    if (!legendPtr->isVisible || legendPtr->numEntries == 0)
	return;

    if (legendPtr->usePosition) {
	x = legendPtr->x;
	y = legendPtr->y;
	if (x < 0)
	    x += graphPtr->width - legendPtr->width;
	if (y < 0)
	    y += graphPtr->height - legendPtr->height;
	anchor = TK_ANCHOR_NW;
    } else {
	x = graphPtr->width - (legendPtr->borderWidth + 3 * PADX);
	y = GY(graphPtr, 0.95);
	anchor = TK_ANCHOR_NE;
    }
    newPt = GetBoxCoords(x, y, legendPtr->width, legendPtr->height, anchor);
    if (legendPtr->borderWidth > 0) {
	Tk_Fill3DRectangle(Tk_Display(graphPtr->tkwin),
			   (Drawable) graphPtr->output,
			   legendPtr->border, newPt.x, newPt.y,
			   legendPtr->width, legendPtr->height,
			   legendPtr->borderWidth, legendPtr->relief);
    }
    fontHeight = FONTHEIGHT(graphPtr->fontPtr);
    y = newPt.y + PADY + fontHeight / 2 + legendPtr->borderWidth;
    x = newPt.x + PADX + legendPtr->borderWidth;
    for (linePtr = (Line *) FirstListEntry(&(graphPtr->drawnLines), &searchId);
	 linePtr != NULL; linePtr = (Line *) NextListEntry(&searchId)) {
	if (!NULLSTR(linePtr->label)) {
	    DrawSymbol(linePtr, x + legendPtr->maxSymSize / 2, y);
	    DrawText(graphPtr, graphPtr->fontPtr, graphPtr->gc,
		     linePtr->label, x + legendPtr->maxSymSize + PADX, y,
		     TK_ANCHOR_W);
	    y += fontHeight;
	}
    }
}

static double logTable[]=
{
    0.0, 0.301, 0.477, 0.602, 0.699, 0.778, 0.845, 0.903, 0.954, 1.0
};

/*
 * -----------------------------------------------------------------
 *
 * DrawXAxis --
 *
 * -----------------------------------------------------------------
 */
static void
DrawXAxis(graphPtr)
    Graph *graphPtr;
{
    Axis *axisPtr = &(graphPtr->X);
    Line *linePtr;
    ListEntry *searchId;
    register int i, j;
    double x;
    int y;		     /* constant y-coordinate of axis */
    XSegment *segArr;
    register int segCnt, need;
    char tickLabel[80];

    /*
     * Save all major and minor tick line segment coordinates in an array of
     * line segments.  Try to draw all ticks in one XDrawSegments call.
     */
    need = (axisPtr->major.numSteps + 1 +
	    ((axisPtr->major.numSteps + 2) * axisPtr->minor.numSteps));
#ifdef NO_ALLOCA
    segArr = (XSegment *) ckalloc(need * sizeof(XSegment));
#else
    segArr = (XSegment *) alloca(need * sizeof(XSegment));
#endif
    segCnt = 0;

    /* Axis line */
    segArr[segCnt++] = Gr_Segment(graphPtr, 0.0, 0.0, 1.0, 0.0);

    if (axisPtr->major.numSteps > 0) {
	double subValue;
	double value;

	if (!axisPtr->logScale && axisPtr->minor.numSteps > 0) {
	    subValue = axisPtr->minor.low;
	    for (j = 1; j < axisPtr->minor.numSteps; j++) {
		if (subValue >= axisPtr->major.low)
		    break;
		x = ((subValue - axisPtr->minLimit) / axisPtr->range);
		segArr[segCnt++] = Gr_Segment(graphPtr, x, 0.0, x, -MINOR_TICK);
		subValue += axisPtr->minor.stepSize;
	    }
	}
	if (graphPtr->type == BARCHART_TYPE) {
	    y = graphPtr->height - (graphPtr->borderWidth +
				  FONTHEIGHT(graphPtr->fontPtr) + 2 * PADY);
	} else {
	    y = GY(graphPtr, -LABEL_TICK);
	}
	value = axisPtr->major.low;
	linePtr = (Line *) FirstListEntry(&(graphPtr->drawnLines), &searchId);
	for (i = 0; i < axisPtr->major.numSteps; i++) {

	    /* Clean up round-off error from labels */
	    value = ROUND(value, axisPtr->major.stepSize);

	    /* Scale the tick value [0..1] */
	    x = ((value - axisPtr->minLimit) / axisPtr->range);

	    if (graphPtr->type == BARCHART_TYPE) {
		if (!NULLSTR(linePtr->label)) {
		    if (graphPtr->xrotation == ROTATE_270)
			DrawRotatedText(graphPtr, graphPtr->fontPtr, graphPtr->gc,
					linePtr->label, GX(graphPtr, x), y,
					graphPtr->xrotation, TK_ANCHOR_S);
		    else
			DrawRotatedText(graphPtr, graphPtr->fontPtr, graphPtr->gc,
					linePtr->label, GX(graphPtr, x),
					GY(graphPtr, -LABEL_TICK),
					graphPtr->xrotation, TK_ANCHOR_N);
		}
		linePtr = (Line *) NextListEntry(&searchId);
	    } else {
		/* Draw numeric value string at each major tick */
		FormatLabel(axisPtr->logScale, value, tickLabel);
		DrawText(graphPtr, graphPtr->numberFontPtr,
			 graphPtr->numberGC, tickLabel, GX(graphPtr, x), y,
			 TK_ANCHOR_N);
	    }
	    segArr[segCnt++] = Gr_Segment(graphPtr, x, 0.0, x, -MAJOR_TICK);
	    if (axisPtr->minor.numSteps > 0 && value < axisPtr->maxLimit) {
		if (axisPtr->logScale) {
		    for (j = 1; j < 9; j++) {
			subValue = value + logTable[j];
			x = ((subValue - axisPtr->minLimit) / axisPtr->range);
			segArr[segCnt++] =
			    Gr_Segment(graphPtr, x, 0.0, x,
				       -MAJOR_TICK * logTable[j]);
		    }
		} else {
		    subValue = value + axisPtr->minor.stepSize;
		    for (j = 1; (j < axisPtr->minor.numSteps) &&
			 (subValue <= axisPtr->maxLimit); j++) {
			x = ((subValue - axisPtr->minLimit) / axisPtr->range);
			segArr[segCnt++] =
			    Gr_Segment(graphPtr, x, 0.0, x, -MINOR_TICK);
			subValue += axisPtr->minor.stepSize;
		    }
		}
	    }
	    value += axisPtr->major.stepSize;
	}
    }
    /* Draw the X label */
    if (!NULLSTR(axisPtr->label)) {
	y = graphPtr->height -
	    (graphPtr->borderWidth + PADY + FONTHEIGHT(graphPtr->fontPtr) / 2);
	DrawText(graphPtr, graphPtr->fontPtr, graphPtr->gc, axisPtr->label,
		 GX(graphPtr, 0.5), y, TK_ANCHOR_CENTER);
    }
    XDrawSegments(Tk_Display(graphPtr->tkwin), (Drawable) graphPtr->output,
		  graphPtr->numberGC, segArr, segCnt);
    if (segCnt > need)
	fprintf(stderr, "Number allocated = %d, used = %d\n", need, segCnt);
#ifdef NO_ALLOCA
    ckfree((char *)segArr);
#endif
}

/*
 * -----------------------------------------------------------------
 *
 * DrawYAxis --
 *
 * -----------------------------------------------------------------
 */
static void
DrawYAxis(graphPtr)
    Graph *graphPtr;
{
    Axis *axisPtr = &(graphPtr->Y);
    register int i, j;
    register int x;
    double y;
    XSegment *segArr;
    register int segCnt;
    int need;
    char tickLabel[80];

    /*
     * Try to draw all the ticks and subticks in one XDrawSegments call. Save
     * all tick line segment coordinates in an array of line segments.
     */
    need = (axisPtr->major.numSteps + 1 +
	    ((axisPtr->major.numSteps + 2) * axisPtr->minor.numSteps));
#ifdef NO_ALLOCA
    segArr = (XSegment *) ckalloc(need * sizeof(XSegment));
#else
    segArr = (XSegment *) alloca(need * sizeof(XSegment));
#endif
    segCnt = 0;
    segArr[segCnt++] = Gr_Segment(graphPtr, 0.0, 0.0, 0.0, 1.0); /* Axis */
    if (!NULLSTR(axisPtr->label)) {
	x = PADX + graphPtr->borderWidth + FONTHEIGHT(graphPtr->fontPtr) / 2;
	DrawRotatedText(graphPtr, graphPtr->fontPtr, graphPtr->gc,
			axisPtr->label, x, GY(graphPtr, 0.5), 90,
			TK_ANCHOR_CENTER);
    }
    if (axisPtr->major.numSteps > 0) {
	double subValue;
	double value;

	if (!axisPtr->logScale && (axisPtr->minor.numSteps > 0)) {
	    subValue = axisPtr->minor.low;
	    for (j = 1; j < axisPtr->minor.numSteps; j++) {
		if (subValue >= axisPtr->major.low)
		    break;
		y = ((subValue - axisPtr->minLimit) / axisPtr->range);
		segArr[segCnt++] =
		    Gr_Segment(graphPtr, 0.0, y, -MINOR_TICK, y);
		subValue += axisPtr->minor.stepSize;
	    }
	}
	x = GX(graphPtr, -LABEL_TICK);
	value = axisPtr->major.low;
	for (i = 0; i < axisPtr->major.numSteps; i++) {
	    value = ROUND(value, axisPtr->major.stepSize);

	    /* Scale the tick value [0..1] */
	    y = ((value - axisPtr->minLimit) / axisPtr->range);
	    segArr[segCnt++] = Gr_Segment(graphPtr, 0.0, y, -MAJOR_TICK, y);

	    /* Draw tick label at each major tick */
	    FormatLabel(axisPtr->logScale, value, tickLabel);
	    DrawText(graphPtr, graphPtr->numberFontPtr, graphPtr->numberGC,
		     tickLabel, x, GY(graphPtr, y), TK_ANCHOR_E);
	    /* Minor ticks */
	    if (axisPtr->minor.numSteps > 0 && value < axisPtr->maxLimit) {
		if (axisPtr->logScale) {
		    for (j = 1; j < 9; j++) {
			subValue = value + logTable[j];
			y = ((subValue - axisPtr->minLimit) / axisPtr->range);
			segArr[segCnt++] = Gr_Segment(graphPtr, 0.0, y,
					      -MAJOR_TICK * logTable[j], y);
		    }
		} else {
		    subValue = value + axisPtr->minor.stepSize;
		    for (j = 1; (j < axisPtr->minor.numSteps) &&
			 (subValue <= axisPtr->maxLimit); j++) {
			y = ((subValue - axisPtr->minLimit) / axisPtr->range);
			segArr[segCnt++] =
			    Gr_Segment(graphPtr, 0.0, y, -MINOR_TICK, y);
			subValue += axisPtr->minor.stepSize;
		    }
		}
	    }
	    value += axisPtr->major.stepSize;
	}
    }
    XDrawSegments(Tk_Display(graphPtr->tkwin), (Drawable) graphPtr->output,
		  graphPtr->numberGC, segArr, segCnt);

    if (segCnt > need)
	fprintf(stderr, "Number allocated = %d, used = %d\n", need, segCnt);
#ifdef NO_ALLOCA
    ckfree((char *)segArr);
#endif
}

/*
 * -----------------------------------------------------------------
 *
 * DrawXYGraph --
 *
 * -----------------------------------------------------------------
 */
static int
DrawXYGraph(graphPtr)
    register Graph *graphPtr;
{
    register int n;
    register double x, y;
    register Line *linePtr;
    XPoint *ptArr;
    register int numPoints;
    int numValues;
    register double *xvaluePtr, *yvaluePtr;
    double lastx;
    ListEntry *searchId;
    Tk_Window tkwin = graphPtr->tkwin;
    Drawable draw = (Drawable) graphPtr->output;

    DrawXAxis(graphPtr);
    DrawYAxis(graphPtr);

#ifdef NO_ALLOCA
    ptArr = (XPoint *) ckalloc(graphPtr->maxValues * sizeof(XPoint));
#else
    ptArr = (XPoint *) alloca(graphPtr->maxValues * sizeof(XPoint));
#endif
    if (ptArr == NULL) {
	Tcl_AppendResult(graphPtr->interp, "alloc:", sys_errlist[errno],
			 ": Can't allocate array of points", NULL);
	return TCL_ERROR;
    }
    for (linePtr = (Line *) FirstListEntry(&(graphPtr->drawnLines), &searchId);
	 linePtr != NULL; linePtr = (Line *) NextListEntry(&searchId)) {
	/* Must have both X and Y values */
	numValues = MIN(linePtr->x.numValues, linePtr->y.numValues);
	if (numValues < 1)
	    continue;
	xvaluePtr = linePtr->x.valueArr, yvaluePtr = linePtr->y.valueArr;
	lastx = 0.0;	     /* Suppress compiler warning */
	numPoints = 0;
	for (n = 0; n < numValues; n++, xvaluePtr++, yvaluePtr++) {

	    /* Ignore points out of range (range is [0,1] after scaling) */
	    x = ScaleX(graphPtr, *xvaluePtr);
	    if (x < 0.0 || x > 1.0)
		continue;
	    y = ScaleY(graphPtr, *yvaluePtr);
	    if (y < 0.0 || y > 1.0)
		continue;

	    if (LINESTYLE(linePtr->symbol)) {
		if (!(graphPtr->showRetrace || linePtr->showRetrace) &&
		    (numPoints > 0) && (x < lastx)) {
		    XDrawLines(Tk_Display(tkwin), draw, linePtr->gc,
			       ptArr, numPoints, CoordModeOrigin);
		    numPoints = 0;
		}
		ptArr[numPoints++] = Gr_Point(graphPtr, x, y);
		lastx = x;
	    } else if (linePtr->symbol == POINT_SYMBOL) {
		ptArr[numPoints++] = Gr_Point(graphPtr, x, y);
	    } else {
		DrawSymbol(linePtr, GX(graphPtr, x), GY(graphPtr, y));
	    }
	}
	if (numPoints > 0) {
	    if (LINESTYLE(linePtr->symbol))
		XDrawLines(Tk_Display(tkwin), draw, linePtr->gc,
			   ptArr, numPoints, CoordModeOrigin);
	    else if (linePtr->symbol == POINT_SYMBOL)
		XDrawPoints(Tk_Display(tkwin), draw, linePtr->gc,
			    ptArr, numPoints, CoordModeOrigin);
	}
    }
#ifdef NO_ALLOCA
    ckfree((char *)ptArr);
#endif
    return TCL_OK;
}

/*
 * -----------------------------------------------------------------
 *
 * DrawBarchart --
 *
 * -----------------------------------------------------------------
 */
static int
DrawBarchart(graphPtr)
    register Graph *graphPtr;
{
    register double x, y, baseLine;
    register Line *linePtr;
    int w;
    ListEntry *searchId;
    int y0;
    Drawable draw = (Drawable) graphPtr->output;

    DrawYAxis(graphPtr);
    DrawXAxis(graphPtr);
    baseLine = MAX(graphPtr->Y.minLimit, 0.0);	/* Determine baseline */
    /* Calculate the width of each bar */
    w = (int)rint(graphPtr->X.scale * graphPtr->barWidthPct * .01 *
	      ((1.0 + LABEL_TICK) / (graphPtr->drawnLines.numEntries + 1)));
    y0 = GY(graphPtr, ScaleY(graphPtr, baseLine));
    x = 1.0;
    for (linePtr = (Line *) FirstListEntry(&(graphPtr->drawnLines), &searchId);
	 linePtr != NULL; linePtr = (Line *) NextListEntry(&searchId), x++) {
        if (linePtr->y.numValues > 0) {/* Make sure data exists for the line */
	    int h;
	    XPoint pt;

	    y = ScaleY(graphPtr, linePtr->y.valueArr[0]);
	    if (y < 0.0)
	        y = 0.0;
	    else if (y > 1.0)
	        y = 1.0;
	    pt = Gr_Point(graphPtr, ScaleX(graphPtr, x), y);
	    h = y0 - pt.y;
	    if (h < 0) {
	        h = -h;
	        pt = GetBoxCoords(pt.x, pt.y, w, h, TK_ANCHOR_S);
	    } else {
	        pt = GetBoxCoords(pt.x, pt.y, w, h, TK_ANCHOR_N);
	    }
	    if (linePtr->y.valueArr[0] < 0.0)
	        pt.y = y0;
	    XFillRectangle(Tk_Display(graphPtr->tkwin), draw, linePtr->gc,
			   pt.x, pt.y, w, h);
	}
    }
    return TCL_OK;
}

/*
 * -----------------------------------------------------------------
 *
 * PostScript routines to print the graph
 *
 * -----------------------------------------------------------------
 */
static char lineProc[]= "/Line { % Draw solid line\n\
   % Stack: x1 y1 x2 y2\n\
   /y2 exch def\n\
   /x2 exch def\n\
   /y1 exch def\n\
   /x1 exch def\n\
   newpath\n\
     x1 y1 moveto\n\
     x2 y2 lineto\n\
   closepath\n\
   stroke\n\
} def\n";

static char dashedStyleProc[]= "/dashedLineStyle { % Set dashed line style\n\
  [5 2] 0 setdash\n\
} def\n";
static char dottedStyleProc[]= "/dottedLineStyle { % Set dotted line style\n\
  [1 1] 0 setdash\n\
} def\n";
static char solidStyleProc[]= "/solidLineStyle { % Set solid line style\n\
  [] 0 setdash\n\
} def\n";

static char fgColorProc[]= "/SetFgColor { % Set foreground color\n\
  % Stack: r g b\n\
  isMonochrome 1 eq { \n\
     0 0 0 pop pop pop\n\
  } if\n\
  setrgbcolor\n\
} def\n";
static char bgColorProc[]= "/SetBgColor { % Set background color\n\
  % Stack: r g b\n\
  isMonochrome 1 eq { \n\
     1 1 1 pop pop pop\n\
  } if\n\
  setrgbcolor\n\
} def\n";

/* PS procedure to draw rotated text */
static char rotTextProc[]= "/RText { % Draw rotated text\n\
  % Stack: s x y r\n\
  gsave\n\
  /r exch def\n\
  /y exch def\n\
  /x exch def\n\
  /s exch def\n\
  x y translate\n\
  0 0 moveto\n\
  1 -1 scale\n\
  r 90 mul rotate\n\
  s show\n\
  grestore\n\
} def\n";

/* PS procedure to create filled rectangle */
static char rectProc[]= "/Box { % Create filled rectangle\n\
  % Stack: x y w h\n\
  gsave\n\
  /h exch def\n\
  /w exch def\n\
  /y exch def\n\
  /x exch def\n\
  newpath\n\
    x y moveto\n\
    w 0 rlineto\n\
    0 h rlineto\n\
    w neg 0 rlineto\n\
  closepath\n\
  fill\n\
  grestore\n\
} def\n";

/* PS procedure to draw (non-rotated) text */
static char textProc[]= "/Text { % Draw text\n\
  % Stack: s x y\n\
  gsave\n\
  /y exch def\n\
  /x exch def\n\
  /s exch def\n\
  newpath\n\
    x y moveto\n\
    1 -1 scale\n\
  closepath\n\
  s show\n\
  grestore\n\
} def\n";

static char dottedSymProc[]= "/dotted { % Draw dotted line\n\
   % Stack: x y r\n\
   /r exch def\n\
   /y exch def\n\
   /x exch def\n\
   [1 1] 0 setdash\n\
   x r sub y moveto\n\
   x r add y lineto\n\
   stroke\n\
} def\n";

static char dashedSymProc[]= "/dashed { % Draw dashed line\n\
   % Stack: x y r\n\
   /r exch def\n\
   /y exch def\n\
   /x exch def\n\
   [5 2] 0 setdash\n\
   x r sub y moveto\n\
   x r add y lineto\n\
   stroke\n\
} def\n";

static char solidSymProc[]= "/solid { % Draw solid line\n\
   % Stack: x y r\n\
   /r exch def\n\
   /y exch def\n\
   /x exch def\n\
   [] 0 setdash\n\
   x r sub y moveto\n\
   x r add y lineto\n\
   stroke\n\
} def\n";

static char crossSymProc[]= "/cross { % Draw cross\n\
   % Stack: x y r\n\
   /r exch def\n\
   /y exch def\n\
   /x exch def\n\
   x r sub y r sub moveto\n\
   x r add y r add lineto\n\
   stroke\n\
   x r sub y r add moveto\n\
   x r add y r sub lineto\n\
   stroke\n\
} def\n";

static char plusSymProc[]= "/plus { % Draw plus\n\
   % Stack: x y r\n\
   /r exch def\n\
   /y exch def\n\
   /x exch def\n\
   x r sub y moveto\n\
   x r add y lineto\n\
   stroke\n\
   x y r sub moveto\n\
   x y r add lineto\n\
   stroke\n\
} def\n";

static char circleSymProc[]= "/circle { % Draw filled circle\n\
   % Stack: x y r\n\
   /r exch def\n\
   /y exch def\n\
   /x exch def\n\
   x y moveto\n\
   newpath\n\
     x y r 0 360 arc\n\
   closepath\n\
   fill\n\
} def\n";

static char squareSymProc[]= "/square { % Draw filled square\n\
   % Stack: x y r\n\
   /r exch def\n\
   /y exch def\n\
   /x exch def\n\
   x r sub y r sub moveto\n\
   x y r r Box\n\
} def\n";

static char diamondSymProc[]= "/diamond { % Draw filled diamond\n\
   % Stack: x y r\n\
   /r exch def\n\
   /y exch def\n\
   /x exch def\n\
   newpath\n\
     x r sub y moveto\n\
     x y r sub lineto\n\
     x r add y lineto\n\
     x y r add lineto\n\
     x r sub y lineto\n\
   closepath\n\
   fill\n\
} def\n";

static char pointSymProc[]= "/point { % Draw filled point \n\
   % Stack: x y r\n\
   /r exch def\n\
   /y exch def\n\
   /x exch def\n\
   x 0.5 sub y 0.5 sub moveto\n\
   x y 0.5 0.5 Box\n\
} def\n";

static char *PSRoutines[]=
{
    lineProc, rectProc, rotTextProc, textProc, solidStyleProc,
    dashedStyleProc, dottedStyleProc, solidSymProc, dashedSymProc,
    dottedSymProc, crossSymProc, plusSymProc, squareSymProc,
    circleSymProc, diamondSymProc, pointSymProc, fgColorProc, bgColorProc,
};
static int numRoutines = sizeof(PSRoutines) / sizeof(char *);

#define PSSETFG(f,c) \
    fprintf (f, "%g %g %g SetFgColor\n", \
	    (c)->red / 65536.0, (c)->green / 65536.0, (c)->blue / 65536.0)
#define PSSETBG(f,c) \
    fprintf (f, "%g %g %g SetBgColor\n", \
	    (c)->red / 65536.0, (c)->green / 65536.0, (c)->blue / 65536.0)

#define PSATTR(f,t,s) \
    fprintf (f, "%d setlinewidth\n%sLineStyle\n", t, s)

#define PSRECT(f,x,y,w,h) \
    fprintf (f, "%d %d %d %d Box\n", x, y, w, h)


/*
 * -----------------------------------------------------------------
 *
 * PSFont --
 *
 * -----------------------------------------------------------------
 */
static void
PSFont(f, dpy, fontPtr)
    FILE *f;		     /* File to write postscript commands */
    Display *dpy;	     /* X display to query about atoms */
    XFontStruct *fontPtr;    /* X font to query about */
{
    Atom atom;
    Atom foundryAtom;
    register char *namePtr;
    char *foundry;
    int ptSize;
    char *fontAtom;

    namePtr = foundry = NULL;
    foundryAtom = XInternAtom(dpy, "FOUNDRY", True);
    if (XGetFontProperty(fontPtr, foundryAtom, &atom)) {
	foundry = XGetAtomName(dpy, atom);
    }
    if (XGetFontProperty(fontPtr, XA_POINT_SIZE, &ptSize) == False) {
	ptSize = 120;	     /* Default point size */
    }
    fontAtom = NULL;
    namePtr = "Helvetica";   /* Default font */
    /* Handle font mappings only if foundry is Adobe */
    if (!NULLSTR(foundry) && strcmp(foundry, "Adobe") == 0) {
	if (XGetFontProperty(fontPtr, XA_FAMILY_NAME, &atom)) {
	    fontAtom = XGetAtomName(dpy, atom);
	}
	if (fontAtom != NULL) {
	    namePtr = fontAtom;
	    /* Kludge for font mappings */
	    if (*namePtr == 'T' && strcmp(namePtr, "Times") == 0) {
		namePtr = "Times-Roman";
	    } else if (*namePtr == 'N' &&
		       strcmp(namePtr, "New Century Schoolbook") == 0) {
		namePtr = "NewCenturySchlbk-Roman";
	    }
	}
    }
    fprintf(f, "/%s findfont %d scalefont setfont\n", namePtr, ptSize / 10);
    /* Free atom strings */
    if (foundry != NULL)
	XFree(foundry);
    if (fontAtom != NULL)
	XFree(fontAtom);
}

/*
 * --------------------------------------------------------------------------
 *
 * PSPreamble
 *
 *    The postscript preamble does a translation and scaling to make the
 *    units compatible.
 *
 *     +-----------------------+
 *     |	1" = 72pica    |   1" left, right, top, and bottom margin
 *     |  ------------------ur |   leaving a 6.5" x 9" area.
 *     |  |  O--->	    |  |
 *     |  |  |	            |  |
 *     |  |  | 6.5" = 468 pica |
 *     |  |  v	            |  |
 *     |  |		    |  |                     468 pica
 *     |  |  9" = 648 pica  |  |   scaleX =  ---------------------------
 *     |  |                 |  |                  Width of window
 * 11" |  |		    |  |
 *     | ll------------------  |
 *     |     bounding box      |                     648 pica
 *     |                       |   scaleY =  ---------------------------
 *     |                       |                  Height of window
 *     |		       |
 *     |		       |  To retain the aspect ratio, we use only
 *     |		       |  the smaller of the two scales.  The Y scale
 *     |		       |  is negative since the X11 Y origin is at
 *     +-----------------------+  the top instead of the bottom.
 *  		8.5"
 *
 * ---------------------------------------------------------------------
 */

/* Postscript coordinate mappings. */
#define PS_WIDTH_INCHES 	6.5
#define PS_WIDTH_PICA  		468.0
#define PS_WIDTH_MM		165.1
#define PS_HEIGHT_INCHES 	9.0
#define PS_HEIGHT_PICA   	648.0
#define PS_HEIGHT_MM		228.6
#define MM_PER_INCH		25.4

#define MM_PER_INCH 25.4

#include <time.h>
#include <sys/time.h>

static void
PSPreamble(graphPtr, options)
    Graph *graphPtr;
    PSOption *options;
{
    int i;
    double scale;
    double scaleByHeight, scaleByWidth;
    FILE *f = (FILE *) graphPtr->output;
    long date;
    char *versionID;

    scaleByHeight = PS_HEIGHT_PICA / graphPtr->psHeight;
    scaleByWidth = PS_WIDTH_PICA / graphPtr->psWidth;
    scale = MIN(scaleByHeight, scaleByWidth);

    fputs("%!PS-Adobe-3.0 EPSF-3.0\n", f);
    fprintf(f, "%%%%Title: (%s)\n", options->fileName);
    fputs("%%Pages: 1\n", f);
    fputs("%%DocumentNeededResources: font Helvetica Courier\n", f);
    /* Compute Landscape/Portrait sizes */
    fprintf(f, "%%%%BoundingBox:  %d %d %d %d\n",
	    72,		     /* Lower left x */
	    720 - (int)rint(graphPtr->psHeight * scale),	/* Lower left y */
	    72 + (int)rint(graphPtr->psWidth * scale),	/* Upper right x */
	    720);	     /* Upper right y */

    versionID = Tcl_GetVar(graphPtr->interp, "tk_version", TCL_GLOBAL_ONLY);
    if (versionID == NULL)
	versionID = "unknown";
    fprintf(f, "%%%%Creator: %s (Tk version %s)\n",
	    Tk_PathName(graphPtr->tkwin), versionID);
    date = time(NULL);
    fprintf(f, "%%%%CreationDate: %s", ctime(&date));
    fputs("%%EndComments\n", f);
    fputs("%%BeginSetup\n", f);
    for (i = 0; i < numRoutines; i++)
	fputs(PSRoutines[i], f);
    fprintf(f, "/isMonochrome %d def\n", options->isMonochrome);
    fputs("0 setlinewidth\n1 setlinecap\nsolidLineStyle\n", f);
    PSFont(f, Tk_Display(graphPtr->tkwin), graphPtr->fontPtr);
    if (options->isLandscape) {
	fputs("540 720 translate\n-90 rotate\n", f);
    } else {
	fputs("72 720 translate\n", f);
    }
    fprintf(f, "%g -%g scale\n\n", scale, scale);
    fputs("%%EndSetup\n", f);
    if (!options->isMonochrome) {	/* Draw background */
	PSSETBG(f, Tk_3DBorderColor(graphPtr->border));
	PSRECT(f, 0, 0, graphPtr->psWidth, graphPtr->psHeight);
    }
    PSSETFG(f, graphPtr->fgColor);
}

/*
 * -----------------------------------------------------------------
 *
 * PSSymbol --
 *
 * -----------------------------------------------------------------
 */
static void
PSSymbol(f, linePtr, x, y)
    FILE *f;
    Line *linePtr;
    int x;
    int y;
{
    register double radius = linePtr->symbolSize / 2.0;
    char *symbolName;

    symbolName = NameOfSymbol(linePtr->symbol);
    fprintf(f, "%d %d %g %s\n", x, y, radius, symbolName);
}

/*
 * -----------------------------------------------------------------
 *
 * PSText --
 *
 * -----------------------------------------------------------------
 */
static void
PSText(graphPtr, fontPtr, text, x, y, anchor)
    Graph *graphPtr;
    XFontStruct *fontPtr;
    char *text;
    int x;
    int y;
    Tk_Anchor anchor;
{
    if (!NULLSTR(text)) {
	XPoint newPt;
	FILE *f = (FILE *) graphPtr->output;

	PSFont(f, Tk_Display(graphPtr->tkwin), fontPtr);
	newPt = GetTextCoords(fontPtr, text, x, y, anchor, ROTATE_0);
	fprintf(f, "(%s) %d %d Text\n", text, newPt.x, newPt.y);
    }
}

/*
 * -----------------------------------------------------------------
 *
 * PSRotatedText --
 *
 * -----------------------------------------------------------------
 */
static void
PSRotatedText(graphPtr, fontPtr, fgColor, bgColor,
	      text, x, y, rotation, anchor)
    Graph *graphPtr;
    XFontStruct *fontPtr;
    XColor *fgColor, *bgColor;
    char *text;
    int x;
    int y;
    int rotation;
    Tk_Anchor anchor;
{
    if (!NULLSTR(text)) {
	int quadrant;
	FILE *f = (FILE *) graphPtr->output;
	XPoint newPt;

	quadrant = Quadrant(rotation);	/* Compute quadrant */
	newPt = GetTextCoords(fontPtr, text, x, y, anchor, quadrant);
	PSFont(f, Tk_Display(graphPtr->tkwin), fontPtr);
	PSSETFG(f, fgColor); /* Set text color */
	fprintf(f, "(%s) %d %d %d RText\n", text, newPt.x, newPt.y, quadrant);
    }
}

/*
 * -----------------------------------------------------------------
 *
 * PSLine--
 *
 * -----------------------------------------------------------------
 */
static void
PSLine(graphPtr, x1, y1, x2, y2)
    Graph *graphPtr;
    double x1, y1, x2, y2;
{
    XSegment seg;
    FILE *f = (FILE *) graphPtr->output;

    seg = Gr_Segment(graphPtr, x1, y1, x2, y2);
    fprintf(f, "%d %d %d %d Line\n", seg.x1, seg.y1, seg.x2, seg.y2);
}

/*
 * -----------------------------------------------------------------
 *
 * PSTags --
 *
 * -----------------------------------------------------------------
 */
static void
PSTags(graphPtr)
    Graph *graphPtr;
{
    ListEntry *searchID;
    register Tag *tagPtr;
    FILE *f = (FILE *) graphPtr->output;

    for (tagPtr = (Tag *) FirstListEntry(&(graphPtr->tags), &searchID);
	 tagPtr != NULL; tagPtr = (Tag *) NextListEntry(&searchID)) {
	if (!NULLSTR(tagPtr->text) || (tagPtr->bitmap == None)) {
	    double x, y;

	    /*
	     * If tag is associated with a particular line, see if that line
	     * is to be plotted. If not, skip drawing the tag.
	     */
	    if (!NULLSTR(tagPtr->lineName) &&
		(FindListEntry(&(graphPtr->drawnLines),
			       tagPtr->lineName) == NULL))
		continue;
	    x = ScaleX(graphPtr, tagPtr->x), y = ScaleY(graphPtr, tagPtr->y);
	    PSSETFG(f, tagPtr->fgColor);
	    PSRotatedText(graphPtr, tagPtr->fontPtr,
			  tagPtr->fgColor, tagPtr->bgColor, tagPtr->text,
			  GX(graphPtr, x), GY(graphPtr, y),
			  tagPtr->rotation, tagPtr->anchor);
	}
    }
}

/*
 * -----------------------------------------------------------------
 *
 * PSLegend --
 *
 * -----------------------------------------------------------------
 */
static void
PSLegend(graphPtr)
    Graph *graphPtr;
{
    FILE *f = (FILE *) graphPtr->output;
    register int x, y;
    register Line *linePtr;
    Legend *legendPtr;
    XPoint pt;
    Tk_Anchor anchor;
    ListEntry *searchId;
    int fontHeight;
    char *symbolName;

    legendPtr = &(graphPtr->legend);
    if (!legendPtr->isVisible || legendPtr->numEntries == 0)
	return;
    if (legendPtr->usePosition) {

	/*
	 * Legend position was given in screen coordinates, so we have to
	 * scale it into postscript coordinates
	 */
	x = (int)rint(legendPtr->x *
		      ((double)graphPtr->psWidth / graphPtr->width));
	y = (int)rint(legendPtr->y *
		      ((double)graphPtr->psHeight / graphPtr->height));
	if (x < 0)
	    x += graphPtr->psWidth - legendPtr->width;
	if (y < 0)
	    y += graphPtr->psHeight - legendPtr->height;
	anchor = TK_ANCHOR_NW;
    } else {
	x = graphPtr->psWidth - (legendPtr->borderWidth + 3 * PADX);
	y = GY(graphPtr, 0.95);
	anchor = TK_ANCHOR_NE;
    }
    pt = GetBoxCoords(x, y, legendPtr->width, legendPtr->height, anchor);
    if (legendPtr->borderWidth > 0) {
	PSSETBG(f, Tk_3DBorderColor(legendPtr->border));
	PSRECT(f, pt.x, pt.y, legendPtr->width, legendPtr->height);
    }
    fontHeight = FONTHEIGHT(graphPtr->fontPtr);
    y = pt.y + PADY + fontHeight / 2 + legendPtr->borderWidth;
    x = pt.x + PADX + legendPtr->borderWidth;

    /* Print the symbol and label associated with the line */
    for (linePtr = (Line *) FirstListEntry(&(graphPtr->drawnLines), &searchId);
	 linePtr != NULL; linePtr = (Line *) NextListEntry(&searchId)) {
	if (!NULLSTR(linePtr->label)) {
	    /* Set the line color, type and thickness */
	    symbolName = "solid";
	    if (LINESTYLE(linePtr->symbol)) {
		symbolName = NameOfSymbol(linePtr->symbol);
	    }
	    PSSETFG(f, linePtr->fgColor);
	    PSSymbol(f, linePtr, x + legendPtr->maxSymSize / 2, y);
	    PSSETFG(f, graphPtr->fgColor);
	    PSText(graphPtr, graphPtr->fontPtr, linePtr->label,
		   x + legendPtr->maxSymSize + 2 * PADX, y, TK_ANCHOR_W);
	    y += fontHeight;
	}
    }
}

/*
 * -----------------------------------------------------------------
 *
 * PSXAxis --
 *
 * -----------------------------------------------------------------
 */
static void
PSXAxis(graphPtr)
    Graph *graphPtr;
{
    FILE *f = (FILE *) graphPtr->output;
    Axis *axisPtr = &(graphPtr->X);
    register int i, j;
    double x;
    int y;
    char tickLabel[80];

    /* Set the line color, type and thickness */
    PSSETFG(f, graphPtr->numberFg);
    PSATTR(f, graphPtr->axisThickness, "solid");
    /* Axis without ticks */
    PSLine(graphPtr, 0.0, 0.0, 1.0, 0.0);

    /* Draw the X label */
    if (!NULLSTR(axisPtr->label)) {
	y = graphPtr->psHeight;
	y -= (PADY + graphPtr->borderWidth + FONTHEIGHT(graphPtr->fontPtr) / 2);
	PSText(graphPtr, graphPtr->fontPtr, axisPtr->label,
	       GX(graphPtr, 0.5), y, TK_ANCHOR_CENTER);
    }
    if ((axisPtr->major.numSteps > 0) && (axisPtr->major.stepSize > 0.0)) {
	double subValue;
	double value;
	Line *linePtr;
	ListEntry *searchId;

	if (!(axisPtr->logScale) && (axisPtr->minor.numSteps > 0)) {
	    subValue = axisPtr->minor.low;
	    for (j = 1; j < axisPtr->minor.numSteps; j++) {
		if (subValue >= axisPtr->major.low)
		    break;
		x = ((subValue - axisPtr->minLimit) / axisPtr->range);
		PSLine(graphPtr, x, 0.0, x, -MINOR_TICK);
		subValue += axisPtr->minor.stepSize;
	    }
	}
	if (graphPtr->type == BARCHART_TYPE) {
	    y = graphPtr->height - (graphPtr->borderWidth +
				  FONTHEIGHT(graphPtr->fontPtr) + 2 * PADY);
	} else {
	    y = GY(graphPtr, -LABEL_TICK);
	}
	value = axisPtr->major.low;
	linePtr = (Line *) FirstListEntry(&(graphPtr->drawnLines), &searchId);
	for (i = 0; i < axisPtr->major.numSteps; i++) {
	    /* Clean up labels */
	    value = ROUND(value, axisPtr->major.stepSize);
	    /* Scale the tick value [0..1] */
	    x = ((value - axisPtr->minLimit) / axisPtr->range);

	    if (graphPtr->type == BARCHART_TYPE) {
		if (!NULLSTR(linePtr->label)) {
		    PSRotatedText(graphPtr, graphPtr->fontPtr,
				  graphPtr->fgColor, linePtr->bgColor,
				  linePtr->label, GX(graphPtr, x), y,
				  graphPtr->xrotation, TK_ANCHOR_S);
		}
		linePtr = (Line *) NextListEntry(&searchId);
	    } else {
		/* Draw numeric value string at each major tick */
		FormatLabel(axisPtr->logScale, value, tickLabel);
		PSText(graphPtr, graphPtr->numberFontPtr, tickLabel,
		       GX(graphPtr, x), y, TK_ANCHOR_N);
	    }
	    PSSETFG(f, graphPtr->numberFg);
	    PSLine(graphPtr, x, 0.0, x, -MAJOR_TICK);

	    if ((axisPtr->minor.numSteps > 0) && (value < axisPtr->maxLimit)) {
		if (axisPtr->logScale) {
		    subValue = value;
		    for (j = 1; j < 9; j++) {
			subValue = value + logTable[j];
			x = ((subValue - axisPtr->minLimit) / axisPtr->range);
			PSLine(graphPtr, x, 0.0, x, -MAJOR_TICK * logTable[j]);
		    }
		} else {
		    subValue = value + axisPtr->minor.stepSize;
		    for (j = 1; (j < axisPtr->minor.numSteps) &&
			 (subValue <= axisPtr->maxLimit); j++) {
			x = ((subValue - axisPtr->minLimit) / axisPtr->range);
			PSLine(graphPtr, x, 0.0, x, -MINOR_TICK);
			subValue += axisPtr->minor.stepSize;
		    }
		}
	    }
	    value += axisPtr->major.stepSize;
	}
    }
}

/*
 * -----------------------------------------------------------------
 *
 * PSYAxis --
 *
 * -----------------------------------------------------------------
 */
static void
PSYAxis(graphPtr)
    Graph *graphPtr;
{
    FILE *f = (FILE *) graphPtr->output;
    Axis *axisPtr = &(graphPtr->Y);
    register int i, j;
    double y;
    int x;
    char tickLabel[80];

    /* Set the line color, type and thickness */
    PSSETFG(f, graphPtr->numberFg);
    PSATTR(f, graphPtr->axisThickness, "solid");
    /* Axis without ticks */
    PSLine(graphPtr, 0.0, 0.0, 0.0, 1.0);

    /* Y Axis label */
    if (!NULLSTR(axisPtr->label)) {
	x = PADX + graphPtr->borderWidth + FONTHEIGHT(graphPtr->fontPtr) / 2;
	PSRotatedText(graphPtr, graphPtr->fontPtr, graphPtr->numberFg,
		      Tk_3DBorderColor(graphPtr->border), axisPtr->label,
		      x, GY(graphPtr, 0.5), 90, TK_ANCHOR_CENTER);
    }
    /* Major and minor ticks, including tick labels */
    if ((axisPtr->major.numSteps > 0) && (axisPtr->major.stepSize > 0.0)) {
	double subValue;
	double value;

	if (!(axisPtr->logScale) && (axisPtr->minor.numSteps > 0)) {
	    subValue = axisPtr->minor.low;
	    for (j = 1; j < axisPtr->minor.numSteps; j++) {
		if (subValue >= axisPtr->major.low)
		    break;
		y = ((subValue - axisPtr->minLimit) / axisPtr->range);
		PSLine(graphPtr, 0.0, y, -MINOR_TICK, y);
		subValue += axisPtr->minor.stepSize;
	    }
	}
	x = GX(graphPtr, -LABEL_TICK);
	value = axisPtr->major.low;
	for (i = 0; i < axisPtr->major.numSteps; i++) {
	    /* Clean up labels */
	    value = ROUND(value, axisPtr->major.stepSize);
	    /* Scale the tick value [0..1] */
	    y = ((value - axisPtr->minLimit) / axisPtr->range);
	    FormatLabel(axisPtr->logScale, value, tickLabel);
	    PSText(graphPtr, graphPtr->numberFontPtr, tickLabel,
		   x, GY(graphPtr, y), TK_ANCHOR_E);
	    PSLine(graphPtr, 0.0, y, -MAJOR_TICK, y);

	    /* Minor ticks */
	    if ((axisPtr->minor.numSteps > 0) && (value < axisPtr->maxLimit)) {
		if (axisPtr->logScale) {
		    for (j = 1; j < 9; j++) {
			subValue = value + logTable[j];
			y = ((subValue - axisPtr->minLimit) / axisPtr->range);
			PSLine(graphPtr, 0.0, y, -MAJOR_TICK * logTable[j], y);
		    }
		} else {
		    subValue = value + axisPtr->minor.stepSize;
		    for (j = 1; (j < axisPtr->minor.numSteps) &&
			 (subValue <= axisPtr->maxLimit); j++) {
			y = ((subValue - axisPtr->minLimit) / axisPtr->range);
			PSLine(graphPtr, 0.0, y, -MINOR_TICK, y);
			subValue += axisPtr->minor.stepSize;
		    }
		}
	    }
	    value += axisPtr->major.stepSize;
	}
    }
}

/*
 *----------------------------------------------------------------------
 *
 * PSGraph --
 *
 *	This procedure is invoked to print the graph in a file.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Commands are output in PostScript to the file.
 *
 *----------------------------------------------------------------------
 */
static int
PSGraph(graphPtr)
    Graph *graphPtr;
{
    int n;
    register double x, y;
    int x1, y1;
    register Line *linePtr;
    ListEntry *searchId;
    FILE *f = (FILE *) graphPtr->output;

    PSXAxis(graphPtr);
    PSYAxis(graphPtr);
    for (linePtr = (Line *) FirstListEntry(&(graphPtr->drawnLines), &searchId);
	 linePtr != NULL; linePtr = (Line *) NextListEntry(&searchId)) {
	register int numPoints = 0;
	int numValues;
	register double *xvaluePtr, *yvaluePtr;
	double lastx;
	char *symbolName;

	xvaluePtr = linePtr->x.valueArr, yvaluePtr = linePtr->y.valueArr;

	lastx = 0.0;	     /* Suppress compiler warning */
	numValues = MIN(linePtr->x.numValues, linePtr->y.numValues);

	/* Set the line color, type and thickness */
	symbolName = "solid";
	if (LINESTYLE(linePtr->symbol)) {
	    symbolName = NameOfSymbol(linePtr->symbol);
	}
	PSSETFG(f, linePtr->fgColor);
	PSATTR(f, linePtr->lineWidth, symbolName);
	/* fprintf (f, "newpath\n"); */
	for (n = 0; n < numValues; n++, xvaluePtr++, yvaluePtr++) {
	    /* Ignore points out of range (range is [0,1] after scaling) */
	    x = ScaleX(graphPtr, *xvaluePtr);
	    if (x < 0.0 || x > 1.0)
		continue;
	    y = ScaleY(graphPtr, *yvaluePtr);
	    if (y < 0.0 || y > 1.0)
		continue;
	    x1 = GX(graphPtr, x), y1 = GY(graphPtr, y);
	    if (LINESTYLE(linePtr->symbol)) {
		if (!(graphPtr->showRetrace || linePtr->showRetrace) &&
		    (numPoints > 0) && (x < lastx)) {
		    numPoints = 0;
		    fprintf(f, "stroke\n%d %d moveto\n", x1, y1);
		} else {
		    if (numPoints == 0)
			fprintf(f, "%d %d moveto\n", x1, y1);
		    fprintf(f, "%d %d lineto\n", x1, y1);
		    numPoints++;
		}
		lastx = x;
	    } else {
		PSSymbol(f, linePtr, x1, y1);
	    }
	}
	fputs("stroke\n", f);
    }
    return TCL_OK;
}

/*
 * PSBargraph
 *
 * Each bar is calculated as
 * - X axis is centered names
 */
static int
PSBarchart(graphPtr)
    register Graph *graphPtr;
{
    register double x, y, baseLine;
    register Line *linePtr;
    int w;
    ListEntry *searchId;
    int y0;
    FILE *f = (FILE *) graphPtr->output;

    PSYAxis(graphPtr);
    PSXAxis(graphPtr);
    baseLine = MAX(graphPtr->Y.minLimit, 0.0);	/* Determine baseline */
    /* Calculate the width of each bar */
    w = (int)rint(graphPtr->X.scale * graphPtr->barWidthPct * .01 *
	      ((1.0 + LABEL_TICK) / (graphPtr->drawnLines.numEntries + 1)));
    y0 = GY(graphPtr, ScaleY(graphPtr, baseLine));
    x = 1.0;
    for (linePtr = (Line *) FirstListEntry(&(graphPtr->drawnLines), &searchId);
	 linePtr != NULL; linePtr = (Line *) NextListEntry(&searchId), x++) {
        if (linePtr->y.numValues > 0) {/* Make sure data exists for the line */
	    int h;
	    XPoint newPt;

	    y = ScaleY(graphPtr, linePtr->y.valueArr[0]);
	    if (y > 1.0)
  	        y = 1.0;
	    else if (y < 0.0)
	        y = 0.0;
	    newPt = Gr_Point(graphPtr, ScaleX(graphPtr, x), y);
	    h = y0 - newPt.y;
	    if (h < 0) {
		h = -h;
		newPt = GetBoxCoords(newPt.x, newPt.y, w, h, TK_ANCHOR_S);
	    } else {
		newPt = GetBoxCoords(newPt.x, newPt.y, w, h, TK_ANCHOR_N);
	    }
	    if (linePtr->y.valueArr[0] < 0.0)
		newPt.y = y0;
	    PSSETFG(f, linePtr->fgColor);
	    fprintf(f, "%d %d %d %d Box\n", newPt.x, newPt.y, w, h);
	}
    }
    return TCL_OK;
}

/*
 * -----------------------------------------------------------------
 *
 * ComputeLayout --
 *
 * Calculate the layout of the graph.  Based upon the data, axis
 * limits, X and Y labels, and title height, determine the cavity
 * left which is the plotting surface.  The first step get the data
 * and axis limits for calculating the the space needed for the top,
 * bottom, left, and right margins.
 *
 * 1) The LEFT margin is the area from the left border to the Y axis
 *    (not including ticks). It composes the border width, the width
 *    an optional Y axis label and its padding, and the tick numeric labels.
 *    The Y axis label is rotated 90 degrees so that the width is the
 *    font height.
 *
 * 2) The RIGHT margin is the area from the end of the graph to the
 *    right window border. It composes the border width, some padding,
 *    the font height (this may be dubious. It appears to provide a more
 *    even border), the max of the legend width and 1/2 max X tick number.
 *    This last part is so that the last tick label is not clipped.
 *
 *       Area Width
 *  _____________________________________________________
 *  _______________________________________________________
 *  |         |                               |           |
 *  |         |   TOP  height of title        |           |  A
 *  |_________|_______________________________|___________|  r
 *  |         |                               |           |  e
 *  |  LEFT   |                               | RIGHT     |  a
 *  |         |                               |           |
 *  | Y       |                               |           |  H
 *  |         |     PLOTTING SURFACE  105%    |           |  e
 *  | l       |     100 + 5% tick length      |           |  i
 *  | a       |                               |           |  g
 *  | b       |                               | legend    |  h
 *  | e       |                               | width     |  t
 *  | l       |                               |           |
 *  |         |                               |           |
 *  | width of|                               |           |
 *  | widest  |                               |           |
 *  | number  |                               |           |
 *  |         |                               |           |
 *  |         |                               |           |
 *  |         |                               |           |
 *  |         | origin (xoffset, yoffset)     |           |
 *  |_________|_______________________________|___________|
 *  |         |   height of number       1/2 width of     |
 *  |         |                         max tick number   |
 *  |         |   BOTTOM   height of X label  |           |
 *  |_________|_______________________________|___________|
 *
 * 3) The TOP margin is the area from the top window border to the top
 *    of the graph. It composes the border width, twice the height of
 *    the title font (if one is given) and some padding between the
 *    title.
 *
 * 4) The BOTTOM margin is area from the bottom window border to the
 *    X axis (not including ticks). It composes the border width, the height
 *    an optional X axis label and its padding, the height of the font
 *    of the tick labels.
 *
 * The plotting area is between the margins which includes the X and Y axes
 * including the ticks but not the tick numeric labels. The length of
 * the ticks and its padding is 5% of the entire plotting area.  Hence the
 * entire plotting area is scaled as 105% of the width and height of the
 * area.
 *
 * The axis labels, ticks labels, title, and legend may or may not be
 * displayed which must be taken into account.
 *
 *
 * -----------------------------------------------------------------
 */
static int
ComputeLayout(graphPtr, width, height)
    Graph *graphPtr;
    int width;		     /* Width of window/plot area */
    int height;		     /* Height of window/plot area */
{
    int reqMargin = 0;
    int leftMargin, rightMargin;
    int topMargin, bottomMargin;
    int maxTickWidth = 0;
    int maxLabelWidth = 0;
    int range;
    int fontHeight = FONTHEIGHT(graphPtr->fontPtr);

    GetDataExtents(graphPtr);
    ConfigureXAxis(graphPtr);
    ConfigureYAxis(graphPtr);

    topMargin = PADY;
    if (!NULLSTR(graphPtr->title))
	topMargin += ((fontHeight * 2) + PADY);

    leftMargin = PADX;
    if (!NULLSTR(graphPtr->Y.label))
	leftMargin += (fontHeight + 3 * PADX);

    if (graphPtr->Y.major.numSteps > 0) {
	/* Get the width of the widest Y tick label */
	leftMargin += GetTickWidth(&(graphPtr->Y), graphPtr->numberFontPtr);
    }
    bottomMargin = PADY;
    if (!NULLSTR(graphPtr->X.label))
	bottomMargin += (fontHeight + 2 * PADY);

    rightMargin = PADX + fontHeight;	/* dubious using fontHeight here */
    graphPtr->legend.width = 0;
    maxLabelWidth = GetLegendExtents(graphPtr, width, height);
    if (graphPtr->X.major.numSteps > 0) {
	maxTickWidth =
	    GetTickWidth(&(graphPtr->X), graphPtr->numberFontPtr) / 2;
	if (graphPtr->type == BARCHART_TYPE) {
	    int quadrant;

	    quadrant = Quadrant(graphPtr->xrotation);	/* Compute quadrant */
	    bottomMargin += ((quadrant == ROTATE_270 || quadrant == ROTATE_90)
			     ? maxLabelWidth : fontHeight);
	} else {
	    bottomMargin += FONTHEIGHT(graphPtr->numberFontPtr);
	}
    }
    /* Override calculated values if user specified margins */
    if (graphPtr->leftMargin > 0)
	leftMargin = graphPtr->leftMargin;
    if (graphPtr->topMargin > 0)
	topMargin = graphPtr->topMargin;
    if (graphPtr->bottomMargin > 0)
	bottomMargin = graphPtr->bottomMargin;

    reqMargin = graphPtr->rightMargin;
    if ((reqMargin <= 0) &&
	graphPtr->legend.isVisible && !graphPtr->legend.usePosition) {
	reqMargin = graphPtr->legend.width;
    }
    rightMargin += MAX(reqMargin, maxTickWidth);

    /* Based upon the margins, calculate the space left for the graph. */
    graphPtr->X.offset = leftMargin + graphPtr->borderWidth;
    graphPtr->Y.offset = (height - (graphPtr->borderWidth + bottomMargin));
    range = width - (leftMargin + rightMargin + (2 * graphPtr->borderWidth));
    if (range < 0) {
	return TCL_ERROR;
    }
    graphPtr->X.scale = range / (1.0 + LABEL_TICK);	/* Pixels per X unit */
    range = height - (topMargin + bottomMargin + (2 * graphPtr->borderWidth));
    if (range < 0) {
	return TCL_ERROR;
    }
    graphPtr->Y.scale = range / (1.0 + LABEL_TICK);	/* Pixels per Y unit */

    /* Add tick distance to center graph */
    graphPtr->X.offset += (int)rint(LABEL_TICK * graphPtr->X.scale);
    graphPtr->Y.offset -= (int)rint(LABEL_TICK * graphPtr->Y.scale);
    return TCL_OK;
}

/*
 *--------------------------------------------------------------
 *
 * GraphLimits --
 *
 *	This procedure returns a list of the axis limits for
 *	the graph.  The format is { xmin xmax ymin ymax}.
 *
 * Results:
 *	Always returns TCL_OK.  The interp->result field is
 *	a list of the graph axis limits.
 *
 *--------------------------------------------------------------
 */
static int
GraphLimits(interp, graphPtr)
    Tcl_Interp *interp;
    Graph *graphPtr;
{
    char *fmt;
    char buf[80];

    /* Until there is global OFMT variable */
    fmt = "%.10g";
    if (graphPtr->type == XYGRAPH_TYPE) {
	sprintf(buf, fmt, graphPtr->X.minLimit);	/* X min */
	Tcl_AppendElement(interp, buf, FALSE);
	sprintf(buf, fmt, graphPtr->X.maxLimit);	/* X max */
	Tcl_AppendElement(interp, buf, FALSE);
    }
    sprintf(buf, fmt, graphPtr->Y.minLimit);	/* Y min */
    Tcl_AppendElement(interp, buf, FALSE);
    sprintf(buf, fmt, graphPtr->Y.maxLimit);	/* Y max */
    Tcl_AppendElement(interp, buf, FALSE);
    return TCL_OK;
}

/*
 *--------------------------------------------------------------
 *
 * GraphLocate --
 *
 *	This procedure returns a list of the graph coordinate
 *	values corresponding with the given screen X and Y
 *	coordinate positions.
 *
 * Results:
 *	Returns a standard Tcl result.  The interp->result field is
 *	a Tcl list of the corresponding graph X and Y coordinates.
 *	If an error occured while parsing the screen positions,
 *	TCL_ERROR is returned, and interp->result will contain
 *	the error message.
 *
 *--------------------------------------------------------------
 */
static int
GraphLocate(interp, graphPtr, screenX, screenY)
    Tcl_Interp *interp;	     /* Interpreter to report results back to */
    Graph *graphPtr;	     /* Graph widget record */
    char *screenX;	     /* String representing screen x coordinate */
    char *screenY;	     /* String representing Screen y coordinate */
{
    int sx, sy;		     /* Convert integer screen coordinates */
    double x, y;	     /* Resulting graph coordinate values */
    char buf[80];

    if (Tcl_GetInt(interp, screenX, &sx) != TCL_OK ||
	Tcl_GetInt(interp, screenY, &sy) != TCL_OK) {
	return TCL_ERROR;
    }
    /* Perform the reverse transformation from screen coordinates to data */
    x = (sx - graphPtr->X.offset) / graphPtr->X.scale;
    x = UnscaleX(graphPtr, x);
    y = (graphPtr->Y.offset - sy) / graphPtr->Y.scale;
    y = UnscaleY(graphPtr, y);
    sprintf(buf, "%.15g %.15g", x, y);
    Tcl_SetResult(interp, buf, TCL_VOLATILE);
    return TCL_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * GraphLineNames --
 *
 *	Given an Tcl list of line names, this procedure rebuilds the
 *	visibleLine list, ignoring invalid line names. The visible
 *	line list contains not only which lines are to be drawn, but
 *	the order in which to draw them.  This is really only important
 *	for bar and pie charts.
 *
 * Results:
 *	The return value is a standard Tcl result.  Only if the
 *	Tcl list cannot be split, a TCL_ERROR is returned and
 *	interp->result contains an error message.
 *
 * Side effects:
 *	The graph is eventually redrawn using the new list of visible lines.
 *
 *----------------------------------------------------------------------
 */
static int
GraphLineNames(interp, graphPtr, newList)
    Tcl_Interp *interp;	     /* Interpreter to report results back to */
    Graph *graphPtr;	     /* Graph widget record */
    char *newList;	     /* Tcl list of line names */
{
    int numNames;	     /* Number of names found in Tcl name list */
    char **nameArr;	     /* Broken out array of line names */
    ListEntry *searchId;     /* Search token for list operations */
    register int cnt;	     /* */
    Line *linePtr;	     /* Line information record */

    if (Tcl_SplitList(interp, newList, &numNames, &nameArr) != TCL_OK) {
	Tcl_AppendResult(interp, "Can't split name list \"", newList, "\"",
			 NULL);
	return TCL_ERROR;
    }
    /*
     * Delete the current list of visible lines and mark each line as not
     * drawn.
     */
    for (linePtr = (Line *) FirstListEntry(&(graphPtr->drawnLines), &searchId);
	 linePtr != NULL; linePtr = (Line *) NextListEntry(&searchId)) {
	linePtr->isVisible = FALSE;
	DeleteListEntry(&(graphPtr->drawnLines), linePtr->name);
    }

    /*
     * Rebuild the list of visible lines, checking each name to make sure the
     * line exists. Currently ignoring invalid names.
     */
    for (cnt = 0; cnt < numNames; cnt++) {
	linePtr = (Line *) FindListEntry(&(graphPtr->allLines), nameArr[cnt]);
	if (linePtr != NULL) {
	    linePtr->isVisible = TRUE;
	    CreateListEntry(&(graphPtr->drawnLines), linePtr->name, linePtr);
	}
    }
    ckfree((char *)nameArr);
    return TCL_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * GraphInsert --
 *
 *	Add a new line to the graph.
 *
 * Results:
 *	The return value is a standard Tcl result.
 *
 *----------------------------------------------------------------------
 */
static int
GraphInsert(interp, graphPtr, argc, argv, flags, redrawFlag)
    Tcl_Interp *interp;
    Graph *graphPtr;
    int argc;
    char **argv;
    int flags;
    int *redrawFlag;
{
    Line *linePtr;
    int result;

    if (argc < 3) {
	Tcl_AppendResult(interp, "wrong # args: should be \"", argv[0],
			 " ", argv[1], " name ?options?\"", NULL);
	return TCL_ERROR;
    }
    linePtr = CreateLine(graphPtr, argv[2]);
    if (linePtr == NULL) {
	Tcl_AppendResult(interp, "Can't create \"", argv[2], "\"", NULL);
	return TCL_ERROR;
    }
    result = ConfigureLine(interp, linePtr, argc - 3, argv + 3, flags);
    if (result != TCL_OK) {
	DeleteLine(interp, graphPtr, linePtr->name, redrawFlag);
	return TCL_ERROR;
    }
    *redrawFlag = TRUE;
    return TCL_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * GraphNewTag --
 *
 *	Add a new tag to the graph.
 *
 * Results:
 *	The return value is a standard Tcl result.
 *
 * Side effects:
 *	The graph is eventually redrawn with the new tag.
 *
 *----------------------------------------------------------------------
 */
static int
GraphNewTag(interp, graphPtr, argc, argv, flags, redrawFlag)
    Tcl_Interp *interp;
    Graph *graphPtr;
    int argc;
    char **argv;
    int flags;
    int *redrawFlag;
{
    Tag *tagPtr;
    int result;
    double x, y;

    if (argc < 5) {
	Tcl_AppendResult(interp, "wrong # args: should be \"", argv[0],
			 " ", argv[1], " name x y ?options?\"", NULL);
	return TCL_ERROR;
    }
    /* Get X and Y coordinates */
    if (GetExprValue (interp, argv[3], &x) != TCL_OK ||
	GetExprValue (interp, argv[4], &y) != TCL_OK) {
	return TCL_ERROR;
    }
    tagPtr = CreateTag(graphPtr, argv[2], x, y);
    if (tagPtr == NULL)
	return TCL_ERROR;
    result = ConfigureTag(interp, graphPtr, tagPtr, argc - 5, argv + 5, flags);
    if (result != TCL_OK) {
	DeleteTag(interp, graphPtr, tagPtr->name, redrawFlag);
	return TCL_ERROR;
    }
    *redrawFlag = TRUE;
    return TCL_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * GraphPrint --
 *
 *	This procedure is invoked to print the graph in a file.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	A new postscript file is created.
 *
 *----------------------------------------------------------------------
 */
static int
GraphPrint(interp, tkwin, graphPtr, argc, argv)
    Tcl_Interp *interp;	     /* Interpreter to report results back to */
    Tk_Window tkwin;	     /* Window to use */
    Graph *graphPtr;	     /* Graph widget record */
    int argc;		     /* Number of options in argv vector */
    char **argv;	     /* Option vector */
{
    FILE *f;
    PSOption options;
    int width, height;
    register int i;
    register char *p;
    int length;

    width = height = 0;
    options.isLandscape = options.isCentered = options.isMonochrome = FALSE;
    if (graphPtr->drawnLines.numEntries <= 0) {
	Tcl_AppendResult(interp, "No lines are visible in ",
			 Tk_PathName(tkwin), (char *)NULL);
	return TCL_ERROR;
    }
    options.geometry = NULL;
    /* Process arguments */
    f = fopen(argv[1], "w");
    if (f == NULL) {
	Tcl_AppendResult(interp, "Can't open \"", argv[1], "\"", NULL);
	Tcl_SetErrorCode(interp, "UNIX", "fopen", sys_errlist[errno], NULL);
	return TCL_ERROR;
    }
    graphPtr->output = (ClientData) f;
    options.fileName = argv[1];
    for (i = 2; i < argc; i++) {
	p = argv[i];
	length = strlen(argv[i]) - 1;
	if (*p++ == '-') {
	    if (*p == 'm' && strncmp(p, "monochrome", length) == 0)
		options.isMonochrome = TRUE;
	    else if (*p == 'c' && strncmp(p, "centered", length) == 0)
		options.isCentered = TRUE;
	    else if (*p == 'l' && strncmp(p, "landscape", length) == 0)
		options.isLandscape = TRUE;
	    else if (*p == 'g' && strncmp(p, "geometry", length) == 0) {
		if (++i < argc) {
		    p = strchr(argv[i], 'x');
		    if (p == NULL) {
			Tcl_AppendResult(interp, "Bad geometry: should be \"",
			      argv[i - 1], " widthxheight\"", (char *)NULL);
		    }
		    *p++ = '\0';
		    if (Tk_GetPixels(interp, tkwin, argv[i], &width) != TCL_OK)
			return TCL_ERROR;
		    if (Tk_GetPixels(interp, tkwin, p, &height) != TCL_OK)
			return TCL_ERROR;
		} else {
		    Tcl_AppendResult(interp, "Missing ", argv[i - 1],
				     " argument", (char *)NULL);
		    return TCL_ERROR;
		}
	    } else {
		Tcl_AppendResult(interp, "Unknown ", argv[0], " option \"",
				 argv[i], "\"", (char *)NULL);
		return TCL_ERROR;
	    }
	}
    }
    /* */
    graphPtr->psWidth = (width > 0) ? width : graphPtr->width;
    graphPtr->psHeight = (height > 0) ? height : graphPtr->height;
    ComputeLayout(graphPtr, graphPtr->psWidth, graphPtr->psHeight);
    PSPreamble(graphPtr, &options);
    PSTags(graphPtr);
    PSLegend(graphPtr);
    if (!NULLSTR(graphPtr->title)) {
	PSText(graphPtr, graphPtr->fontPtr, graphPtr->title,
	       GX(graphPtr, 0.5),
	       PADY + graphPtr->borderWidth + FONTHEIGHT(graphPtr->fontPtr),
	       TK_ANCHOR_CENTER);
    }
    switch (graphPtr->type) {
    case XYGRAPH_TYPE:
	PSGraph(graphPtr);
	break;
    case BARCHART_TYPE:
	PSBarchart(graphPtr);
	break;
    case PIECHART_TYPE:
	fprintf(stderr, "postscript: Not implemented yet\n");
	break;
    }
    fputs("showpage\n", f);
    fputs("%%Trailer\n", f);
    fputs("%%EOF\n", f);

    fclose(f);
    Tcl_SetResult(interp, options.fileName, TCL_VOLATILE);
    return TCL_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * CreateGraph --
 *
 *	This procedure creates and initializes a new widget.
 *
 * Results:
 *	The return value is a pointer to a structure describing
 *	the new widget.  If an error occurred, then the return
 *	value is NULL and an error message is left in interp->result.
 *
 * Side effects:
 *	Memory is allocated, a Tk_Window is created, etc.
 *
 *----------------------------------------------------------------------
 */
static Graph *
CreateGraph(interp, tkwin, pathName, type)
    Tcl_Interp *interp;
    Tk_Window tkwin;
    char *pathName;
    int type;
{
    register Graph *graphPtr;
    Tk_Window new;

    graphPtr = (Graph *) calloc(1, sizeof(Graph));
    if (graphPtr == NULL) {
	return (NULL);
    }
    /* Create the window. */
    new = Tk_CreateWindowFromPath(interp, tkwin, pathName, NULL);
    if (new == NULL) {
	ckfree((char *)graphPtr);
	return (NULL);
    }
    Tk_SetClass(new, classNames[type]);

    /* Initialize the data structure for the graph. */
    graphPtr->tkwin = new;
    graphPtr->interp = interp;
    graphPtr->type = type;
    graphPtr->X.reqMinimum = graphPtr->Y.reqMinimum = NegativeInfinity;
    graphPtr->X.reqMaximum = graphPtr->Y.reqMaximum = PositiveInfinity;
    graphPtr->X.major.stepSize = graphPtr->Y.major.stepSize = 1.0;
    Tk_CreateEventHandler(graphPtr->tkwin, ExposureMask | StructureNotifyMask,
			  GraphEventProc, (ClientData) graphPtr);
    Tcl_CreateCommand(interp, Tk_PathName(graphPtr->tkwin), GraphWidgetCmd,
		      (ClientData) graphPtr, (Tcl_CmdDeleteProc *) NULL);
    return (graphPtr);
}

/*
 *----------------------------------------------------------------------
 *
 * DestroyGraph --
 *
 *	This procedure is invoked by Tk_EventuallyFree or Tk_Release
 *	to clean up the internal structure of a graph at a safe time
 *	(when no-one is using it anymore).
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Everything associated with the widget is freed up.
 *
 *----------------------------------------------------------------------
 */
static void
DestroyGraph(clientData)
    ClientData clientData;
{
    register Graph *graphPtr = (Graph *) clientData;
    register Line *linePtr;
    ListEntry *searchId;

    /* Remove the individual line data structures and then the lists */
    for (linePtr = (Line *) FirstListEntry(&(graphPtr->allLines), &searchId);
	 linePtr != NULL; linePtr = (Line *) NextListEntry(&searchId)) {
	DestroyLine(linePtr);
    }
    ClearList(&(graphPtr->allLines));
    ClearList(&(graphPtr->drawnLines));
    if (graphPtr->border)    /* 3D border */
	Tk_Free3DBorder(graphPtr->border);
    if (graphPtr->geometry)  /* Geometry */
	free(graphPtr->geometry);
    if (graphPtr->gc != None)/* Graphics context of graph */
	Tk_FreeGC(graphPtr->gc);
    if (graphPtr->title)     /* Graph title */
	free(graphPtr->title);
    if (graphPtr->fontPtr)   /* Normal font */
	Tk_FreeFontStruct(graphPtr->fontPtr);
    if (graphPtr->numberFontPtr)	/* Axis/number font */
	Tk_FreeFontStruct(graphPtr->numberFontPtr);
    if (graphPtr->numberFg)  /* Axis/number color */
	Tk_FreeColor(graphPtr->numberFg);
    if (graphPtr->numberGC != None)	/* Graphics context of axis */
	Tk_FreeGC(graphPtr->numberGC);
    if (graphPtr->fgColor)   /* Foreground color */
	Tk_FreeColor(graphPtr->fgColor);
    if (graphPtr->cursor != None)	/* cursor */
	Tk_FreeCursor(graphPtr->cursor);
    if (graphPtr->X.label)   /* X axis label */
	ckfree(graphPtr->X.label);
    if (graphPtr->Y.label)   /* Y axis label */
	ckfree(graphPtr->Y.label);
    if (graphPtr->legend.border)	/* Legend 3D border */
	Tk_Free3DBorder(graphPtr->legend.border);
    free((char *)graphPtr);
}

/*
 *----------------------------------------------------------------------
 *
 * ConfigureGraph --
 *
 *	This procedure is called to process an argv/argc list, plus
 *	the Tk option database, in order to configure (or
 *	reconfigure) a graph widget.
 *
 * Results:
 *	The return value is a standard Tcl result.  If TCL_ERROR is
 *	returned, then interp->result contains an error message.
 *
 * Side effects:
 *	Configuration information, such as text string, colors, font,
 *	etc. get set for graphPtr;  old resources get freed, if there
 *	were any.  The graph is redisplayed.
 *
 *----------------------------------------------------------------------
 */
static int
ConfigureGraph(interp, graphPtr, argc, argv, flags)
    Tcl_Interp *interp;	     /* Interpreter to report results back to */
    register Graph *graphPtr;/* Graph widget record */
    int argc;		     /* Number of configuration arguments */
    char **argv;	     /* Configuration arguments */
    int flags;		     /* Configuration flags */
{
    XColor *borderColor;
    GC newGC;
    XGCValues gcValues;
    unsigned int valueMask;

    if (Tk_ConfigureWidget(interp, graphPtr->tkwin, configSpecs,
			   argc, argv, (char *)graphPtr, flags) != TCL_OK) {
	return TCL_ERROR;
    }
    if (graphPtr->geometry != NULL) {
	int height, width;

	if (sscanf(graphPtr->geometry, "%dx%d", &width, &height) != 2) {
	    Tcl_AppendResult(interp, "bad geometry \"", graphPtr->geometry,
			     "\": expected widthxheight", (char *)NULL);
	    return TCL_ERROR;
	}
	Tk_GeometryRequest(graphPtr->tkwin, width, height);
	graphPtr->width = width, graphPtr->height = height;
    }
    if (graphPtr->axisThickness <= 1)
	graphPtr->axisThickness = 0;
    /* Check requested X and Y axis limits */
    if (graphPtr->X.reqMinimum >= graphPtr->X.reqMaximum) {
	sprintf(interp->result, "invalid X axis limits (min %g >= max %g)",
		graphPtr->X.reqMinimum, graphPtr->X.reqMaximum);
	return TCL_ERROR;
    }
    if (graphPtr->Y.reqMinimum >= graphPtr->Y.reqMaximum) {
	sprintf(interp->result, "invalid Y axis limits (min %g >= max %g)",
		graphPtr->Y.reqMinimum, graphPtr->Y.reqMaximum);
	return TCL_ERROR;
    }
    borderColor = Tk_3DBorderColor(graphPtr->border);
    Tk_SetInternalBorder(graphPtr->tkwin, graphPtr->borderWidth);
    Tk_SetBackgroundFromBorder(graphPtr->tkwin, graphPtr->border);

    /* Create graph GC */
    gcValues.line_width = graphPtr->axisThickness;
    gcValues.foreground = graphPtr->fgColor->pixel;
    gcValues.background = borderColor->pixel;
    gcValues.font = graphPtr->fontPtr->fid;
    valueMask = (GCForeground | GCBackground | GCFont | GCLineWidth);
    newGC = Tk_GetGC(graphPtr->tkwin, valueMask, &gcValues);
    if (graphPtr->gc != None)
	Tk_FreeGC(graphPtr->gc);
    graphPtr->gc = newGC;

    /* Create axis GC */
    gcValues.font = graphPtr->numberFontPtr->fid;
    gcValues.foreground = graphPtr->numberFg->pixel;
    newGC = Tk_GetGC(graphPtr->tkwin, valueMask, &gcValues);
    if (graphPtr->numberGC != None)
	Tk_FreeGC(graphPtr->numberGC);
    graphPtr->numberGC = newGC;

    return TCL_OK;
}

/*
 *--------------------------------------------------------------
 *
 * GraphCmd --
 *
 *
 * Results:
 *	A standard Tcl result.
 *
 * Side effects:
 *	See the user documentation.
 *
 *--------------------------------------------------------------
 */
int
GraphCmd(clientData, interp, argc, argv)
    ClientData clientData;
    Tcl_Interp *interp;
    int argc;
    char **argv;
{
    Tk_Window tkwin = (Tk_Window) clientData;
    register Graph *graphPtr;
    char c;
    int type;

    if (argc < 2) {
	Tcl_AppendResult(interp, "wrong # args:  should be \"", argv[0],
			 " pathName ?options?\"", (char *)NULL);
	return TCL_ERROR;
    }
    c = argv[0][0];
    if ((c == 'x') && strcmp(argv[0], "xygraph") == 0)
	type = XYGRAPH_TYPE;
    else if ((c == 'b') && strcmp(argv[0], "barchart") == 0)
	type = BARCHART_TYPE;
    else if ((c == 'p') && strcmp(argv[0], "piechart") == 0)
	type = PIECHART_TYPE;
    else {
	Tcl_AppendResult(interp, "Unknown graph-creation command ",
			 argv[0], NULL);
	return TCL_ERROR;
    }
    /* Initialize infinity constants */
    NegativeInfinity = -HUGE_VAL;
    PositiveInfinity = HUGE_VAL;

    graphPtr = CreateGraph(interp, tkwin, argv[1], type);
    if (graphPtr == NULL)
	return TCL_ERROR;
    if (ConfigureGraph(interp, graphPtr, argc - 2, argv + 2,
		       configFlags[type]) != TCL_OK) {
	Tk_DestroyWindow(graphPtr->tkwin);
	return TCL_ERROR;
    }
    interp->result = Tk_PathName(graphPtr->tkwin);
    return TCL_OK;
}

/*
 *--------------------------------------------------------------
 *
 * GraphWidgetCmd --
 *
 *	This procedure is invoked to process the Tcl command
 *	that corresponds to a widget managed by this module.
 *	See the user documentation for details on what it does.
 *
 * Results:
 *	A standard Tcl result.
 *
 * Side effects:
 *	See the user documentation.
 *
 *--------------------------------------------------------------
 */
static int
GraphWidgetCmd(clientData, interp, argc, argv)
    ClientData clientData;
    Tcl_Interp *interp;
    int argc;
    char **argv;
{
    register Graph *graphPtr = (Graph *) clientData;
    register Line *linePtr;
    int result = TCL_ERROR;
    int redrawFlag = FALSE;
    Tk_Window tkwin = graphPtr->tkwin;
    char c;
    int length;
    int flags;
    int type;

    if (argc < 2) {
	Tcl_AppendResult(interp, "wrong # args: should be \"", argv[0],
			 " option ?arg arg ...?\"", (char *)NULL);
	return TCL_ERROR;
    }
    Tk_Preserve((ClientData) graphPtr);

    c = argv[1][0];
    length = strlen(argv[1]);
    type = graphPtr->type;
    flags = configFlags[type];
    if ((c == 'c') && (strncmp(argv[1], "configure", length) == 0)) {
	if (argc == 2)
	    result = Tk_ConfigureInfo(interp, tkwin, configSpecs,
				      (char *)graphPtr, (char *)NULL, flags);
	else if (argc == 3)
	    result = Tk_ConfigureInfo(interp, tkwin, configSpecs,
				      (char *)graphPtr, argv[2], flags);
	else {
	    result = ConfigureGraph(interp, graphPtr, argc - 2, argv + 2,
				    TK_CONFIG_ARGV_ONLY | flags);
	    redrawFlag = TRUE;
	}
    } else if ((c == 'i') && (strncmp(argv[1], "insert", length) == 0)) {
	result = GraphInsert(interp, graphPtr, argc, argv, flags, &redrawFlag);
	if (result != TCL_OK)
	    goto error;
    } else if ((c == 'd') && (strncmp(argv[1], "delete", length) == 0)) {
	if (argc < 3) {
	    Tcl_AppendResult(interp, "wrong # args: should be \"", argv[0],
			     " delete name\"", NULL);
	    goto error;
	}
	result = DeleteLine(interp, graphPtr, argv[2], &redrawFlag);
    } else if ((c == 't') && (strncmp(argv[1], "tagconfigure", length) == 0)) {
	Tag *tagPtr;

	if (argc < 3) {
	    Tcl_AppendResult(interp, "wrong # args: should be \"", argv[0],
			     " tagconfigure tagName ?arg arg ...?\"", NULL);
	    goto error;
	}
	tagPtr = (Tag *) FindListEntry(&(graphPtr->tags), argv[2]);
	if (tagPtr == NULL)
	    goto error;
	if (argc == 3)
	    result = Tk_ConfigureInfo(interp, tkwin, tagConfigSpecs,
				      (char *)tagPtr, (char *)NULL, flags);
	else if (argc == 4)
	    result = Tk_ConfigureInfo(interp, tkwin, tagConfigSpecs,
				      (char *)tagPtr, argv[3], flags);
	else {
	    result = ConfigureTag(interp, graphPtr, tagPtr, argc - 3, argv + 3,
				  TK_CONFIG_ARGV_ONLY | flags);
	    redrawFlag = TRUE;
	}
    } else if ((c == 'n') && (strncmp(argv[1], "newtag", length) == 0)) {
	result = GraphNewTag(interp, graphPtr, argc, argv, flags, &redrawFlag);
	if (result != TCL_OK)
	    goto error;
    } else if ((c == 'u') && (strncmp(argv[1], "untag", length) == 0)) {
	if (argc < 3) {
	    Tcl_AppendResult(interp, "wrong # args: should be \"", argv[0],
			     " untag tagName\"", NULL);
	    goto error;
	}
	result = DeleteTag(interp, graphPtr, argv[2], &redrawFlag);
    } else if ((c == 'b') && (type == BARCHART_TYPE) && 
	       (strncmp(argv[1], "barconfigure", length) == 0)) {	
        if (argc < 3) {
	    Tcl_AppendResult(interp, "wrong # args: should be \"", argv[0],
			     " barconfigure name ?arg arg ...?\"", NULL);
	    goto error;
	}
        goto lineconfig;
    } else if ((c == 'l') && (length > 2) &&
	       (strncmp(argv[1], "lineconfigure", length) == 0) && 
	       (type == XYGRAPH_TYPE)) {
	if (argc < 3) {
	    Tcl_AppendResult(interp, "wrong # args: should be \"", argv[0],
			     " lineconfigure name ?arg arg ...?\"", NULL);
	    goto error;
	}
    lineconfig:
	linePtr = (Line *) FindListEntry(&(graphPtr->allLines), argv[2]);
	if (linePtr == NULL) {
	    Tcl_AppendResult(interp, "Can't find \"", argv[2], "\"",
			     NULL);
	    goto error;
	}
	if (argc == 3)
	    result = Tk_ConfigureInfo(interp, tkwin, lineConfigSpecs,
				      (char *)linePtr, (char *)NULL, flags);
	else if (argc == 4)
	    result = Tk_ConfigureInfo(interp, tkwin, lineConfigSpecs,
				      (char *)linePtr, argv[3], flags);
	else {
	    result = ConfigureLine(interp, linePtr, argc - 3, argv + 3,
				   TK_CONFIG_ARGV_ONLY | flags);
	    /* If the line is being displayed, redraw the graph */
	    if (linePtr->isVisible)
		redrawFlag = TRUE;
	}
    } else if ((c == 'l') && (length > 1)
	       && (strncmp(argv[1], "locate", length) == 0)) {
	if (argc != 4) {
	    Tcl_AppendResult(interp, "wrong # args: should be \"", argv[0],
			     " locate x y\"", NULL);
	    goto error;
	}
	result = GraphLocate(interp, graphPtr, argv[2], argv[3]);
    } else if ((c == 's') && (strncmp(argv[1], "show", length) == 0)) {
	if (argc == 3) {
	    GraphLineNames(interp, graphPtr, argv[2]);
	    redrawFlag = TRUE;
	} else if (argc != 2) {
	    Tcl_AppendResult(interp, "wrong # args: should be \"", argv[0],
			     " show ?nameList?\"", NULL);
	    goto error;
	}
	result = GetLineNames(interp, &(graphPtr->drawnLines));
    } else if ((c == 'l') && (length > 2) &&
	       (strncmp(argv[1], "limits", length) == 0)) {
	if (argc != 2) {
	    Tcl_AppendResult(interp, "wrong # args: should be \"", argv[0],
			     " limits\"", NULL);
	    goto error;
	}
	result = GraphLimits(interp, graphPtr);
    } else if ((c == 'n') && (strncmp(argv[1], "names", length) == 0)) {
	if (argc != 2) {
	    Tcl_AppendResult(interp, "wrong # args: should be \"", argv[0],
			     " names\"", NULL);
	    goto error;
	}
	result = GetLineNames(interp, &(graphPtr->allLines));
    } else if ((c == 'p') && (strncmp(argv[1], "postscript", length) == 0)) {
	if (argc < 3) {
	    Tcl_AppendResult(interp, "wrong # args: should be \"", argv[0],
			     " postscript file ?options?\"", NULL);
	    goto error;
	}
	result = GraphPrint(interp, tkwin, graphPtr, argc - 1, argv + 1);
    } else {
	Tcl_AppendResult(interp, "bad option \"", argv[1], "\":  should be ",
			 configNames[type], "configure, configure, delete, \
insert, limits, locate, newtag, postscript, show, tagconfigure, or untag ", 
			 NULL);
	goto error;
    }
    /* If plot was reconfigured, recalculate the layout of the graph */
    graphPtr->flags |= LAYOUT_NEEDED;
    if (result == TCL_OK && redrawFlag == TRUE)
	EventuallyRedraw(graphPtr);	/* Redraw the graph */
  error:
    Tk_Release((ClientData) graphPtr);
    return result;
}

/*
 *----------------------------------------------------------------------
 *
 * DisplayGraph --
 *
 *	This procedure is invoked to display a graph widget.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Commands are output to X to display the graph in its
 *	current mode.
 *
 *----------------------------------------------------------------------
 */
static void
DisplayGraph(clientData)
    ClientData clientData;
{
    register Graph *graphPtr = (Graph *) clientData;
    Tk_Window tkwin = graphPtr->tkwin;
    Drawable draw;
    Pixmap pixMap = None;
    int result;
    
    graphPtr->flags &= ~REDRAW_PENDING;
    if ((tkwin == NULL) || !Tk_IsMapped(tkwin))
	return;
    /* Reset width/height */
    graphPtr->width = Tk_Width(graphPtr->tkwin);
    graphPtr->height = Tk_Height(graphPtr->tkwin);

    draw = Tk_WindowId(tkwin);
    if (graphPtr->doubleBuffered) {
	int depth = DefaultDepth(Tk_Display(tkwin), Tk_ScreenNumber(tkwin));
	pixMap = XCreatePixmap(Tk_Display(tkwin), Tk_WindowId(tkwin),
			       graphPtr->width, graphPtr->height, depth);
	draw = pixMap;
    }
    graphPtr->output = (ClientData) draw;	/* Output device/resource */

    /* Clear the window or pixmap */
    Tk_Fill3DRectangle(Tk_Display(tkwin), draw, graphPtr->border,
		       0, 0, graphPtr->width, graphPtr->height,
		       graphPtr->borderWidth, graphPtr->relief);

    if (graphPtr->drawnLines.numEntries <= 0) {
	if (graphPtr->doubleBuffered) {
	    /* Finally copy the pixmap out */
	    XCopyArea(Tk_Display(tkwin), pixMap, Tk_WindowId(tkwin),
		      graphPtr->gc, 0, 0, graphPtr->width, graphPtr->height,
		      0, 0);
	    XFreePixmap(Tk_Display(tkwin), pixMap);
	}
	return;		     /* No visible lines, get out */
    }
    if (graphPtr->flags & LAYOUT_NEEDED) {
	if (ComputeLayout(graphPtr, graphPtr->width, 
			  graphPtr->height) != TCL_OK) {
	    return;	     /* Not enough room to plot graph, get out */
	}
	graphPtr->flags &= ~LAYOUT_NEEDED;
    }
    DrawTags(graphPtr);
    DrawLegend(graphPtr);
    if (!NULLSTR(graphPtr->title)) {	/* Display title */
	int y = PADY + graphPtr->borderWidth + FONTHEIGHT(graphPtr->fontPtr);
	DrawText(graphPtr, graphPtr->fontPtr, graphPtr->gc, graphPtr->title,
		 GX(graphPtr, 0.5), y, TK_ANCHOR_CENTER);
    }
    switch (graphPtr->type) {
    case XYGRAPH_TYPE:
        result = DrawXYGraph(graphPtr);
	break;
    case BARCHART_TYPE:
	result = DrawBarchart(graphPtr);
	break;
    case PIECHART_TYPE:
	result = TCL_OK;
	break;
    }
    if (result != TCL_OK) {
        TkBindError(graphPtr->interp);
	return;
    }
    if (graphPtr->doubleBuffered) {
	XCopyArea(Tk_Display(tkwin), pixMap, Tk_WindowId(tkwin),
	       graphPtr->gc, 0, 0, graphPtr->width, graphPtr->height, 0, 0);
	XFreePixmap(Tk_Display(tkwin), pixMap);
    }
}
