#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <stdio.h>
#include <ctype.h>
#if HAVE_STDLIB_H
#   include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#   include <unistd.h>
#endif
#if HAVE_STRING_H
#   include <string.h>
#else
#  include <strings.h>
#endif

#include <sys/types.h>

#if HAVE_SYS_PARAM_H
#   include <sys/param.h>
#endif
#ifdef HAVE_SYS_STAT_H
#   include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
#   include <fcntl.h>
#endif

#include <errno.h>

#if HAVE_DMALLOC_H
#  include <dmalloc.h>
#endif

#include <net-snmp/types.h>
#include <net-snmp/library/container.h>
#include <net-snmp/library/file_utils.h>
#include <net-snmp/library/text_utils.h>


/*------------------------------------------------------------------
 *
 * Prototypes
 *
 */
void
_pm_save_index_string_string(FILE *f, netsnmp_container *cin,
                             int flags);
void
_pm_save_everything(FILE *f, netsnmp_container *cin, int flags);
void
_pm_user_function(FILE *f, netsnmp_container *cin,
                  netsnmp_line_process_info *lpi, int flags);




/*------------------------------------------------------------------
 *
 * Text file processing functions
 *
 */

/**
 * process text file, reading into extras
 */
netsnmp_container *
netsnmp_file_text_parse(netsnmp_file *f, netsnmp_container *cin,
                        int parse_mode, u_int flags, void *context)
{
    netsnmp_container *c = cin;
    FILE              *fin;
    int                rc;

    if (NULL == f)
        return NULL;

    if ((NULL == c) && (!(flags & PM_FLAG_NO_CONTAINER))) {
        c = netsnmp_container_find("text_parse:binary_array");
        if (NULL == c)
            return NULL;
    }

    rc = netsnmp_file_open(f);
    if (rc < 0) { /** error already logged */
        if ((NULL !=c) && (c != cin))
            CONTAINER_FREE(c);
        return NULL;
    }
    
    /*
     * get a stream from the file descriptor. This DOES NOT rewind the
     * file (if fd was previously opened).
     */
    fin = fdopen(f->fd, "r");
    if (NULL == fin) {
        if (NS_FI_AUTOCLOSE(f->ns_flags))
            close(f->fd);
        if ((NULL !=c) && (c != cin))
            CONTAINER_FREE(c);
        return NULL;
    }

    switch (parse_mode) {

        case PM_SAVE_EVERYTHING:
            _pm_save_everything(fin, c, flags);
            break;

        case PM_INDEX_STRING_STRING:
            _pm_save_index_string_string(fin, c, flags);
            break;

        case PM_USER_FUNCTION:
            if (NULL != context)
                _pm_user_function(fin, c, (netsnmp_line_process_info*)context,
                                  flags);
            break;

        default:
            snmp_log(LOG_ERR, "unknown parse mode %d\n", parse_mode);
            break;
    }


    /*
     * close the stream, which will have the side effect of also closing
     * the file descriptor, so we need to reset it.
     */
    fclose(fin);
    f->fd = -1;

    return c;
}


/**
 * @internal
 * parse mode: save everything
 */
void
_pm_save_everything(FILE *f, netsnmp_container *cin, int flags)
{
    char               line[STRINGMAX], *ptr;
    size_t             len;

    netsnmp_assert(NULL != f);
    netsnmp_assert(NULL != cin);

    while (fgets(line, sizeof(line), f) != NULL) {

        ptr = line;
        len = strlen(line) - 1;
        if (line[len] == '\n')
            line[len] = 0;

        /*
         * save blank line or comment?
         */
        if (flags & PM_FLAG_SKIP_WHITESPACE) {
            if (NULL == (ptr = skip_white(ptr)))
                continue;
        }

        ptr = strdup(line);
        if (NULL == ptr) {
            snmp_log(LOG_ERR,"malloc failed\n");
            break;
        }

        CONTAINER_INSERT(cin,ptr);
    }
}

/**
 * @internal
 * parse mode: 
 */
void
_pm_save_index_string_string(FILE *f, netsnmp_container *cin,
                             int flags)
{
    char                        line[STRINGMAX], *ptr;
    netsnmp_cvalue_triple      *nct;
    size_t                      count = 0, len;

    netsnmp_assert(NULL != f);
    netsnmp_assert(NULL != cin);

    while (fgets(line, sizeof(line), f) != NULL) {

        ++count;
        ptr = line;
        len = strlen(line) - 1;
        if (line[len] == '\n')
            line[len] = 0;

        /*
         * save blank line or comment?
         */
        if (flags & PM_FLAG_SKIP_WHITESPACE) {
            if (NULL == (ptr = skip_white(ptr)))
                continue;
        }

        nct = SNMP_MALLOC_TYPEDEF(netsnmp_cvalue_triple);
        if (NULL == nct) {
            snmp_log(LOG_ERR,"malloc failed\n");
            break;
        }
            
        /*
         * copy whole line, then set second pointer to
         * after token. One malloc, 2 strings!
         */
        nct->v1.ul = count;
        nct->v2.cp = strdup(line);
        if (NULL == nct->v2.cp) {
            snmp_log(LOG_ERR,"malloc failed\n");
            free(nct);
            break;
        }
        nct->v3.cp = skip_white(nct->v2.cp);
        if (NULL != nct->v3.cp) {
            *(nct->v3.cp) = 0;
            ++(nct->v3.cp);
        }
        CONTAINER_INSERT(cin, nct);
    }
}

/**
 * @internal
 * parse mode: 
 */
void
_pm_user_function(FILE *f, netsnmp_container *cin,
                  netsnmp_line_process_info *lpi, int flags)
{
    char                        buf[STRINGMAX];
    netsnmp_line_info           li;
    void                       *mem = NULL;
    int                         rc;

    netsnmp_assert(NULL != f);
    netsnmp_assert(NULL != cin);

    /*
     * static buf, or does the user want the memory?
     */
    if (flags & PMLP_FLAG_ALLOC_LINE) {
        if (0 != lpi->line_max)
            li.line_max =  lpi->line_max;
        else
            li.line_max = STRINGMAX;
        li.line = calloc(li.line_max, 1);
        if (NULL == li.line) {
            snmp_log(LOG_ERR,"malloc failed\n");
            return;
        }
    }
    else {
        li.line = buf;
        li.line_max = sizeof(buf);
    }
        
    li.index = 0;
    while (fgets(li.line, li.line_max, f) != NULL) {

        ++li.index;
        li.start = li.line;
        li.line_len = strlen(li.line) - 1;
        if ((!(lpi->flags & PMLP_FLAG_LEAVE_NEWLINE)) &&
            (li.line[li.line_len] == '\n'))
            li.line[li.line_len] = 0;
        
        /*
         * save blank line or comment?
         */
        if (!(lpi->flags & PMLP_FLAG_PROCESS_WHITESPACE)) {
            if (NULL == (li.start = skip_white(li.start)))
                continue;
        }

        /*
         *  do we need to allocate memory for the use?
         * if the last call didn't use the memory we allocated,
         * re-use it. Otherwise, allocate new chunk.
         */
        if ((0 != lpi->mem_size) && (NULL == mem)) {
            mem = calloc(lpi->mem_size, 1);
            if (NULL == mem) {
                snmp_log(LOG_ERR,"malloc failed\n");
                break;
            }
        }

        /*
         * do they want a copy ot the line?
         */
        if (lpi->flags & PMLP_FLAG_STRDUP_LINE) {
            li.start = strdup(li.start);
            if (NULL == li.start) {
                snmp_log(LOG_ERR,"malloc failed\n");
                break;
            }
        }
        else if (lpi->flags & PMLP_FLAG_ALLOC_LINE) {
            li.start = li.line;
        }

        /*
         * call the user function. If the function wants to save
         * the memory chunk, insert it in the container, the clear
         * pointer so we reallocate next time.
         */
        li.start_len = strlen(li.start);
        rc = (*lpi->process)(&li, mem, lpi);
        if (PMLP_RC_MEMORY_USED == rc) {

            if (!(lpi->flags & PMLP_FLAG_NO_CONTAINER))
                CONTAINER_INSERT(cin, mem);
            
            mem = NULL;
            
            if (lpi->flags & PMLP_FLAG_ALLOC_LINE) {
                li.line = calloc(li.line_max, 1);
                if (NULL == li.line) {
                    snmp_log(LOG_ERR,"malloc failed\n");
                    break;
                }
            }
        }
        else if (PMLP_RC_MEMORY_UNUSED == rc ) {
            /*
             * they didn't use the memory. if li.start was a strdup, we have to
             * release it. leave mem, we can re-use it (its a fixed size).
             */
            if (lpi->flags & PMLP_FLAG_STRDUP_LINE)
                free(li.start); /* no point in SNMP_FREE */
        }
        else {
            if (PMLP_RC_STOP_PROCESSING != rc )
                snmp_log(LOG_ERR, "unknown rc %d from text processor\n", rc);
            break;
        }
    }
}
