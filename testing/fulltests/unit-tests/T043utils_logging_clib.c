/* HEADER Testing snmp_logging, text_utils, file_utils, dir_utils, and system utilities */
    int run_t043(void);
    int rc = run_t043();
    if (__did_plan == 0) {
        PLAN(__test_counter);
    }
    return rc;
}

#include <fcntl.h>
#include <sys/stat.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/library/file_utils.h>
#include <net-snmp/library/text_utils.h>
#include <net-snmp/library/dir_utils.h>

static int
t043_line_cb(netsnmp_line_info *line_info, void *mem,
             struct netsnmp_line_process_info_s *lpi)
{
    int *count = (int *)lpi->user_context;
    if (count) {
        (*count)++;
        if (*count >= 2)
            return PMLP_RC_STOP_PROCESSING;
    }
    return PMLP_RC_MEMORY_UNUSED;
}

int
run_t043(void)
{
    char tmp_dir[128];
    char tmp_sub[160];
    char tmp_file[192];
    FILE *fp;

    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_DONT_PERSIST_STATE, 1);
    init_snmp("T043utils_logging");

    /* 1. snmp_log_options() boundary and missing-argument cases */
    {
        char opt_s_missing[] = "S7";
        char opt_s_valid[] = "S7d";
        char opt_prio_bad1[] = "E99-99";
        char opt_prio_bad2[] = "99-99n";
        char *argv_s1[] = { "prog", "-L", opt_s_missing, NULL };
        char *argv_s2[] = { "prog", "-L", opt_s_valid, NULL };
        char *argv_p1[] = { "prog", "-L", opt_prio_bad1, NULL };
        char *argv_p2[] = { "prog", "-L", opt_prio_bad2, NULL };

        optind = 3;
        OK(snmp_log_options(opt_s_missing, 3, argv_s1) == -1,
           "snmp_log_options rejects -LS7 without facility character");
        optind = 3;
        OK(snmp_log_options(opt_s_valid, 3, argv_s2) == 0,
           "snmp_log_options accepts -LS7d");
        optind = 3;
        OK(snmp_log_options(opt_prio_bad1, 3, argv_p1) == -1,
           "snmp_log_options rejects out-of-range priority in -LE99-99");
        optind = 3;
        OK(snmp_log_options(opt_prio_bad2, 3, argv_p2) == -1,
           "snmp_log_options rejects out-of-range priority in -L99-99n");
        snmp_disable_log();
    }

    /* 2. file_utils and text_utils tests */
    snprintf(tmp_dir, sizeof(tmp_dir), "/tmp/netsnmp_t043_%d", (int)getpid());
    snprintf(tmp_sub, sizeof(tmp_sub), "%s/sub", tmp_dir);
    snprintf(tmp_file, sizeof(tmp_file), "%s/sub/test.txt", tmp_dir);
    mkdir(tmp_dir, 0700);
    mkdir(tmp_sub, 0700);

    fp = fopen(tmp_file, "wb");
    if (fp) {
        fputs("# comment line\n\nkey1 val1\nkey2 val2\nkey3 val3\n", fp);
        fclose(fp);
    }

#if !defined(NETSNMP_FEATURE_REMOVE_FILE_UTILS) && !defined(NETSNMP_FEATURE_REMOVE_TEXT_UTILS)
    {
        netsnmp_file *fobj = netsnmp_file_fill(NULL, tmp_file, O_RDONLY, 0, 0);
        netsnmp_container *c, *cin;
        netsnmp_line_process_info lpi;
        int cb_count = 0;

        OK(fobj != NULL, "netsnmp_file_fill created file object");
        if (fobj) {
            OK(netsnmp_file_open(fobj) >= 0, "netsnmp_file_open succeeded");
            OK(netsnmp_file_close(fobj) == 0, "netsnmp_file_close succeeded");

            /* PM_SAVE_EVERYTHING */
            cin = netsnmp_container_find("fifo");
            c = netsnmp_file_text_parse(fobj, cin, PM_SAVE_EVERYTHING,
                                        PM_FLAG_SKIP_WHITESPACE, NULL);
            OK(c != NULL && CONTAINER_SIZE(c) == 3,
               "netsnmp_file_text_parse PM_SAVE_EVERYTHING parsed 3 non-blank non-comment lines");
            if (c) {
                void *elem;
                while ((elem = CONTAINER_FIRST(c)) != NULL) {
                    CONTAINER_REMOVE(c, NULL);
                    free(elem);
                }
                CONTAINER_FREE(c);
            }

            /* PM_INDEX_STRING_STRING */
            cin = netsnmp_container_find("fifo");
            c = netsnmp_file_text_parse(fobj, cin, PM_INDEX_STRING_STRING,
                                        PM_FLAG_SKIP_WHITESPACE, NULL);
            OK(c != NULL && CONTAINER_SIZE(c) == 3,
               "netsnmp_file_text_parse PM_INDEX_STRING_STRING parsed 3 key-value pairs");
            if (c) {
                netsnmp_token_value_index *tvi;
                while ((tvi = (netsnmp_token_value_index *)CONTAINER_FIRST(c)) != NULL) {
                    CONTAINER_REMOVE(c, NULL);
                    free(tvi->token);
                    free(tvi);
                }
                CONTAINER_FREE(c);
            }

            /* PM_USER_FUNCTION with PMLP_FLAG_ALLOC_LINE and early stop */
            memset(&lpi, 0, sizeof(lpi));
            lpi.process = t043_line_cb;
            lpi.user_context = &cb_count;
            lpi.flags = PMLP_FLAG_ALLOC_LINE | PMLP_FLAG_LEAVE_NEWLINE;
            cin = netsnmp_container_find("fifo");
            c = netsnmp_file_text_parse(fobj, cin, PM_USER_FUNCTION, 0, &lpi);
            OK(cb_count == 2 && c != NULL,
               "netsnmp_file_text_parse PM_USER_FUNCTION with PMLP_FLAG_ALLOC_LINE frees line on stop");
            if (c) {
                CONTAINER_FREE(c);
            }

            /* Unknown parse mode with PM_FLAG_NO_CONTAINER */
            c = netsnmp_file_text_parse(fobj, NULL, 999, PM_FLAG_NO_CONTAINER,
                                        NULL);
            OK(c == NULL, "netsnmp_file_text_parse handles unknown parse_mode");

            netsnmp_file_release(fobj);
        }
    }
#endif

    /* 3. dir_utils: netsnmp_directory_container_read_some with NSFILE, STATS, and RECURSE */
#if !defined(NETSNMP_FEATURE_REMOVE_DIR_UTILS) && !defined(NETSNMP_FEATURE_REMOVE_FILE_UTILS_STATS)
    {
        netsnmp_container *dirc;

        dirc = netsnmp_directory_container_read_some(
            NULL, tmp_dir, NULL, NULL,
            NETSNMP_DIR_RECURSE | NETSNMP_DIR_NSFILE |
            NETSNMP_DIR_NSFILE_STATS);
        OK(dirc != NULL && CONTAINER_SIZE(dirc) >= 1,
           "netsnmp_directory_container_read_some recurses and populates netsnmp_file stats");
        if (dirc)
            netsnmp_directory_container_free(dirc);

        dirc = netsnmp_directory_container_read_some(
            NULL, tmp_sub, NULL, NULL, NETSNMP_DIR_RELATIVE_PATH);
        OK(dirc != NULL && CONTAINER_SIZE(dirc) == 1,
           "netsnmp_directory_container_read_some supports NETSNMP_DIR_RELATIVE_PATH");
        if (dirc)
            netsnmp_directory_container_free(dirc);

        dirc = netsnmp_directory_container_read_some(
            NULL, tmp_dir, NULL, NULL,
            NETSNMP_DIR_RELATIVE_PATH | NETSNMP_DIR_RECURSE);
        OK(dirc == NULL,
           "netsnmp_directory_container_read_some rejects NETSNMP_DIR_RELATIVE_PATH with NETSNMP_DIR_RECURSE");
    }
#endif

    unlink(tmp_file);
    rmdir(tmp_sub);
    rmdir(tmp_dir);

    /* 4. system.c: netsnmp_gethostbyname_v4 */
    {
        in_addr_t addr = 0;
        int rc;

        rc = netsnmp_gethostbyname_v4("127.0.0.1", &addr);
        OK(rc == 0 && addr == htonl(INADDR_LOOPBACK),
           "netsnmp_gethostbyname_v4 resolves 127.0.0.1");
        rc = netsnmp_gethostbyname_v4("nonexistent.invalid.", &addr);
        OK(rc == -1,
           "netsnmp_gethostbyname_v4 returns -1 for unresolvable host");
    }

    snmp_shutdown("T043utils_logging");
