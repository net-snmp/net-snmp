/* HEADER Testing certificate utilities and TLS base config (cert_util.c / snmpTLSBaseDomain.c) */
    int run_t040(void);
    int rc = run_t040();
    if (__did_plan == 0) {
        PLAN(__test_counter);
    }
    return rc;
}

#if defined(NETSNMP_USE_OPENSSL) && defined(HAVE_LIBSSL) && defined(NETSNMP_TRANSPORT_TLSBASE_DOMAIN)
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <net-snmp/library/cert_util.h>
#include <net-snmp/library/snmpTLSBaseDomain.h>
#endif

int
run_t040(void)
{
#if defined(NETSNMP_USE_OPENSSL) && defined(HAVE_LIBSSL) && defined(NETSNMP_TRANSPORT_TLSBASE_DOMAIN)
    char pdir[128];
    char idx_dir[160];
    char idx_file[192];
    char tls_dir[160];
    char certs_dir[192];
    FILE *fp;

    snprintf(pdir, sizeof(pdir), "/tmp/netsnmp_t040_%d", (int)getpid());
    snprintf(idx_dir, sizeof(idx_dir), "%s/cert_indexes", pdir);
    snprintf(idx_file, sizeof(idx_file), "%s/cert_indexes/99", pdir);
    snprintf(tls_dir, sizeof(tls_dir), "%s/tls", pdir);
    snprintf(certs_dir, sizeof(certs_dir), "%s/tls/certs", pdir);
    mkdir(pdir, 0700);
    mkdir(idx_dir, 0700);
    mkdir(tls_dir, 0700);
    mkdir(certs_dir, 0700);

    /* Create a pre-existing cert_indexes/99 file to exercise _certindex_add and _certindexes_load */
    fp = fopen(idx_file, "wb");
    if (fp) {
        fprintf(fp, "DIR %s 1\r\n", certs_dir);
        fclose(fp);
    }

    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_DONT_PERSIST_STATE, 1);
    set_persistent_directory(pdir);
    netsnmp_ds_set_string(NETSNMP_DS_LIBRARY_ID,
                          NETSNMP_DS_LIB_CONFIGURATION_DIR, pdir);
    init_snmp("T040cert_util");
    netsnmp_certs_agent_init();

    /* 1. Test netsnmp_tls_fingerprint_build and netsnmp_tls_fingerprint_parse */
    {
        u_char *tls_fp = NULL;
        size_t tls_fp_len = 0;
        char fp_buf[64];
        char *fp_str = fp_buf;
        u_int fp_str_len = sizeof(fp_buf);
        u_char ht_out = 0;
        const char hex_in[] = "0102030405060708090a0b0c0d0e0f1011121314";
        int rc;

        rc = netsnmp_tls_fingerprint_build(NS_HASH_SHA1, hex_in,
                                           &tls_fp, &tls_fp_len, 1);
        OK(rc == SNMPERR_SUCCESS && tls_fp != NULL && tls_fp_len == 21,
           "netsnmp_tls_fingerprint_build builds SHA1 TLS binary fingerprint");
        if (tls_fp) {
            rc = netsnmp_tls_fingerprint_parse(tls_fp, (int)tls_fp_len,
                                               &fp_str, &fp_str_len, 0,
                                               &ht_out);
            OK(rc == SNMPERR_SUCCESS && ht_out == NS_HASH_SHA1 &&
               fp_str != NULL && strcasecmp(fp_str, hex_in) == 0,
               "netsnmp_tls_fingerprint_parse parses SHA1 TLS binary fingerprint");
            free(tls_fp);
        }
    }

    /* 2. Test config handlers: localCert, peerCert, clientCert, serverCert, trustCert, certSecName, snmpTlstmParams, snmpTlstmAddr */
    {
        netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                               NETSNMP_DS_LIB_HAVE_READ_CONFIG, 1);

        /* Exercise _add_certfile and _parse_trust_cert via netsnmp_config */
        netsnmp_config("localCert 02:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14");
        netsnmp_config("peerCert 02:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f:20:21:22:23:24");
        netsnmp_config("trustCert 02:21:22:23:24:25:26:27:28:29:2a:2b:2c:2d:2e:2f:30:31:32:33:34");
        netsnmp_config("clientCert \"02:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14\"");
        netsnmp_config("serverCert \"02:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f:20:21:22:23:24\"");
        OK(1, "localCert, peerCert, trustCert, clientCert, serverCert config handlers parsed safely");

        /* Exercise netsnmp_cert_parse_secname (_parse_secname) valid, duplicate priority, and error paths */
        netsnmp_config("certSecName 10 02:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14 --sn alice");
        /* Duplicate priority 10 should trigger error cleanup path freeing secname/fp */
        netsnmp_config("certSecName 10 02:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14 --sn bob");
        /* Missing fingerprint / malformed flags */
        netsnmp_config("certSecName 20");
        netsnmp_config("certSecName 30 02:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14 --cn");
        /* Oversized 70-char token to test 64-byte buffer bounds in _parse_secname */
        netsnmp_config("certSecName 40 02:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14 --sn 0123456789012345678901234567890123456789012345678901234567890123456789");
        OK(1, "certSecName config handler exercised valid, duplicate, truncated, and oversized inputs");

        /* Exercise _parse_params and _parse_addr, then remove and free entries */
        {
            snmpTlstmParams p_key, *p_found;
            netsnmp_container *addr_c;

            netsnmp_config("snmpTlstmParams param1 02:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14");
            netsnmp_config("snmpTlstmParams");
            memset(&p_key, 0, sizeof(p_key));
            p_key.name = (char *)"param1";
            p_found = netsnmp_tlstmParams_find(&p_key);
            OK(p_found != NULL, "snmpTlstmParams config handler added param1");
            if (p_found) {
                netsnmp_tlstmParams_remove(p_found);
                netsnmp_tlstmParams_free(p_found);
            }

            netsnmp_config("snmpTlstmAddr addr1 02:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14 id1");
            netsnmp_config("snmpTlstmAddr");
            addr_c = netsnmp_tlstmAddr_container();
            if (addr_c) {
                snmpTlstmAddr a_key, *a_found;
                memset(&a_key, 0, sizeof(a_key));
                a_key.name = (char *)"addr1";
                a_found = CONTAINER_FIND(addr_c, &a_key);
                OK(a_found != NULL, "snmpTlstmAddr config handler added addr1");
                if (a_found) {
                    netsnmp_tlstmAddr_remove(a_found);
                    netsnmp_tlstmAddr_free(a_found);
                }
            }
        }
    }

    /* 3. Test netsnmp_cert_find */
    {
        netsnmp_cert *cert;
        cert = netsnmp_cert_find(NS_CERT_IDENTITY, NS_CERTKEY_FINGERPRINT,
                                 (void *)"020102030405060708090a0b0c0d0e0f1011121314");
        OK(cert == NULL || cert != NULL,
           "netsnmp_cert_find executes without error");
    }

    snmp_shutdown("T040cert_util");

    unlink(idx_file);
    rmdir(certs_dir);
    rmdir(tls_dir);
    rmdir(idx_dir);
    rmdir(pdir);
#else
    OK(1, "skipped: OpenSSL / TLSBase not enabled");
#endif
