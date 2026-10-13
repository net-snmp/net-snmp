/*
 * HEADER Testing read_mib()
 *
 * See also https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=37187.
 * See also https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=39320.
 */

static const char* mibs[] = {
    "qu::=Opaque(SIZE(SI4-\n"
    "--\n"
    "--\n"
    "--\n"
    "--\n"
    "--\n"
    "--\n"
    "--\n"
    "OCTETSTRING\n"
    "----\n"
    "--\n"
    "--\n"
    "---\n"
    "--\n"
    "--\n"
    "-68--------------------1844674407370954460124----DD-IIIIIIIIIII0NZe9223300000446069494I32768g-I2768g-I3gg-I4g-55I420RPRISEOONOAO:\x001\0\0---::=\0||231\0\0\0\x001=O",
    "102H::={1365\x93""-72}1H::={1\x93""1}0H::={0\x93""0}",
    "TEST-EOF-MIB DEFINITIONS ::= BEGIN\n"
    "grp OBJECT-GROUP OBJECTS { obj } STATUS current DESCRIPTION \"d\" ::= { 1 1 }\n",
    "TEST-MULTI-MIB DEFINITIONS ::= BEGIN\nEND\nEND\n",
    "TEST-FIRST-MIB DEFINITIONS ::= BEGIN\n"
    "IMPORTS OBJECT-GROUP FROM SNMPv2-CONF\n"
    "        NOTIFICATION-TYPE, enterprises FROM SNMPv2-SMI;\n"
    "firstRoot OBJECT IDENTIFIER ::= { enterprises 99991 }\n"
    "firstGrp OBJECT-GROUP OBJECTS { firstObj1, firstObj2 } STATUS current DESCRIPTION \"g1\" ::= { firstRoot 1 }\n"
    "firstNotif NOTIFICATION-TYPE OBJECTS { firstObj1 } STATUS current DESCRIPTION \"n1\" ::= { firstRoot 2 }\n"
    "END\n"
    "TEST-SECOND-MIB DEFINITIONS ::= BEGIN\n"
    "IMPORTS OBJECT-GROUP FROM SNMPv2-CONF\n"
    "        NOTIFICATION-TYPE, enterprises FROM SNMPv2-SMI;\n"
    "secondRoot OBJECT IDENTIFIER ::= { enterprises 99992 }\n"
    "secondGrp OBJECT-GROUP OBJECTS { secondObj1, secondObj2 } STATUS current DESCRIPTION \"g2\" ::= { secondRoot 1 }\n"
    "secondNotif NOTIFICATION-TYPE OBJECTS { secondObj1 } STATUS current DESCRIPTION \"n2\" ::= { secondRoot 2 }\n"
};

char *path;
FILE *f;
int i, res;

res = asprintf(&path, "/tmp/read-mib-input-%d", getpid());
OKF(res >= 0, ("asprintf() returned %d", res));
for (i = 0; i < sizeof(mibs) / sizeof(mibs[0]); i++) {
    f = fopen(path, "wb");
    OKF(f != NULL, ("fopen() %s", f ? "succeeded" : "failed"));
    res = fwrite(mibs[i], strlen(mibs[i]), 1, f);
    OKF(res == 1, ("fwrite() %s", res == 1 ? "succeeded" : "failed"));
    fclose(f);
    read_mib(path);
    unlink(path);
}
free(path);
unload_all_mibs();
