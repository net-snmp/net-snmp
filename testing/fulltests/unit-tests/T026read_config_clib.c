/*
 * HEADER Testing read_config()
 */

static const unsigned char data[] = { 0xff, 0x20, 0xff };
char *path;
FILE *f;

register_mib_handlers();

OK(asprintf(&path, "/tmp/read-config-input-%d", getpid()) >= 0,
   "asprintf() failed");
f = fopen(path, "wb");
OK(f != NULL, "fopen() failed");
OK(fwrite(data, sizeof(data), 1, f) == 1, "fwrite() failed");
fclose(f);
read_config(path, read_config_get_handlers("snmp"), 0);
free(path);
