#include <EXTERN.h>
#include "perl.h"

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

static PerlInterpreter *my_perl;

void boot_DynaLoader (CV* cv);

void
xs_init(void)
{
    char myfile[] = __FILE__;
    char modulename[] = "DynaLoader::boot_DynaLoader";
    /* DynaLoader is a special case */
    newXS(modulename, boot_DynaLoader, myfile);
}

void
maybe_source_perl_startup(void) 
{
    const char *embedargs[] = { "", "" };
    const char *perl_init_file = ds_get_string(DS_APPLICATION_ID,
                                               DS_AGENT_PERL_INIT_FILE);
    char init_file[SNMP_MAXBUF];

    static int have_done_init = 0;

    if (have_done_init)
        return;
    have_done_init = 1;
    
    if (!perl_init_file) {
        snprintf(init_file, sizeof(init_file)-1,
                 "%s/%s", SNMPSHAREPATH, "snmp_perl.pl");
        perl_init_file = init_file;
    }
    embedargs[1] = perl_init_file;

    DEBUGMSGTL(("perl", "initializing perl (%s)\n", embedargs[1]));
    my_perl = perl_alloc();
    perl_construct(my_perl);
    perl_parse(my_perl, xs_init, 2, (char **) embedargs, NULL);
    perl_run(my_perl);
    DEBUGMSGTL(("perl", "done initializing perl\n"));
}

void
do_something_perlish(char *something)
{
    if (ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_DISABLE_PERL))
        return;
    maybe_source_perl_startup();
    DEBUGMSGTL(("perl", "calling perl\n"));
    eval_pv(something, TRUE);
    DEBUGMSGTL(("perl", "finished calling perl\n"));
}

void perl_config_handler(const char *token, char *line) 
{
    do_something_perlish(line);
}

void
init_perl(void) 
{
    const char *appid = ds_get_string(DS_LIBRARY_ID, DS_LIB_APPTYPE);
    const char *defaultid = "snmpd";

    if (!appid)
        appid = defaultid;
    
    /* register config handlers */
    snmpd_register_config_handler("perl", perl_config_handler, NULL,
                                  "PERLCODE");

    /* define the perlInitFile token to point to an init file */
    ds_register_config(ASN_OCTET_STR, appid, "perlInitFile",
                       DS_APPLICATION_ID, DS_AGENT_PERL_INIT_FILE);

    /* define the perlInitFile token to point to an init file */
    ds_register_config(ASN_BOOLEAN, appid, "disablePerl",
                       DS_APPLICATION_ID, DS_AGENT_DISABLE_PERL);
}

void
shutdown_perl(void) 
{
    if (ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_DISABLE_PERL))
        return;
    DEBUGMSGTL(("perl", "shutting down perl\n"));
    perl_destruct(my_perl);
    perl_free(my_perl);
    DEBUGMSGTL(("perl", "finished shutting down perl\n"));
}
