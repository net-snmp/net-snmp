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
do_something_perlish(char *something)
{
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
    const char *embedargs[] = { "", "snmp_perl.pl" };

    DEBUGMSGTL(("perl", "initializing perl\n"));
    my_perl = perl_alloc();
    perl_construct(my_perl);
    perl_parse(my_perl, xs_init, 2, (char **) embedargs, NULL);
    perl_run(my_perl);
    DEBUGMSGTL(("perl", "done initializing perl\n"));

    /* register config handlers */
    snmpd_register_config_handler("perl", perl_config_handler, NULL,
                                  "PERLCODE");
}

void
shutdown_perl(void) 
{
    DEBUGMSGTL(("perl", "shutting down perl\n"));
    perl_destruct(my_perl);
    perl_free(my_perl);
    DEBUGMSGTL(("perl", "finished shutting down perl\n"));
}
