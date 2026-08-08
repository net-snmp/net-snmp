#!./perl

use strict;
use warnings;
BEGIN {
    my $has_vacm = 0;
    my $has_sys  = 0;
    my ($fh1, $fh2);
    if (open($fh1, "<../../include/net-snmp/agent/agent_module_config.h") || open($fh1, "<../../include/net-snmp/agent/mib_module_config.h")) {
        while (<$fh1>) {
            $has_vacm = 1 if /#define USING_MIBII_VACM_CONF_MODULE\b/;
        }
        close($fh1);
    }
    if (open($fh2, "<../../include/net-snmp/agent/mib_module_config.h")) {
        while (<$fh2>) {
            $has_sys = 1 if /#define USING_MIBII_SYSTEM_MIB_MODULE\b/;
        }
        close($fh2);
    }
    if (!$has_vacm || !$has_sys) {
        print "1..0 # Skip dump-session.t: required modules (vacm_conf/system_mib) not supported by agent\n";
        exit 0;
    }
}

use Test;

BEGIN {
    eval "use Cwd qw(abs_path)";
    plan tests => 1;
}

use SNMP;
use Data::Dumper;
require "t/startagent.pl";
use vars qw($agent_host $agent_port $comm);

# See also https://sourceforge.net/p/net-snmp/bugs/2488/

my $s = new SNMP::Session(DestHost=>$agent_host, Version=>1, Community=>$comm,
                          RemotePort=>$agent_port);

print Dumper($s->get('anything'));

ok(1);

snmptest_cleanup();
