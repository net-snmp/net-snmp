use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'NetSNMP::agent',
    'VERSION_FROM'	=> 'agent.pm', # finds $VERSION
    'LIBS'		=> `net-snmp-config --agent-libs`,
);
