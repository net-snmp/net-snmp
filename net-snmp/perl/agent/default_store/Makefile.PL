use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'NetSNMP::agent::default_store',
    'VERSION_FROM'	=> 'default_store.pm', # finds $VERSION
    'LIBS'		=> `net-snmp-config --agent-libs`,
);
