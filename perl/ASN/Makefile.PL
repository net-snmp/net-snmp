use ExtUtils::MakeMaker;
require 5;
use Config;
use Getopt::Long;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

# we don't actually need these, but the net-snmp installation will
# pass it by default anyway.
GetOptions("NET-SNMP-CONFIG=s" => \$nsconfig,
	   "NET-SNMP-IN-SOURCE=s" => \$insource);
WriteMakefile(
    'NAME'		=> 'NetSNMP::ASN',
    'VERSION_FROM'	=> 'ASN.pm', # finds $VERSION
    'PREREQ_PM'		=> {}, # e.g., Module::Name => 1.1
    'LIBS'		=> [''], # e.g., '-lm'
    'DEFINE'		=> '', # e.g., '-DHAVE_SOMETHING'
    'INC'		=> '', # e.g., '-I/usr/include/other'
);
