use ExtUtils::MakeMaker;
require 5;
use Config;
use Getopt::Long;

%MakeParams = InitMakeParams();

WriteMakefile(%MakeParams);


sub InitMakeParams {
    my %Params = (
		  'NAME'		=> 'NetSNMP::agent::default_store',
		  'VERSION_FROM'	=> 'default_store.pm', # finds $VERSION
		  );

    my $snmp_lib, $snmp_llib, $sep;
    if ($Config{'osname'} eq 'MSWin32') {
	$snmp_lib = 'libnetsnmp.lib';
	$snmp_link_lib = 'libnetsnmp';
	$sep = '\\';
	# XXX fix me
    } else {
	$nsconfig="net-snmp-config"; # in path by default
	GetOptions("NET-SNMP-CONFIG=s" => \$nsconfig,
		   "NET-SNMP-IN-SOURCE=s" => \$insource);
	$Params{'LIBS'}    = `$nsconfig --libs`;
	$Params{'CCFLAGS'} = `$nsconfig --cflags`;
	if ($insource eq "true") {
	    $Params{'LIBS'} = "-L../../../snmplib/.libs -L../../../snmplib/ " . $Params{'LIBS'};
	    $Params{'CCFLAGS'} = "-I../../../include " . $Params{'CCFLAGS'};
	}
	$Params{'CCFLAGS'} =~ s/ -W[-\w]+//g; # ignore developer warnings
	$prefix            = `$nsconfig --prefix`;
	chomp($prefix);
	$sep = '/';
	if ($Params{'LIBS'} eq "" || $Params{'CCFLAGS'} eq "") {
	    die "You need to install net-snmp first (I can't find net-snmp-config)";
	}
    }

    return(%Params);
}
