use ExtUtils::MakeMaker;
require 5;
use Config;
use Getopt::Long;

%MakeParams = InitMakeParams();

WriteMakefile(%MakeParams);


sub InitMakeParams {
    my %Params = (
		  'NAME'		=> 'NetSNMP::agent',
		  'VERSION_FROM'	=> 'agent.pm', # finds $VERSION
		  'PREREQ_PM'           => {'NetSNMP::OID' => 0.1},
		  'PM'                => { 
		      'agent.pm' => '$(INST_LIBDIR)/agent.pm',
		      'netsnmp_request_info.pm' =>
			  '$(INST_LIBDIR)/agent/netsnmp_request_info.pm'
		  },
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
	$Params{'LIBS'}    = `$nsconfig --agent-libs`;
	$Params{'CCFLAGS'} = `$nsconfig --cflags`;
	if ($insource eq "true") {
	    $Params{'LIBS'} = "-L../../../snmplib/.libs -L../../../snmplib/ -L../../agent/.libs -L../../agent/ -L../../agent/helpers/.libs -L../../agent/helpers/ " . $Params{'LIBS'};
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
