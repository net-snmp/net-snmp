use ExtUtils::MakeMaker;
require 5;
use Config;
use Getopt::Long;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

%MakeParams = InitMakeParams();

WriteMakefile(%MakeParams);

sub InitMakeParams {
    my $opts;
    my %Params = (
		  'NAME'		=> 'NetSNMP::ASN',
		  'VERSION_FROM'	=> 'ASN.pm', # finds $VERSION
		  'XSPROTOARG'          => '-prototypes',
		  'PREREQ_PM'           => {},
		  );
    my ($snmp_lib, $snmp_llib, $sep);

    $opts = NetSNMPGetOpts();
    $Params{'LIBS'}    = `$opts->{'nsconfig'} --libs`;
    chomp($Params{'LIBS'});
    $Params{'CCFLAGS'} = `$opts->{'nsconfig'} --cflags`;
    chomp($Params{'CCFLAGS'});
    $Params{'CCFLAGS'} .= " " . $Config{'ccflags'};

    if ($opts->{'insource'} eq "true") {
	$Params{'LIBS'} = "-L../../snmplib/.libs -L../../snmplib/ " . $Params{'LIBS'};
	$Params{'CCFLAGS'} = "-I../../include " . $Params{'CCFLAGS'};
    }
    $Params{'CCFLAGS'} =~ s/ -W[-\w]+//g; # ignore developer warnings
    if ($Params{'LIBS'} eq "" || $Params{'CCFLAGS'} eq "") {
	die "You need to install net-snmp first (I can't find net-snmp-config)";
    }
    return (%Params);
}
# common subroutines -- DO NOT EDIT.
# They are imported from the Makefile.subs.pl file
sub NetSNMPGetOpts {
    my %ret;
    my $rootpath = shift;
    $rootpath = "../" if (!$rootpath);
    $rootpath .= '/' if ($rootpath !~ /\/$/);

    if ($ENV{'NET-SNMP-CONFIG'} && 
	$ENV{'NET-SNMP-IN-SOURCE'}) {
	# have env vars, pull from there
	$ret{'nsconfig'} = $ENV{'NET-SNMP-CONFIG'};
	$ret{'insource'} = $ENV{'NET-SNMP-IN-SOURCE'};
    } else {
	# don't have env vars, pull from command line and put there
	GetOptions("NET-SNMP-CONFIG=s" => \$ret{'nsconfig'},
		   "NET-SNMP-IN-SOURCE=s" => \$ret{'insource'});

	if ($ret{'insource'} eq "true" && $ret{'nsconfig'} eq "") {
	    $ret{'nsconfig'}="sh ROOTPATH../net-snmp-config";
	} elsif ($ret{'nsconfig'} eq "") {
	    $ret{'nsconfig'}="net-snmp-config";
	}

	$ENV{'NET-SNMP-CONFIG'}    = $ret{'nsconfig'};
	$ENV{'NET-SNMP-IN-SOURCE'} = $ret{'insource'};
    }	
    
    $ret{'nsconfig'} =~ s/ROOTPATH/$rootpath/;

    $ret{'rootpath'} = $rootpath;

    \%ret;
}
