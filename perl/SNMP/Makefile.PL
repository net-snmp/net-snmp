use ExtUtils::MakeMaker;
require 5;
use Config;
use Getopt::Long;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

%MakeParams = InitMakeParams();

WriteMakefile(%MakeParams);

GetTestInfo();

sub InitMakeParams {
    my $opts;
    my %Params = (
		  NAME         => 'SNMP',
		  dist         => { SUFFIX => "gz", COMPRESS => "gzip -9f"},
		  MAN3PODS => { 'SNMP.pm' => '$(INST_MAN3DIR)/SNMP.3' },
		  XSPROTOARG   => '-noprototypes', 	# XXX remove later?
		  VERSION_FROM => 'SNMP.pm',
		  realclean        => { FILES => 'host' },
		  );

    my ($snmp_lib, $snmp_llib, $sep);
    if ($Config{'osname'} eq 'MSWin32') {
	$snmp_lib = 'libnetsnmp.lib';
	$snmp_link_lib = 'libnetsnmp';
	$sep = '\\';
	# XXX fix me
    } else {
	$opts = NetSNMPGetOpts();
	if (!$ENV{'NETSNMP_LIBS'}) {
	    $Params{'LIBS'}    = `$opts->{'nsconfig'} --libs`;
	    chomp($Params{'LIBS'});
	} else {
	    $Params{'LIBS'} = $ENV{'NETSNMP_LIBS'};
	}
	if (!$ENV{'NETSNMP_CCFLAGS'}) {
	    $Params{'CCFLAGS'} = `$opts->{'nsconfig'} --cflags`;
	    chomp($Params{'CCFLAGS'});
	    $Params{'CCFLAGS'} .= " " . $Config{'ccflags'};
	} else {
	    $Params{'CCFLAGS'} = $ENV{'NETSNMP_CCFLAGS'};
	}
	if ($opts->{'insource'} eq "true") {
	    $Params{'LIBS'} = "-L../../snmplib/.libs -L../../snmplib/ " . $Params{'LIBS'};
	    $Params{'CCFLAGS'} = "-I../../include " . $Params{'CCFLAGS'};
#	} else {
#	    $Params{'PREREQ_PM'} = { 'NetSNMP::default_store' => 0.01 };
	}
	$Params{'CCFLAGS'} =~ s/ -W[-\w]+//g; # ignore developer warnings
	if (!$ENV{'NETSNMP_PREFIX'}) {
	    $prefix            = `$opts->{'nsconfig'} --prefix`;
	    chomp($prefix);
	    $sep = '/';
	} else {
	    $prefix = $ENV{'NETSNMP_PREFIX'};
	}
	if ($Params{'LIBS'} eq "" || $Params{'CCFLAGS'} eq "") {
	    die "You need to install net-snmp first (I can't find net-snmp-config)";
	}
    }

    return(%Params);

}

sub find_files {
    my($f,$d) = @_;
    my ($dir,$found,$file);
    for $dir (@$d){
	$found = 0;
	for $file (@$f) {
	    $found++ if -f "$dir/$file";
	}
	if ($found == @$f) {
	    return $dir;
	}
    }
}

sub GetTestInfo {
    my $sep = ($^O =~ /win32/i ? '\\' : '/');
    my $info_file = "t${sep}snmptest.cmd";
    my $snmpd_path1 = "${prefix}${sep}sbin";
    my $snmpd_path2 = "${sep}usr${sep}sbin";
    my $snmpd_path3 = "${sep}usr${sep}bin";
    open(H, ">$info_file") || die "Error: could not open file '$info_file'($!)";
    if($^O =~ /win32/i) {
#you are using WIN 32
	my $mibdir = "${prefix}${sep}share${sep}snmp${sep}mibs";
	print <<WIN32
==================================================================
You are using Windows 32. The testing of Perl/SNMP API here would
require you to start an snmpd agent and a trap receiver using the
config file provided ( t\\snmptest.conf) manually.The
test scripts will not do this(as in unix testing). So, please
run those agents and enter the following information.If the data
about host, agent_port and trap_port are already present in your
snmptest.cmd file, make test will use those data for testing.
=================================================================
WIN32
;

	$host = prompt("Please enter the host IP address/host name: ", "localhost");
	print H "HOST => $host\n";
	$agent_port = prompt("Please enter the agent port number: ", 161);
	print H "AGENT_PORT => $agent_port\n";
	$trap_port = prompt("Please enter the trap port number: ", 162);
	print H "TRAP_PORT => $trap_port\n";
	$mibdir = prompt("Please enter the MIB directory: ", "/usr/mibs");
	print H "MIBDIR => $mibdir\n";
    } else {
# you are using UNIX
	my ($mibdir, $snmpd, $snmptrapd);
	if ($opts->{'insource'} eq "true") {
	    $mibdir = "../../mibs";
	    $snmpd = "../../agent/snmpd";
	    $snmptrapd = "../../apps/snmptrapd";
	} else {
	    $mibdir = "${prefix}${sep}share${sep}snmp${sep}mibs";
	    $snmpd = find_files(["snmpd"], [$snmpd_path1, $snmpd_path2]);
	    $snmptrapd = find_files(["snmptrapd"], [$snmpd_path1, $snmpd_path2]);
	}
	$mibdir = find_files(["NET-SNMP-MIB.txt"],[$mibdir]);

	$mibdir ||= prompt("Unable to locate the MIBs, Please enter the path: ",
			   $mibdir);
	$snmpd ||= prompt("Unable to locate \"snmpd\". Please enter the path: ",
			  $snmpd_path1);
	$snmptrapd ||=
	    prompt("Unable to locate \"snmptrapd\". Please enter the path: ",
		   $snmpd_path1);

        $snmpd =~ s/($sep)?(snmpd)?$/${sep}snmpd/;
        $snmptrapd =~ s/($sep)?(snmptrapd)?$/${sep}snmptrapd/;

	print H "SNMPD => $snmpd\n";
	print H "SNMPTRAPD => $snmptrapd\n";
	print H "MIBDIR => $mibdir\n";

	if (!$opts->{'insource'}) {
	    if (-e $snmpd and -r $snmpd) {
		if (not -x $snmpd) {
		    warn("Error: $snmpd not executable. 'make test' will not work.\n");
		}
	    } else {
		warn("Error: $snmpd does not exist or is unreadable. 'make test' will not work.\n");
	    }

	    if (-e $snmptrapd and -r $snmptrapd) {
		if (not -x $snmptrapd) {
		    warn("Error: $snmptrapd not executable. 'make test' will not work.\n");
		}
	    } else {
		warn("Error: $snmptrapd does not exist or is unreadable. 'make test' will not work.\n");
	    }
	}
    }
# end of else
    close H;
}

sub HasSSL {
    my $config_header = shift;
    my $has_ssl;
    unless (open(C,"<$config_header")) {
	warn("Unable to open $config_header, assuming no SSL\n");
	return undef;
    }
    while (<C>) {
	$has_ssl++, last if /^\s*#define\s+USE_OPENSSL/;
    }
    close C;
    return $has_ssl;
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
