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
    my %Params = (
		  NAME         => 'SNMP',
		  dist         => { SUFFIX => "gz", COMPRESS => "gzip -9f"},
		  MAN3PODS     => 'SNMP',  # Pods will be built by installman.
		  XSPROTOARG   => '-noprototypes', 	# XXX remove later?
		  VERSION_FROM => 'SNMP.pm',
		  realclean        => { FILES => 'host' },
		  );

    my $snmp_lib, $snmp_llib, $sep;
    if ($Config{'osname'} eq 'MSWin32') {
	$snmp_lib = 'libnetsnmp.lib';
	$snmp_link_lib = 'libnetsnmp';
	$sep = '\\';
	# XXX fix me
    } else {
	$Params{'LIBS'}    = `net-snmp-config --libs`;
	$Params{'CCFLAGS'} = `net-snmp-config --cflags`;
	$prefix            = `net-snmp-config --prefix`;
	chomp($prefix);
	$sep = '/';
	if ($Params{'LIBS'} eq "" || $Params{'CCFLAGS'} eq "") {
	    die "You need to install net-snmp first";
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
    my $mibdir = "${prefix}${sep}share${sep}snmp${sep}mibs";
    my $mibdir = find_files(["NET-SNMP-MIB.txt"],[$mibdir]);
    my $snmpd = find_files(["snmpd"], [$snmpd_path1, $snmpd_path2]);
    my $snmptrapd = find_files(["snmptrapd"], [$snmpd_path1, $snmpd_path2]);

    $mibdir ||= prompt("Unable to locate the MIBs, Please enter the path: ",
		       $snmpd_path1);
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
