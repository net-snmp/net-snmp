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
	$snmp_lib = 'libsnmp.lib';
	$snmp_link_lib = 'libsnmp';
	$sep = '\\';
    } else {
	$snmp_lib = 'libsnmp.a';
	$snmp_link_lib = 'snmp';
	$sep = '/';
    }
    $prefix="${sep}usr${sep}local";
    GetOptions("NET-SNMP-PATH=s" => \$prefix);

    my $inc_path1 = "${prefix}${sep}include";
    my $inc_path2 = "${sep}usr${sep}include";
    my $lib_path1 = "${prefix}${sep}lib";
    my $lib_path2 = "${sep}usr${sep}lib";

    my @IncludeFiles = qw[ucd-snmp/ucd-snmp-config.h
			  ucd-snmp/asn1.h ucd-snmp/mib.h ucd-snmp/parse.h
			  ucd-snmp/snmp.h ucd-snmp/snmp_api.h
			  ucd-snmp/snmp_client.h ucd-snmp/snmp_impl.h
			  ucd-snmp/scapi.h ucd-snmp/keytools.h
			  ucd-snmp/snmpv3.h ucd-snmp/transform_oids.h];

    my @IncludeDirs = ($inc_path2, $inc_path1);

    my $IncludeDir = find_files(\@IncludeFiles,\@IncludeDirs) ||
	prompt("Where are the ucd-snmp include files?","$inc_path1");

    my @LibDirs = ($lib_path1, $lib_path2);

    my $LibDir = find_files(["$snmp_lib"],\@LibDirs) ||
	prompt("Where is the ucd-snmp library installed?","$lib_path2");

    @IncludeFiles = map {"$IncludeDir$sep$_";} @IncludeFiles;
    $ssl_lib = ($^O =~ /win32/i ? 'libeay32.lib' : 'libcrypto.a');
    $ssl_link_lib = ($^O =~ /win32/i ? 'libeay32' : 'crypto');
    my $ssl_link_libs;
    if (HasSSL("$IncludeDir${sep}ucd-snmp/ucd-snmp-config.h")) {
	my @SSLLibDirs = ("/usr/local/lib", "/usr/local/ssl/lib", "/usr/lib");
	my $SSLLibDir = find_files([$ssl_lib], \@SSLLibDirs) ||
	    prompt("Where is the SSL library installed?", $SSLLibDirs[1]);
	$ssl_link = "-L$SSLLibDir -l$ssl_link_lib" if $SSLLibDir;
    }
    $Params{LIBS} = "-L$LibDir -l$snmp_link_lib $ssl_link";
    $Params{INC}  = "-I$IncludeDir";
    $Params{H}    = \@IncludeFiles;
    $Params{LDFLAGS} = "-L$LibDir $Config{ldflags}";
    $Params{LDDLFLAGS} = "-L$LibDir $Config{lddlflags}";

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
    my $mibdir = "${prefix}${sep}share${sep}snmp${sep}mibs";
    my $snmpd_path2 = "${sep}usr${sep}sbin";
    my $snmpd_path3 = "${sep}usr${sep}bin";
    open(H, ">$info_file") || die "Error: could not open file '$info_file'($!)";
    if($^O =~ /win32/i) {
#you are using WIN 32
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
    my $mibdir = find_files(["UCD-SNMP-MIB.txt"],[$mibdir]);
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
