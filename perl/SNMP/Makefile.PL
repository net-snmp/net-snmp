use ExtUtils::MakeMaker;
require 5;
use Config;

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
	$snmp_lib = 'libsnmp.dll';
	$snmp_link_lib = 'libsnmp';
	$sep = '\\';
    } else {
	$snmp_lib = 'libsnmp.a';
	$snmp_link_lib = 'snmp';
	$sep = '/';
    }
    my $inc_path1 = "${sep}usr${sep}local${sep}include";
    my $inc_path2 = "${sep}usr${sep}include";
    my $lib_path1 = "${sep}usr${sep}local${sep}lib";
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

    my $ssl_link_libs;
    if (HasSSL("$IncludeDir${sep}ucd-snmp/ucd-snmp-config.h")) {
	my @SSLLibDirs = ("/usr/local/lib", "/usr/local/ssl/lib", "/usr/lib");
	my $SSLLibDir = find_files(["libcrypto.a"], \@SSLLibDirs) ||
	    prompt("Where is the SSL library installed?", $SSLLibDirs[1]);
	$ssl_link_lib = "-L$SSLLibDir -lcrypto" if $SSLLibDir;
    }
    $Params{LIBS} = "-L$LibDir -l$snmp_link_lib $ssl_link_lib";
    $Params{INC}  = "-I$IncludeDir";
    $Params{H}    = \@IncludeFiles;

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
    my $info_file = "t${sep}snmpd.cmd";
    my $snmpd_path1 = "${sep}usr${sep}local${sep}sbin";
    my $snmpd_path2 = "${sep}usr${sep}sbin";

    open(H, ">$info_file") || die "Error: could not open file '$info_file'($!)";

    my $snmpd = find_files(["snmpd"], [$snmpd_path1, $snmpd_path2]);

    $snmpd = prompt("Unable to locate \"snmpd\". Please enter the path: ") 
	unless $snmpd;

    $snmpd =~ s/($sep)?(snmpd)?$/${sep}snmpd/;

    if (-e $snmpd and -r $snmpd) {
	if (not -x $snmpd) {
	    warn("Error: $snmpd not executable. 'make test' will not work.\n");
	} else {
	    print H "SNMPD => $snmpd\n";
	}
    } else {
	warn("Error: $snmpd does not exist or is unreadable. 'make test' will not work.\n");
    }

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
	$has_ssl++, last if /^\s*#define\s+USE_OPENSSL\s+1/;
    }
    close C;
    return $has_ssl;
}
