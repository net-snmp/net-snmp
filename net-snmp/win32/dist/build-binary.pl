#!/usr/bin/perl
# 
# Build script for Net-SNMP and MSVC
# Written by Alex Burger - alex_b@users.sourceforge.net
# May 10th, 2009
#
use strict;
use File::Copy;
use Cwd 'abs_path';

print "------------------------------------------------------\n";

my $tar_command = 'C:\msys\1.0\bin\tar.exe';
my $gzip_command = 'C:\msys\1.0\bin\gzip.exe';

if (! (-f $tar_command)) {
  die ("Could not find tar command ($tar_command)");
}
else {
  print "tar command:  $tar_command\n";
}
if (! (-f $gzip_command)) {
  die ("Could not find gzip command ($gzip_command)");
}
else {
  print "gzip command: $tar_command\n";
}

my $version = "unknown";
my $version_for_perl = "unknown";
my $version_maj;
my $version_min;
my $version_rev;
my $installer_exe_version = 1;
my $openssl = "disabled";
my $b_ipv6 = "disabled";
my $b_winextdll = "disabled";
my $sdk = "disabled";
my $default_install_base = "c:/usr";
my $install_base = $default_install_base;
my $install = "enabled";
my $install_devel = "disabled";
my $perl = "disabled";
my $perl_install = "disabled";
my $logging = "enabled";
my $debug = "disabled";
my $configOpts = "";
my $cTmp = "";
my $linktype = "static";
my $option;

# Prepend win32\ if running from main directory
my $current_pwd = `%COMSPEC% /c cd`;
chomp $current_pwd;
my $top_dir;
my $win32_dir;
my $perl_dir;

if ($current_pwd =~ /\\win32\\dist$/) {
  $win32_dir = "$current_pwd/../";
  $top_dir = "$current_pwd/../../";
  $perl_dir = "$current_pwd/../../perl/";
}
elsif ($current_pwd =~ /\\win32$/) {
  $win32_dir = $current_pwd;
  $top_dir = "$current_pwd/../";
  $perl_dir = "$current_pwd/../perl/";
}
else {  # Assume top level folder
  $win32_dir = "$current_pwd/win32/";
  $top_dir = $current_pwd;
  $perl_dir = "$current_pwd/perl/";
}

$top_dir = abs_path($top_dir);
$win32_dir = abs_path($win32_dir);
$perl_dir = abs_path($perl_dir);


print "\ntop_dir:      $top_dir\n";
print "win32_dir:    $win32_dir\n";
print "perl_dir:     $perl_dir\n";
print "install base: $install_base\n\n";

chdir $win32_dir;

if ( -d "dist" ) { }
else {
  print "\nPlease copy the win32/dist folder from trunk to $win32_dir/\n\n";
  exit;
}

if ( -d $ENV{MSVCDir} || -d $ENV{VCINSTALLDIR}) {
}
else {
  print "\nPlease run VCVARS32.BAT first to set up the Visual Studio build\n" .
        "environment.\n\n";
  exit;
}

if ( -d $install_base) {
  print "\nPlease delete or rename the $install_base folder.\n\n";
  exit;
}

my $system_netsnmpdll = "$ENV{WINDIR}\\system32\\netsnmp.dll";
if ( -f $system_netsnmpdll) {
  print "\n$system_netsnmpdll should be renamed or deleted.\n\n";
  
  print "Would you like me to delete it? (y/n?)";
  $| = 1;
  my $temp = <STDIN>;
  chomp $temp;
  if (lc($temp) eq "y" || lc($temp) eq "yes") {
    unlink $system_netsnmpdll || die "Could not delete file $system_netsnmpdll\n";
  }
  else {
    exit;
  }
}

###############################################
#
# Determine version from unix configure script
#
###############################################

my $unix_configure_in = "../configure";

open (UNIX_CONFIGURE_IN, "<$unix_configure_in") || die "Can't Open $unix_configure_in\n";

while (<UNIX_CONFIGURE_IN>)
{
  chomp;
  /PACKAGE_VERSION='(.*)'/;
  if ($1 ne "") {
    $version = $1;
    last;
  }
}
close UNIX_CONFIGURE_IN;

# Determine version for Perl (4 characters with commas)
$version_for_perl = $version;
my $dotCount = ($version =~ tr/.//);
while ($dotCount < 3) {
  $version_for_perl .= ".0";
  $dotCount++;
}
$version_for_perl =~ s/\./,/g;

# Determine version for NSIS installer
my @version_array = split(/\./, $version);
$version =~ /.*?\..*?\.(.*)/;
$version_rev = $1 || 0;
$version_maj = $version_array[0] || 0;
$version_min = $version_array[1] || 0;

print "Net-SNMP version:      $version\n";
print "Net-SNMP Perl version: $version_for_perl\n";
print "Net-SNMP version MAJ:  $version_maj\n";
print "Net-SNMP version MIN1: $version_min\n";
print "Net-SNMP version MIN2: $version_rev\n\n";

#goto skip1;
#exit;



#***************************************************************
# Common build options:
$b_ipv6 = "enabled";
$sdk = "enabled";
$default_install_base = "c:/usr";
$install_base = $default_install_base;
$perl_install = "disabled";
$debug = "disabled";
$configOpts = "";
$cTmp = "";
$linktype = "dynamic";

#***************************************************************
# Build binary:
# winExtDLL = disabled
# SSL = enabled
$openssl = "enabled";
$b_winextdll = "disabled";
$perl = "enabled";
$install = "enabled";
$install_devel = "enabled";

print "\n\nBuilding with options:\n";
print "======================\n\n";
print "1.  OpenSSL support:                " . $openssl. "\n";
print "2.  Platform SDK support:           " . $sdk . "\n";
print "\n";
print "3.  Install path:                   " . $install_base . "\n";
print "4.  Install after build:            " . $install . "\n";
print "\n";
print "5.  Perl modules:                   " . $perl . "\n";
print "6.  Install perl modules:           " . $perl_install . "\n";
print "\n";
print "7.  Quiet build (logged):           " . $logging . "\n";
print "8.  Debug mode:                     " . $debug . "\n";
print "\n";
print "9.  IPv6 transports (requires SDK): " . $b_ipv6 . "\n";
print "10. winExtDLL agent (requires SDK): " . $b_winextdll . "\n";
print "\n";
print "11. Link type:                      " . $linktype . "\n";
print "\n";
print "12. Install development files       " . $install_devel . "\n";

chdir $win32_dir;
&build();
&create_perl_package();

print "\nCleaning up $install_base/snmp/persist/\n";
unlink ("$install_base/snmp/persist/snmpd.conf");
unlink ("$install_base/snmp/persist/snmptrapd.conf");

#***************************************************************
# Build binary:
# winExtDLL = enabled
# SSL = enabled
$openssl = "enabled";
$b_winextdll = "enabled";
$perl = "disabled";
$install = "disabled";
$install_devel = "disabled";

print "\n\nBuilding with options:\n";
print "======================\n\n";
print "1.  OpenSSL support:                " . $openssl. "\n";
print "2.  Platform SDK support:           " . $sdk . "\n";
print "\n";
print "3.  Install path:                   " . $install_base . "\n";
print "4.  Install after build:            " . $install . "\n";
print "\n";
print "5.  Perl modules:                   " . $perl . "\n";
print "6.  Install perl modules:           " . $perl_install . "\n";
print "\n";
print "7.  Quiet build (logged):           " . $logging . "\n";
print "8.  Debug mode:                     " . $debug . "\n";
print "\n";
print "9.  IPv6 transports (requires SDK): " . $b_ipv6 . "\n";
print "10. winExtDLL agent (requires SDK): " . $b_winextdll . "\n";
print "\n";
print "11. Link type:                      " . $linktype . "\n";
print "\n";
print "12. Install development files       " . $install_devel . "\n";

chdir $win32_dir;
&build();

print "\nCopying snmpd.exe to snmpd-winExtDLL.exe\n";
copy("bin/release/snmpd.exe","$install_base/bin/snmpd-winExtDLL.exe") || die ("Could not copy snmpd.exe to snmpd-winExtDLL.exe: $?");

print "\nCleaning up $install_base/snmp/persist/\n";
unlink ("$install_base/snmp/persist/snmpd.conf");
unlink ("$install_base/snmp/persist/snmptrapd.conf");


print "Renaming $install_base/bin to $install_base/bin.ssl\n";
rename ("$install_base/bin","$install_base/bin.ssl") || die ("Could not rename folder: $?");
print "Renaming $install_base/lib to $install_base/lib.ssl\n";
rename ("$install_base/lib","$install_base/lib.ssl") || die ("Could not rename folder: $?");
print "Renaming $install_base/perl to $install_base/perl.ssl\n";
rename ("$install_base/perl","$install_base/perl.ssl") || die ("Could not rename folder: $?");

#***************************************************************


#***************************************************************
# Build binary:
# winExtDLL = disabled
# SSL = disabled
$openssl = "disabled";
$b_winextdll = "disabled";
$perl = "enabled";
$install = "enabled";
$install_devel = "enabled";

print "\n\nBuilding with options:\n";
print "======================\n\n";
print "1.  OpenSSL support:                " . $openssl. "\n";
print "2.  Platform SDK support:           " . $sdk . "\n";
print "\n";
print "3.  Install path:                   " . $install_base . "\n";
print "4.  Install after build:            " . $install . "\n";
print "\n";
print "5.  Perl modules:                   " . $perl . "\n";
print "6.  Install perl modules:           " . $perl_install . "\n";
print "\n";
print "7.  Quiet build (logged):           " . $logging . "\n";
print "8.  Debug mode:                     " . $debug . "\n";
print "\n";
print "9.  IPv6 transports (requires SDK): " . $b_ipv6 . "\n";
print "10. winExtDLL agent (requires SDK): " . $b_winextdll . "\n";
print "\n";
print "11. Link type:                      " . $linktype . "\n";
print "\n";
print "12. Install development files       " . $install_devel . "\n";

chdir $win32_dir;
&build();
&create_perl_package();

print "\nCleaning up $install_base/snmp/persist/\n";
unlink ("$install_base/snmp/persist/snmpd.conf");
unlink ("$install_base/snmp/persist/snmptrapd.conf");

#***************************************************************
# Build binary:
# winExtDLL = enabled
# SSL = disabled
$openssl = "disabled";
$b_winextdll = "enabled";
$perl = "disabled";
$install = "disabled";
$install_devel = "disabled";

print "\n\nBuilding with options:\n";
print "======================\n\n";
print "1.  OpenSSL support:                " . $openssl. "\n";
print "2.  Platform SDK support:           " . $sdk . "\n";
print "\n";
print "3.  Install path:                   " . $install_base . "\n";
print "4.  Install after build:            " . $install . "\n";
print "\n";
print "5.  Perl modules:                   " . $perl . "\n";
print "6.  Install perl modules:           " . $perl_install . "\n";
print "\n";
print "7.  Quiet build (logged):           " . $logging . "\n";
print "8.  Debug mode:                     " . $debug . "\n";
print "\n";
print "9.  IPv6 transports (requires SDK): " . $b_ipv6 . "\n";
print "10. winExtDLL agent (requires SDK): " . $b_winextdll . "\n";
print "\n";
print "11. Link type:                      " . $linktype . "\n";
print "\n";
print "12. Install development files       " . $install_devel . "\n";

chdir $win32_dir;
&build();

print "\nCopying snmpd.exe to snmpd-winExtDLL.exe\n";
copy("bin/release/snmpd.exe","$install_base/bin/snmpd-winExtDLL.exe") || die ("Could not copy snmpd.exe to snmpd-winExtDLL.exe: $?");

print "\nCleaning up $install_base/snmp/persist/\n";
unlink ("$install_base/snmp/persist/snmpd.conf");
unlink ("$install_base/snmp/persist/snmptrapd.conf");

#***************************************************************

print "\n\nCopying dist files:\n";
print "===================\n\n";

mkdir ("$install_base/docs");
mkdir ("$install_base/temp");

&check_dir_exists("$install_base/docs");
&check_dir_exists("$install_base/temp");

chdir $top_dir;
copy("COPYING","$install_base/docs/") || die ("Could not copy file: $?");
copy('win32\dist\README.txt',"$install_base/") || die ("Could not copy file: $?");
copy('win32\dist\scripts\net-snmp-perl-test.pl',"$install_base/bin/") || die ("Could not copy file: $?");


skip1:

#***************************************************************

print "\n\nCopying NSIS installer files:\n";
print "=============================\n\n";

chdir $top_dir;
copy('win32\dist\installer\SetEnVar.nsi',"$install_base/") || die ("Could not copy file: $?");
copy('win32\dist\installer\net-snmp.nsi',"$install_base/net-snmp.nsi.in") || die ("Could not copy file: $?");
copy('win32\dist\installer\Add2Path.nsi',"$install_base/") || die ("Could not copy file: $?");
copy('win32\dist\installer\net-snmp-header1.bmp',"$install_base/") || die ("Could not copy file: $?");

open (TEMP, ">$install_base/registeragent.bat") || die ("Could not create file: $?");
close TEMP;
open (TEMP, ">$install_base/unregisteragent.bat") || die ("Could not create file: $?");
close TEMP;
open (TEMP, ">$install_base/registertrapd.bat") || die ("Could not create file: $?");
close TEMP;
open (TEMP, ">$install_base/unregistertrapd.bat") || die ("Could not create file: $?");
close TEMP;
open (TEMP, ">$install_base/etc/snmp/snmp.conf") || die ("Could not create file: $?");
close TEMP;

#
# Build net-snmp.nsi file
#
  {
    my $file_out = "$install_base/net-snmp.nsi";
    my $file_in = "$install_base/net-snmp.nsi.in";
  
    open (FILE_OUT, ">$file_out") || die "Can't Open $file_out\n";
    open (FILE_IN, "<$file_in") || die "Can't Open $file_in\n";
    
    print "creating $file_out\n";
	  
    while (<FILE_IN>)
    {
      chomp;
      s/!define PRODUCT_MAJ_VERSION.*/!define PRODUCT_MAJ_VERSION \"$version_maj\"/;
      s/!define PRODUCT_MIN_VERSION.*/!define PRODUCT_MIN_VERSION \"$version_min\"/;
      s/!define PRODUCT_REVISION.*/!define PRODUCT_REVISION \"$version_rev\"/;
      s/!define PRODUCT_EXE_VERSION.*/!define PRODUCT_EXE_VERSION \"$installer_exe_version\"/;
	  if ($ENV{LIB} =~ /\\x64/) {
            s/!define INSTALLER_PLATFORM.*/!define INSTALLER_PLATFORM \"x64\"/;
            s/!define PRODUCT_EXE_SUFFIX.*/!define PRODUCT_EXE_SUFFIX \".x64.exe\"/;
            s/!define WIN32_PLATFORM.*/!define PRODUCT_EXE_SUFFIX \"x64\"/;
	  }
	  else {
            s/!define INSTALLER_PLATFORM.*/!define INSTALLER_PLATFORM \"x86\"/;
            s/!define PRODUCT_EXE_SUFFIX.*/!define PRODUCT_EXE_SUFFIX \".x86.exe"/;
            s/!define PRODUCT_EXE_SUFFIX.*/!define PRODUCT_EXE_SUFFIX \".x86.exe"/;
            s/!define WIN32_PLATFORM.*/!define PRODUCT_EXE_SUFFIX \"x86\"/;
	  }
  
      print FILE_OUT $_ . "\n";
    }
    close FILE_IN;
    close FILE_OUT;
  }

print "\n=======\n";
print "Done!!!\n";
print "=======\n\n";

exit;






















#***************************************************************
sub build {

  $cTmp = ($openssl eq "enabled" ? "--with-ssl" : "" );
  $configOpts = "$cTmp";
  $cTmp = ($sdk eq "enabled" ? "--with-sdk" : "" );
  $configOpts = "$configOpts $cTmp";
  $cTmp = ($b_ipv6 eq "enabled" ? "--with-ipv6" : "" );
  $configOpts = "$configOpts $cTmp";
  $cTmp = ($b_winextdll eq "enabled" ? "--with-winextdll" : "" );
  $configOpts = "$configOpts $cTmp";
  $cTmp = ($debug eq "enabled" ? "--config=debug" : "--config=release" );
  $configOpts = "$configOpts $cTmp";
  
  # Set environment variables
  
  # Set to not search for non-existent ".dep" files
  $ENV{NO_EXTERNAL_DEPS}="1";
  
  # Set PATH environment variable so Perl make tests can locate the DLL
  $ENV{PATH} = "$current_pwd\\bin\\" . ($debug eq "enabled" ? "debug" : "release" ) . ";$ENV{PATH}";
  
  # Set MIBDIRS environment variable so Perl make tests can locate the mibs
  my $temp_mibdir = "$current_pwd/../mibs";
  $temp_mibdir =~ s/\\/\//g;
  $ENV{MIBDIRS}=$temp_mibdir;
  
  # Set SNMPCONFPATH environment variable so Perl conf.t test can locate
  # the configuration files.
  # See the note about environment variables in the Win32 section of 
  # perl/SNMP/README for details on why this is needed. 
  $ENV{SNMPCONFPATH}="t";$ENV{SNMPCONFPATH};
  
  print "\nBuilding...\n";
  
  print "\nCreating *.out log files.\n\n";

  #print "Deleting old log files...\n";
  #system("del *.out > NUL: 2>&1");

  # Delete net-snmp-config.h from main include folder just in case it was created by a Cygwin or MinGW build
  system("del ..\\include\\net-snmp\\net-snmp-config.h > NUL: 2>&1");
  
  print "Running Configure...\n";
  system("perl Configure $configOpts --linktype=$linktype --prefix=\"$install_base\" > configure.out 2>&1") == 0 || die "Build error (see configure.out)";

  print "Cleaning...\n";
  system("nmake /nologo clean > clean.out 2>&1") == 0 || die "Build error (see clean.out)";

  print "Building main package...\n";
  system("nmake /nologo > make.out 2>&1") == 0 || die "Build error (see make.out)";

  if ($perl eq "enabled") {
    if ($linktype eq "static") {
      print "Running Configure for DLL...\n";
      system("perl Configure $configOpts --linktype=dynamic --prefix=\"$install_base\" > perlconfigure.out 2>&1") == 0 || die "Build error (see perlconfigure.out)";
      
      print "Cleaning libraries...\n";
      system("nmake /nologo libs_clean >> clean.out 2>&1") == 0 || die "Build error (see clean.out)";
      
      print "Building DLL libraries...\n";
      system("nmake /nologo libs > dll.out 2>&1") == 0 || die "Build error (see dll.out)";
    }

    print "Cleaning Perl....\n";
    system("nmake /nologo perl_clean >> clean.out 2>&1"); # If already cleaned, Makefile is gone so don't worry about errors!

    print "Building Perl modules...\n";
    system("nmake /nologo perl > perlmake.out 2>&1") == 0 || die "Build error (see perlmake.out)";

#    print "Testing Perl modules...\n";
#    system("nmake /nologo perl_test > perltest.out 2>&1"); # Don't die if all the tests don't pass..
    
    if ($perl_install eq "enabled") {
      print "Installing Perl modules...\n";
      system("nmake /nologo perl_install > perlinstall.out 2>&1") == 0 || die "Build error (see perlinstall.out)";
    }
      
    print "\nSee perltest.out for Perl test results\n";
  }

  print "\n";
  if ($install eq "enabled") {
    print "Installing main package...\n";
    system("nmake /nologo install > install.out 2>&1") == 0 || die "Build error (see install.out)";
  }
  else {
    print "Type nmake install to install the package to $install_base\n";
  }

  if ($install_devel eq "enabled") {
    print "Installing development files...\n";
    system("nmake /nologo install_devel > install_devel.out 2>&1") == 0 || die "Build error (see install_devel.out)";
  }
  else {
    print "Type nmake install_devel to install the development files to $install_base\n";
  }
  
  if ($perl_install eq "disabled" && $perl eq "enabled") {
    print "Type nmake perl_install to install the Perl modules\n";
  }

  print "\nDone!\n";  
} # sub build




sub create_perl_package {

  print "\n\nCreating Perl package:\n";
  print "========================\n\n";
  
  chdir $perl_dir || die ("Could not enter Perl directory: $perl_dir");
  
  system("nmake ppd > perlpackage.out 2>&1") == 0 || die "Build error (see perlpackage.out)";
  #rename("Bundle-NetSNMP.ppd","NetSNMP.ppd") || die "Could not rename Bundle-NetSNMP.ppd to NetSNMP.ppd";
  
  {
    my $file_out = "NetSNMP.ppd";
    my $file_in = "Bundle-NetSNMP.ppd";
  
    open (FILE_OUT, ">$file_out") || die "Can't Open $file_out\n";
    open (FILE_IN, "<$file_in") || die "Can't Open $file_in\n";
    
    print "creating $file_out\n";
  
    while (<FILE_IN>)
    {
      chomp;
      s/^<SOFTPKG NAME.*/<SOFTPKG NAME="NetSNMP" VERSION="$version_for_perl">/;
      s/.*?<TITLE>.*/    <TITLE>Net-SNMP<\/TITLE>/;
      s/.*?<ABSTRACT>.*/    <ABSTRACT>Object Oriented Interface to Net-SNMP<\/ABSTRACT>/;
      s/.*?<CODEBASE.*/        <CODEBASE HREF="x86\/NetSNMP.tar.gz" \/>/;
  
      print FILE_OUT $_ . "\n";
    }
    close FILE_IN;
    close FILE_OUT;
  }
  
  print "Compressing Perl modules\n";
  unlink "NetSNMP.tar";
  unlink "NetSNMP.tar.gz";
  unlink "perl-tar.out";
  unlink "perl-gzip.out";
  print "  Creating Perl tar file\n";
  if (system("$tar_command cvf NetSNMP.tar blib > perl-tar.out 2>&1")) { die ("Could not create tar file.  See perl-tar.out"); }
  print "  Compressing Perl tar file\n";
  if (system("$gzip_command --best NetSNMP.tar > perl-gzip.out 2>&1")) { die ("Could not compress tar file with gzip. See perl-gzip.out"); }
   
  # Remove chdir..
  chdir $perl_dir || die ("Could not enter Perl directory: $perl_dir");
  mkdir ("$install_base/perl");
  mkdir ("$install_base/perl/x86");
  &check_dir_exists("$install_base/perl");
  &check_dir_exists("$install_base/perl/x86");
  copy("NetSNMP.ppd","$install_base/perl/") || die ("Could not copy file: $?");
  copy("NetSNMP.tar.gz","$install_base/perl/x86/") || die ("Could not copy file: $?");
}  # sub create_perl_package

sub check_dir_exists {
  my $dir = shift;
  if (! -d $dir) {
    die "Directory $dir is missing\n";
  }
}

