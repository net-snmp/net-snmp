#!/usr/bin/perl
my $install_base = "c:/Program Files/Net-SNMP";
my $openssl = "disabled";
my $sdk = "disabled";
my $perl = "disabled";
my $logging = "enabled";
my $debug = "disabled";

# Prepend win32\ if running from main directory
my $current_pwd = `%COMSPEC% /c cd`;
chomp $current_pwd;
if (! ($current_pwd =~ /\\win32$/)) {
  chdir ("win32");
}

if (! (-d $ENV{MSVCDir})) {
  print "\nPlease run VCVARS32.BAT first to set up the Visual Studio build\n" .
        "environment.\n\n";
  system("pause");
  exit;
}

while (1) {
  print "\n\nNet-SNMP build options\n";
  print "======================\n\n";
  print "1. Install path:         " . $install_base . "\n";
  print "2. OpenSSL:              " . $openssl. "\n";
  print "3. Platform SDK:         " . $sdk . "\n";
  print "4. Perl modules:         " . $perl . "\n";
  print "5. Quiet build (logged): " . $logging . "\n";
  print "6. Debug mode:           " . $debug . "\n";
  print "\nF. Finished - start build\n";
  print "Q. Quit - abort build\n\n";
  print "Select option to set/toggle: ";

  chomp ($option = <>);
  if ($option eq "1") {
    my $default_install_base = "c:/Program Files/Net-SNMP";
    print "Please enter the new install path [$default_install_base]: ";
    chomp ($install_base = <>);
    if ($install_base eq "") {
      $install_base = $default_install_base;
    }
    $install_base =~ s/\\/\//g;
  }
  elsif ($option eq "2") {
    if ($openssl eq "enabled") {
      $openssl = "disabled";
    }
    else {
      $openssl = "enabled";
    }
  }
  elsif ($option eq "3") {
    if ($sdk eq "enabled") {
      $sdk = "disabled";
    }
    else {
      $sdk = "enabled";
    }
  }
  elsif ($option eq "4") {
    if ($perl eq "enabled") {
      $perl = "disabled";
    }
    else {
      $perl = "enabled";
    }
  }
  elsif ($option eq "5") {
    if ($logging eq "enabled") {
      $logging = "disabled";
    }
    else {
      $logging = "enabled";
    }
  }
  elsif ($option eq "6") {
    if ($debug eq "enabled") {
      $debug = "disabled";
    }
    else {
      $debug = "enabled";
    }
  }
  elsif (lc($option) eq "f") {
    last;
  }
  elsif (lc($option) eq "q") {
    exit;
  }
}

$openssl = ($openssl eq "enabled" ? "--with-ssl" : "" );
$sdk = ($sdk eq "enabled" ? "--with-sdk" : "" );
$debug = ($debug eq "enabled" ? "--config=debug" : "--config=release" );

print "\nBuilding...\n";

if ($logging eq "enabled") {
  print "\nCreating *.out log files.\n\n";
}

if ($logging eq "enabled") {
  print "Deleting old log files...\n";
  system("del *.out > NUL: 2>&1");

  # Delete net-snmp-config.h from main include folder just in case it was created by a Cygwin or MinGW build
  system("del ..\\include\\net-snmp\\net-snmp-config.h > NUL: 2>&1");
  
  print "Running Configure...\n";
  system("perl Configure $openssl $sdk $debug --linktype=static --prefix=\"$install_base\" > configure.out 2>&1") == 0 || die "Build error (see configure.out)";

  print "Cleaning...\n";
  system("nmake /nologo clean > clean.out 2>&1") == 0 || die "Build error (see clean.out)";

  print "Building main package...\n";
  system("nmake /nologo > make.out 2>&1") == 0 || die "Build error (see make.out)";

  print "Installing main package...\n";
  system("nmake /nologo install > install.out 2>&1") == 0 || die "Build error (see install.out)";

  if ($perl eq "enabled") {
    print "Running Configure for DLL...\n";
    system("perl Configure $openssl $sdk $debug --linktype=dynamic --prefix=\"$install_base\" > perlconfigure.out 2>&1") == 0 || die "Build error (see perlconfigure.out)";

    print "Cleaning libraries...\n";
    system("nmake /nologo libs_clean >> clean.out 2>&1") == 0 || die "Build error (see clean.out)";

    print "Building DLL libraries...\n";
    system("nmake /nologo libs > dll.out 2>&1") == 0 || die "Build error (see dll.out)";

    print "Installing DLL libraries...\n";
    system("nmake /nologo install > installdll.out 2>&1") == 0 || die "Build error (see installdll.out)";

    
    print "Cleaning Perl....\n";
    system("nmake /nologo perl_clean >> clean.out 2>&1"); # If already cleaned, Makefile is gone so don't worry about errors!

    print "Building Perl modules...\n";
    system("nmake /nologo perl > perlmake.out 2>&1") == 0 || die "Build error (see perlmake.out)";

    print "Testing Perl modules...\n";
    system("nmake /nologo perl_test > perltest.out 2>&1"); # Don't die if all the tests don't pass..

    print "Installing Perl modules...\n";
    system("nmake /nologo perl_install > perlinstall.out 2>&1") == 0 || die "Build error (see perlinstall.out)";
    
    print "\nSee perltest.out for Perl test results\n\n";
  }
}
else {
  system("del *.out");

  # Delete net-snmp-config.h from main include folder just in case it was created by a Cygwin or MinGW build
  system("del ..\\include\\net-snmp\\net-snmp-config.h > NUL: 2>&1");

  system("perl Configure $openssl $sdk $debug --linktype=static --prefix=\"$install_base\"") == 0 || die "Build error (see above)";
  system("nmake /nologo clean") == 0 || die "Build error (see above)";
  system("nmake /nologo") == 0 || die "Build error (see above)";
  system("nmake /nologo install") == 0 || die "Build error (see above)";
  
  if ($perl eq "enabled") {
    system("perl Configure $openssl $sdk $debug --linktype=dynamic --prefix=\"$install_base\"") == 0 || die "Build error (see above)";
    system("nmake /nologo libs_clean") == 0 || die "Build error (see above)";
    system("nmake /nologo libs") == 0 || die "Build error (see above)";
    system("nmake /nologo install") == 0 || die "Build error (see above)";
    
    system("nmake /nologo perl_clean"); # If already cleaned, Makefile is gone so don't worry about errors!
    system("nmake /nologo perl") == 0 || die "Build error (see above)";
    system("nmake /nologo perl_test"); # Don't die if all the tests don't pass..
    system("nmake /nologo perl_install") == 0 || die "Build error (see above)";
  }
}

print "\nDone!\n";
