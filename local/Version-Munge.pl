#!/usr/bin/perl

use Getopt::Std;

sub usage {
    print "
$0 [-v VERSION] -R -C -M -D -h

  -M           Modify the files with a new version (-v required)
  -v VERSION   Use VERSION as the version string
  -T TAG       Use TAG as CVS tag (must being with Ext-)
  -C           Commit changes to the files
  -R           Reverse files (rm and cvs update)
  -D           Compare files (cvs diff)
  -f FILE      Just do a particular file
  -t TYPE      Just do a particular type of file

  -V           verbose
";
    exit 1;
}

getopts("v:T:RCMDhnf:t:V",\%opts) || usage();
if ($opts{'h'}) { usage(); }

if (!$opts{'v'} && $opts{'M'} && !$opts{'T'}) {
  warn "no version (-v or -T) specified";
  usage;
}
if (!$opts{'R'} && !$opts{'M'} && !$opts{'C'} && !$opts{'D'}) {
  warn "nothing to do (need -R -C -D or -M)\n";
  usage;
}

my @exprs = (
	     # c files with a equal sign and a specific variable
	     { type => 'c',
	       expr => 'VersionInfo(\s*=\s*[^"]*)"(.*)"',
	       repl => 'VersionInfo$1"$VERSION"', 
	       files => [qw(snmplib/snmp_version.c)]},

	     # documentation files
	     { type => 'docs',
	       expr => 'Version: [\.0-9a-zA-Z]+' =>
	       repl => 'Version: $VERSION', 
	       files => [qw(README FAQ dist/net-snmp.spec)]},

	     # sed files
	     { type => 'sed',
	       expr => '^s\/VERSIONINFO\/[^\/]*' =>
	       repl => 's\/VERSIONINFO\/$VERSION',
	       files => [qw(sedscript.in)]},

	     # Makefiles
	     { type => 'Makefile',
	       expr => 'VERSION = \'(.*)\'',
	       repl => 'VERSION = \'$VERSION\'',
	       files => [qw(dist/Makefile)]},

	     # Doxygen config
	     { type => 'doxygen',
	       expr => 'PROJECT_NUMBER(\s+)=(\s+)\'(.*)\'',
	       repl => 'PROJECT_NUMBER$1=$2\'$VERSION\'',
	       files => [qw(doxygen.conf)]},

	     # perl files
	     { type => 'perl',
	       expr => 'VERSION = \'(.*)\'',
	       repl => 'VERSION = \'$VERSION\'',
	       files => [qw(perl/SNMP/SNMP.pm
			    perl/agent/agent.pm
			    perl/agent/default_store/default_store.pm
			    perl/default_store/default_store.pm
			    perl/OID/OID.pm
			    perl/ASN/ASN.pm
			    perl/AnyData_SNMP/Storage.pm
			    perl/AnyData_SNMP/Format.pm
			    perl/TrapReceiver/TrapReceiver.pm
			   )]}
	    );

if ($opts{'T'} && !$opts{'v'}) {
    $opts{'v'} = $opts{'T'};
    die "usage error: version tag must begin with Ext-" if ($opts{'T'} !~ /^Ext-/);
    $opts{'v'} =~ s/^Ext-//;
    $opts{'v'} =~ s/-/./g;
}
$VERSION = $opts{'v'};

for ($i = 0; $i <= $#exprs; $i++) {
    next if ($opts{'t'} && $exprs[$i]{'type'} ne $opts{'t'});
    foreach my $f (@{$exprs[$i]->{'files'}}) {
	next if ($opts{'f'} && $f ne $opts{'f'});
	if ($opts{'R'}) {
	    print "removing changes and updating $f\n" if ($opts{'V'});
	    unlink($f);
	    system("cvs update $f");
	}
	if ($opts{'M'}) {
	    rename ($f,"$f.bak");
	    open(I,"$f.bak");
	    open(O,">$f");
	    while (<I>) {
		eval "s/$exprs[$i]->{'expr'}/$exprs[$i]->{'repl'}/";
		print O;
	    }
	    close(I);
	    close(O);
	    unlink("$f.bak");
	    print "modified $f using s/$exprs[$i]->{'expr'}/$exprs[$i]->{'repl'}/\n" if ($opts{'V'});
	}
	if ($opts{'D'}) {
	    print "diffing $f\n" if ($opts{'V'});
	    system("cvs diff $f");
	}
	if ($opts{'C'}) {
	    print "committing $f\n" if ($opts{'V'});
	    system("cvs commit -m \"- ($f): version tag ( $VERSION )\" $f");
	}
    }
}
