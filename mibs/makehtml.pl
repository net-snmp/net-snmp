#!/usr/bin/perl

use SNMP;

use Getopt::Std;

%opts = ( M => ".",
	  D => "html");

getopts("M:D:WH:", \%opts) || die "usage: makehtml.pl [-M MIBDIR] [-D OUTDIR]";

$SNMP::save_descriptions = 1;

$ENV{'MIBDIRS'} = $opts{'M'};
$ENV{'SNMPCONFPATH'} = 'bogus';

if (-f "rfclist") {
    open(I,"rfclist");
    while (<I>) {
	if (/^(\d+)\s+([-:\w]+)\s*$/) {
	    my $mib = $2;
	    my $rfc = $1;
	    my @mibs = split(/:/,$mib);
	    foreach my $i (@mibs) {
		$mibs{$i} = $rfc; 
	    }
	}
    }
    close(I);
}

if (-f "nodemap") {
    open(I,"nodemap");
    while (<I>) {
	if (/^([-\w]+)\s+(\w+)\s*$/) {
	    $nodemap{$1} = $2;
	}
    }
    close(I);
}

if ($opts{'H'}) {
    open(I,"$opts{'H'}");
    while (<I>) {
	print;
    }
    close(I);
} else {
    print "<head><title>Net-SNMP Distributed MIBs</title></head>\n";
    print "<body bgcolor=\"#ffffff\">\n";
    print "<h1>Net-SNMP Distributed MIBs</h1>\n";
    print "<p>The following are the MIB files distributed with Net-SNMP.  Note that because they are distributed with Net-SNMP does not mean the agent implements them all.  Another good place for finding other MIB definitions can be found <a href=\"http://www.mibdepot.com/\">at the MIB depot</a>.</p>\n";
}
print "<table border=2 bgcolor=\"#dddddd\">\n";
print "<tr><th>MIB</th><th>RFC</th><th>Description</th>\n";

my %didit;

foreach my $mibf (@ARGV) {
    my $node;
    my $mib = $mibf;
    $mib =~ s/.txt//;

    next if ($didit{$mib});
    $didit{$mib} = 1;

    open(I, "$opts{M}/$mibf");
    while (<I>) {
	if (/(\w+)\s+MODULE-IDENTITY/) {
	    $node = $1;
	}
    }
    close(I);

    if (!$node) {
	print STDERR "Couldn't find starting node for $mib $node $_\n";
	next;
    }

    SNMP::loadModules($mib);

    $desc = $SNMP::MIB{$node}{'description'};

    # get a different tree than the module identity though.
    if (exists($nodemap{$mib})) {
	$node = $nodemap{$mib};
    }

    $desc =~ s/\t/        /g;
    my ($s) = ($desc =~ /\n(\s+)/);
    $desc =~ s/^$s//gm;

    print "<tr><td><a href=\"$node.html\">$mib</a>\n";
    print "<br><a href=\"$mib.txt\">[mib file]</a></td>\n";
    print "<td><a href=\"http://www.ietf.org/rfc/rfc$mibs{$mib}.txt\">rfc$mibs{$mib}</a></td>\n" if ($mibs{$mib});
    print "<td>&nbsp</td>\n" if (!$mibs{$mib});
    print "<td><pre>$desc</pre></td></tr>\n";

    system("MIBS=$mib mib2c -c mib2c.genhtml.conf $node");
    system("mv $node.html $opts{D}");
    if ($opts{'W'}) {
	open(O,">>$opts{D}/$node.html");
	print O "<!--#include virtual=\"/sfbutton.html\" -->\n";
	close(O);
    }
}

print "</table>";
print "<!--#include virtual=\"/sfbutton.html\" -->\n" if ($opts{'W'});
