#!/usr/bin/perl

use SNMP;

$SNMP::save_descriptions = 1;

$ENV{'MIBDIRS'} = '.';
$ENV{'SNMPCONFPATH'} = 'bogus';

if (-f "rfclist") {
    open(I,"rfclist");
    while (<I>) {
	$mibs{$2} = $1 if (/^(\d+)\s+([-\w]+)\s*$/);
    }
    close(I);
}

print "<head><title>Net-SNMP Distributed MIBs</title></head>\n";
print "<body bgcolor=\"#ffffff\">\n";
print "<h1>Net-SNMP Distributed MIBs</h1>\n";
print "<p>The following are the MIB files distributed with Net-SNMP.  Note that because they are distributed with Net-SNMP does not mean the agent implements them all.  Another good place for finding other MIB definitions can be found <a href=\"http://www.mibdepot.com/\">at the MIB depot</a>.</p>\n";
print "<table border=2 bgcolor=\"#dddddd\">\n";
print "<tr><th>MIB</th><th>RFC</th><th>Description</th>\n";

foreach my $mibf (@ARGV) {
    my $node;
    my $mib = $mibf;
    $mib =~ s/.txt//;

    open(I, $mibf);
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

    $desc =~ s/\t/        /g;
    my ($s) = ($desc =~ /\n(\s+)/);
    $desc =~ s/^$s//gm;

    print "<tr><td><a href=\"$node.html\">$mib</a>\n";
    print "<br><a href=\"$mib.txt\">[mib file]</a></td>\n";
    print "<td><a href=\"http://www.ietf.org/rfc/rfc$mibs{$mib}.txt\">rfc$mibs{$mib}</a></td>\n" if ($mibs{$mib});
    print "<td>&nbsp</td>\n" if (!$mibs{$mib});
    print "<td><pre>$desc</pre></td></tr>\n";

    system("(cd html && env MIBDIRS=.. MIBS=$mib mib2c -c ../../local/mib2c.genhtml.conf $node)");
    open(O,">>html/$node.html");
    print O "<!--#include virtual=\"/sfbutton.html\" -->\n";
    close(O);
}

print "</table>";
print "<!--#include virtual=\"/sfbutton.html\" -->\n";

# 	@for i in $(MIBS) ; do \
# 		echo $$i ; \
# 		if grep MODULE-IDENTITY $$i > /dev/null ; then \
# 			m=`echo $$i | sed 's/.txt//'` ; \
# 			a=`egrep '[a-zA-Z]+ +MODULE-IDENTITY' $$i | awk '{print $$1}'` ; \
# 			(cd html && env MIBDIRS=.. MIBS=$$m mib2c -c $(top_srcdir)/../local/mib2c.genhtml.conf $$a ) ; \
# 			perl makehtml.pl $$m $$a >> html/index.html ; \
# 		fi \
# 	done
# 	echo "</table>" >> html/index.html
