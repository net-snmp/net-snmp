#!/usr/bin/perl

my $infile = shift @ARGV;

map { s/\.[0-9]$//; $pages{$_} = 1; } @ARGV;

open(I,$infile);
$first = 1;
print "<HTML>
<HEAD>
<title>Net-SNMP manual pages</title>
<style type=\"text/css\">
<!--
h2{background:#ccccee}
table{background:#bbeebb}
-->
</style>
</head>
<BODY bgcolor=\"#ffffff\" background=\"../ucd-snmp-bg3.gif\">
<h2>Other Net-SNMP Documantion</h2>
<ul>
<table width=100%>
<tr><td width=30%><a href=\"http://www.Net-SNMP.org/tutorial-5/\">The Net-SNMP Tutorial</td><td>A complete tutorial describing how to use the commands, a bit how SNMP works, and how to develop applications and agent plugins.</tr>
<tr><td width=30%><a href=\"http://www.Net-SNMP.org/#Documentation\">Net-SNMP Home Page Documentation</a.</td><td>A high-level summary of Net-SNMP related documentation</td></tr>
<tr><td width=30%><a href=\"http://www.Net-SNMP.org/tutorial-5/agent/\">API documentation</a></td><td>Documentation generated from Doxygen formatted source code comments</td></tr>
</table>
</ul>
";
while (<I>) {
    if (/^#\s*(.*)/) {
	print "</table></ul>\n" if (!$first);
	print "<h2>$1</h2>\n<ul><table width=\"100%\">\n";
	$first = 0;
    } else {
	my $name = $_;
	my $title;
	chomp($name);
	if (!exists($pages{$name})) {
	    print STDERR "$name is in $infile, but not in the rest of the args.\n";
	}
	open(H,"$name.html");
	while (<H>) {
	    if (/<TITLE>(.*)<\/TITLE>/) {
		$title = $1;
	    }
	    if (/<H2>NAME<\/H2>/) {
		$_ = <H>;
		while (/^\s*$/) {
		    $_ = <H>;
		}
		$title = $_;
		chomp($title);
		$title =~ s/\s*$name\s*-\s*//;
	    }
	}
	close(H);
	print " <tr><td width=\"30%\"><a href=\"$name.html\">$name</a></td><td>$title</td></tr>\n";
	delete $pages{$name};
    }
}
print "</table></ul>
<!--#include virtual=\"/sfbutton.html\" -->
</BODY></HTML>\n";

@left = keys(%pages);
if ($#left > -1) {
    print STDERR "missing a filing location for: ",
      join(", ", @left), "\n";
}
