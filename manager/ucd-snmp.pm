#!/usr/local/bin/perl

package ucdsnmp::manager;

use strict;
use Apache::Constants qw(:common);
use CGI qw(:standard);
use SNMP;
use DBI;

# globals
$ucdsnmp::manager::hostname = 'localhost';          # Host that serves the mSQL Database
$ucdsnmp::manager::dbname = 'snmp';                 # mySQL Database name
$ucdsnmp::manager::user = 'root';
# $ucdsnmp::manager::pass = "password";
$ucdsnmp::manager::redimage = "/graphics/red.gif";
$ucdsnmp::manager::greenimage = "/graphics/green.gif";
#$ucdsnmp::manager::verbose = 1;
$ucdsnmp::manager::tableparms = "border=3 ipad=3 bgcolor=#d0d0d0";

# init the snmp library
#$SNMP::save_descriptions=1;
#SNMP::init_mib();

%ucdsnmp::manager::myorder = qw(id 0 oidindex 1 host 2 updated 3);

sub handler {
    my $r = shift;
    Apache->request($r);

    # get info from handler
    my $hostname = $r->dir_config('hostname') || $ucdsnmp::manager::hostname;
    my $dbname = $r->dir_config('dbname') || $ucdsnmp::manager::dbname;
    my $user = $r->dir_config('user') || $ucdsnmp::manager::user;
    my $pass = $r->dir_config('pass') || $ucdsnmp::manager::pass;
    my $verbose = $r->dir_config('verbose') || $ucdsnmp::manager::verbose;

#===========================================================================
#  Global defines
#===========================================================================

my ($dbh, $query, $remuser);

$remuser = $ENV{'REMOTE_USER'};
$remuser = "guest" if (!defined($remuser) || $remuser eq "");

#===========================================================================
# Connect to the mSQL database with the appropriate driver
#===========================================================================
( $dbh = DBI->connect("DBI:mysql:database=$dbname;host=$hostname", $user, $pass))
    or die "\tConnect not ok: $DBI::errstr\n";

$query = new CGI;

#===========================================================================
# Start HTML.
#===========================================================================
print "<body bgcolor=\"#ffffff\">\n";

#===========================================================================
# Display mib related information
#===========================================================================
if (param('displayinfo')) {
    makemibtable(param('displayinfo'));
    return Exit($dbh, "");
}

#===========================================================================
# Display a generic sql table of any kind.
#===========================================================================
if (my $disptable = param('displaytable')) {
    if (param('editable') == 1) {
	print "<form submit=dont>\n";
	displaytable($disptable, -editable, 1);
	print "</form>\n";
    } else {
	displaytable($disptable);
    }
    return Exit($dbh,  "");
}

#===========================================================================
# Get host and group from CGI query.
#===========================================================================
my $host = param('host');
my $group = param('group');


#===========================================================================
# show the list of groups a user belongs to.
#===========================================================================
if (!defined($group)) {
    my @groups = getgroupsforuser($dbh, $remuser);
    if ($#groups > 0) {
	displaytable($dbh, 'usergroups', 
		     '-clauses', "where (user = '$remuser')",
		     '-select', 'distinct groupname',
		     '-printonly', ['groupname'],
		     '-datalink', sub { my $q = self_url();
					my $key = shift;
					my $h = shift;
					return if ($key ne "groupname");
					return addtoken($q,"group=$h");
				    },
		     '-beginhook', 
		     sub { 
			 my $q = self_url();
			 my($dbh, $junk, $data) = @_;
			 if (!defined($data)) {
			     print "<td></td>";
			     return;
			 }
			 my ($cur, $row);
			 $cur = getcursor($dbh, "select host from hostgroups where groupname = '$data->{groupname}'");
			 while (  $row = $cur->fetchrow_hashref ) {
			     if (checkhost($dbh, $data->{'groupname'}, 
					   $row->{'host'})) {
				 print "<td><a href=\"" . addtoken($q,"group=$data->{groupname}&summarizegroup=1") . "\"><img border=0 src=$ucdsnmp::manager::redimage></a></td>\n";
				 return;
			     }
			 }
			 print "<td><img src=$ucdsnmp::manager::greenimage></td>\n";
		     }
		     );
	$dbh->disconnect();
	return Exit($dbh,  $group);
    } else {
	if ($#groups == -1) {
	    print "You are not configured to use the ucd-snmp-manager, please contact your system administrator.";
	    return Exit($dbh,  $group);
	}
	$group = $groups[0];
    }
}

#===========================================================================
# reject un-authorized people accessing a certain group
#===========================================================================
if (!isuser($dbh, $remuser, $group)) {
    print "Unauthorized access to that group ($group)\n";
    return Exit($dbh, $group);
}    

#===========================================================================
# add a new host to a group
#===========================================================================
if (defined(my $newhost = param('newhost'))) {
    if (isadmin($dbh, $remuser, $group)) {
	if ($dbh->do("select * from hostgroups where host = '$newhost' and groupname = '$group'") eq "0E0") {
	    $dbh->do("insert into hostgroups(host,groupname) values('$newhost','$group')") ;
	} else {
	    print "<b>ERROR: host $newhost already in $group</b>\n";
	}
	CGI::delete('newhost');
    }
}

#===========================================================================
# display setup configuration for a group
#===========================================================================
if (defined(param('setupgroup')) && 
    isadmin($dbh, $remuser, $group)) {
    setupgroup($dbh, $group);
    return Exit($dbh, $group);
}

#===========================================================================
# save configuration information submitted about a group
#===========================================================================
if (defined(param('setupgroupsubmit')) && 
    isadmin($dbh, $remuser, $group)) {
    setupgroupsubmit($dbh, $user, $group);
    delete_all();
    param(-name => 'group', -value => $group);
    print "<a href=\"" . self_url() . "\">Entries submitted</a>";
    return Exit($dbh, $group);
}

#===========================================================================
# user preferences
#===========================================================================
if (defined(param('userprefs'))) {
    setupuserpreferences($dbh, $user, $group);
    return Exit($dbh, $group);
}

#===========================================================================
# save submitted user preferences
#===========================================================================
if (defined(param('setupuserprefssubmit')) && 
    isadmin($dbh, $remuser, $group)) {
    setupusersubmit($dbh, $group);
    delete_all();
    param(-name => 'group', -value => $group);
    print "<a href=\"" . self_url() . "\">Entries submitted</a>";
    return Exit($dbh, $group);
}

#===========================================================================
# summarize problems in a group
#===========================================================================
if (defined(param('summarizegroup'))) {
    print "<title>group summary: $group</title>\n";
    summarizeerrors($dbh, "where groupname = '$group'");
    return Exit($dbh, $group);
}

#===========================================================================
# summarize problems on a host
#===========================================================================
if (defined($host) && defined(param('summarizehost'))) {
    print "<title>host summary: $host</title>\n";
    summarizeerrors($dbh, "where groupname = '$group' and host = '$host'");
    return Exit($dbh, $group);
}

#===========================================================================
# display a list of hosts in a group
#===========================================================================
if (!defined($host)) {
    displaytable($dbh, 'hostgroups', 
		 '-notitle',0,
		 '-clauses', "where (groupname = '$group')",
		 '-select', 'distinct host',
		 '-datalink', sub { my $q = self_url();
				    my $key = shift;
				    my $h = shift;
				    return if ($key ne "host");
				    return addtoken($q,"host=$h");
				},
		 '-beginhook', 
		 sub { 
		     my $q = self_url();
		     my($dbh, $junk, $data) = @_;
		     if (!defined($data)) {
			 print "<td></td>";
			 return;
		     }
		     if (checkhost($dbh, $group, $data->{'host'})) {
			 print "<td><a href=\"" . addtoken($q,"group=$group&summarizehost=1&host=$data->{host}") . "\"><img border=0 src=$ucdsnmp::manager::redimage></a></td>\n";
		     } else {
			 print "<td><img src=$ucdsnmp::manager::greenimage></td>\n";
		     }
		 }
		 );
    if (isadmin($dbh, $remuser, $group)) {
	addhostentryform($group);
	my $q = self_url();
	$q =~ s/\?.*//;
	print "<a href=\"" . addtoken($q,"group=$group&setupgroup=1") . "\">setup group $group</a>\n";
    }
    return Exit($dbh, $group);
}

#===========================================================================
# display inforamation about a host
#===========================================================================
showhost($dbh, $host, $group, $remuser);
return Exit($dbh, $group);

#===========================================================================
# END of handler
#===========================================================================

}

# add a token to a url string.  Use either a ? or an & depending on
# existence of ?.
sub addtoken {
    my $url = shift;
    my $token = shift;
    return "$url&$token" if ($url =~ /\?/);
    return "$url?$token";
}

#
# summarizeerrors(CLAUSE):
#   summarize the list of errors in a given CLAUSE
#
sub summarizeerrors {
    my $dbh = shift;
    my $clause = shift;
    print "<table $ucdsnmp::manager::tableparms><tr><td><b>Host</b></td><td><b>Table</b></td><td><b>Description</b></td></tr>\n";
    my $cursor = 
	getcursor($dbh, "SELECT * FROM hosttables $clause");

    while (my $row = $cursor->fetchrow_hashref ) {
	my $exprs = getcursor($dbh, "SELECT * FROM errorexpressions where (tablename = '$row->{tablename}')");
	
	while (my  $expr = $exprs->fetchrow_hashref ) {
	    my $errors = getcursor($dbh, "select * from $row->{tablename} where $expr->{expression} and host = '$row->{host}'");
	    while (my  $error = $errors->fetchrow_hashref ) {
		print "<tr><td>$row->{host}</td><td>$row->{tablename}</td><td>$expr->{returnfield}: $error->{$expr->{returnfield}}</td></tr>";
	    }
	}
    }
    print "</table>";
}

#
# getcursor(CMD):
#    genericlly get a cursor for a given sql command, displaying and
#    printing errors where necessary.
#
sub getcursor {
    my $dbh = shift;
    my $cmd = shift;
    my $cursor;
    ( $cursor = $dbh->prepare( $cmd ))
	or print "\nnot ok: $DBI::errstr\n";
    ( $cursor->execute )
	or print( "\tnot ok: $DBI::errstr\n" );
    return $cursor;
}

#
# mykeysort($a, $b)
#    sorts $a and $b against the order in the mib or against the hard
#    coded special list.
#
sub mykeysort {
    my $mb = $SNMP::MIB{SNMP::translateObj($b)};
    my $ma = $SNMP::MIB{SNMP::translateObj($a)};
    return $ucdsnmp::manager::myorder{$a} <=> $ucdsnmp::manager::myorder{$b} if ((defined($ucdsnmp::manager::myorder{$a}) || !defined($ma->{'subID'})) && (defined($ucdsnmp::manager::myorder{$b}) || !defined($mb->{'subID'})));
    return 1 if (defined($ucdsnmp::manager::myorder{$b}) || !defined($mb->{'subID'}));
    return -1 if (defined($ucdsnmp::manager::myorder{$a}) || !defined($ma->{'subID'}));

    $ma->{'subID'} <=> $mb->{'subID'};
}

#
# checkhost(GROUP, HOST):
#    if anything in a host is an error, as defined by the
#    errorexpressions table, return 1, else 0
#
sub checkhost {
    my $dbh = shift;
    my $group = shift;
    my $host = shift;
    my ($tblh);

    return 2 if ($dbh->do("select * from hosterrors where host = '$host'") ne "0E0");

    # get a list of tables we want to display
    $tblh = getcursor($dbh, "SELECT * FROM hosttables where (host = '$host' and groupname = '$group')");

    # table data
    my($exprs, $tablelist);
    while ( $tablelist = $tblh->fetchrow_hashref ) {
	$exprs = getcursor($dbh, "SELECT * FROM errorexpressions where (tablename = '$tablelist->{tablename}')");
	while(my $expr = $exprs->fetchrow_hashref) {
	    if ($dbh->do("select * from $tablelist->{tablename} where $expr->{expression} and host = '$host'") ne "0E0") {
		return 1;
	    }
	}
    }
    return 0;
}

#
#  showhost(HOST):
#
#    display all the tables monitored for a given host (in a group).
#
sub showhost {
    my $dbh = shift;
    my $host = shift;
    my $group = shift;
    my $remuser = shift;
    # host header
    print "<title>ucd-snmp manager report for host: $host</title>\n";
    print "<h3>host: $host</h3>\n";

    # does the host have a serious error?

    my $errlist = getcursor($dbh, "SELECT * FROM hosterrors where (host = '$host')");
    if ( $dbh->do("SELECT * FROM hosterrors where (host = '$host')") ne "0E0") {
	displaytable($dbh, 'hosterrors', 
		     '-clauses', "where (host = '$host')",
		     '-dontdisplaycol', "select * from userprefs where user = '$remuser' and groupname = '$group' and tablename = ? and columnname = ? and displayit = 'N'",
		     '-beginhook', sub {
			 if ($#_ < 2) {
			     #doing header;
			     print "<td></td>";
			 } else {
			     print "<td><img src=\"$ucdsnmp::manager::redimage\"></td>\n";
			 }});
    }

    # get a list of tables we want to display
    my $tblh = getcursor($dbh, "SELECT * FROM hosttables where (host = '$host' and groupname = '$group')");

    # table data
    my($tablelist);
    while (  $tablelist = $tblh->fetchrow_hashref ) {

	displaytable($dbh, $tablelist->{'tablename'}, 
		     '-clauses', "where (host = '$host') order by oidindex",
		     '-dontdisplaycol', "select * from userprefs where user = '$remuser' and groupname = '$group' and tablename = ? and columnname = ? and displayit = 'N'",
		     '-sort', "mykeysort",
		     '-dolink', \&linktodisplayinfo,
		     '-beginhook', \&printredgreen);
    }
}

#
#  linktodisplayinfo(STRING):
#
#    returns a url to the appropriate displayinfo link if STRING is a
#    mib node.
#
sub linktodisplayinfo {
    return if (exists($ucdsnmp::manager::myorder{shift}));
    return self_url() . "&displayinfo=" . shift;
}

# printredgreen(TABLENAME, DATA):
#
#   display a red or a green dot in a table dependent on the table's
#   values and associated expression
#
#   DATA is NULL when in a header row (displaying header names).
#
sub printredgreen {
    my $dbh = shift;
    my $tablename = shift;
    my $data = shift;
    my ($exprs, $expr, $img);

    if (!defined($data)) {
	#doing header;
	print "<td></td>";
	return;
    }

    my $cmd = "SELECT * FROM errorexpressions where (tablename = '$tablename')";
    print " $cmd\n" if ($ucdsnmp::manager::verbose);
    ( $exprs = $dbh->prepare( $cmd ) )
	or die "\nnot ok: $DBI::errstr\n";
    ( $exprs->execute )
	or print( "\tnot ok: $DBI::errstr\n" );

    $img = $ucdsnmp::manager::greenimage;
    while($expr = $exprs->fetchrow_hashref) {
	if ($dbh->do("select oidindex from $tablename where host = '$data->{host}' and oidindex = '$data->{oidindex}' and $expr->{expression}") ne "0E0") {
	    $img = $ucdsnmp::manager::redimage;
	}
    }
    print "<td><img src=$img></td>";
}

# displaytable(TABLENAME, CONFIG...):
#
#   genericly displays any sql table in existence.
#
sub displaytable {
    my $dbh = shift;
    my $tablename = shift;
    my %config = @_;
    my $clauses = $config{'-clauses'};
    my $sort = $config{'-sort'};
    my $dolink = $config{'-dolink'};
    my $datalink = $config{'-datalink'};
    my $beginhook = $config{'-beginhook'};
    my $selectwhat = $config{'-select'};
    my $printonly = $config{'-printonly'};
    $selectwhat = "*" if (!defined($selectwhat));
    my ($thetable, $data, $ref);

    # get a list of data from the table we want to display
    $thetable = getcursor($dbh, "SELECT $selectwhat FROM $tablename $clauses");

    my $prefs = $dbh->prepare($config{'-dontdisplaycol'}) if ($config{'-dontdisplaycol'});

    # table header
    my $doheader = 1;
    my @keys;
    while( $data = $thetable->fetchrow_hashref ) {
	if ($doheader) {
	    if (defined($sort)) {
		@keys = (sort $sort keys(%$data));
	    } else {
		@keys = (sort keys(%$data));
	    }
	    if (!defined($config{'-notitle'})) {
		print "<br><b>";
		print "<a href=\"$ref\">" if (defined($dolink) && 
					      defined($ref = &$dolink($tablename)));
		print "$tablename";
		print "</a>" if (defined($ref));
		print "</b>\n";
	    }
	    print "<br>\n";
	    print "<table $ucdsnmp::manager::tableparms>\n<tr>";
	    if (defined($beginhook)) {
		&$beginhook($dbh, $tablename);
	    }
	    foreach my $l (@keys) {
		if (!defined($prefs) || 
		    $prefs->execute($tablename, $l) eq "0E0") {
		    print "<td>";
		    print "<a href=\"$ref\">" if (defined($dolink) && 
						  defined($ref = &$dolink($l)));
		    print "$l";
		    print "</a>" if (defined($ref));
		    print "</td>";
		}
	    }
	    "</tr>\n";
	    $doheader = 0;
	}

	print "<tr>";
	if (defined($beginhook)) {
	    &$beginhook($dbh, $tablename, $data);
	}
	foreach my $key (@keys) {
	    if (!defined($prefs) || 
		$prefs->execute($tablename, $key) eq "0E0") {
		print "<td>";
		print "<a href=\"$ref\">" if (defined($datalink) && 
					      defined($ref = &$datalink($key, $data->{$key})));
		if (defined($config{'-editable'})) {
		    print "<input type=text name=\"$key.x.$data->{$key}\" value=\"$data->{$key}\">";
		} else {
		    print $data->{$key};
		}
		print "</a>" if (defined($ref));
		print "</td>";
	    }
	}
	print "</tr>\n";
    }
    print "</table>\n";
}
    

#
# display information about a given mib node as a table.
#
sub makemibtable {
    my $dispinfo = shift;
    # display information about a data type in a table
    my $mib = $SNMP::MIB{SNMP::translateObj($dispinfo)};
    print "<table $ucdsnmp::manager::tableparms><tr><td>\n";
    foreach my $i (qw(label type access status units hint moduleID description enums)) {
#    foreach my $i (keys(%$mib)) {
	next if (!defined($$mib{$i}) || $$mib{$i} eq "");
	next if (ref($$mib{$i}) eq "HASH" && $#{keys(%{$$mib{$i}})} == -1);
	print "<tr><td>$i</td><td>";
	if (ref($$mib{$i}) eq "HASH") {
	    print "<table $ucdsnmp::manager::tableparms><tr><td>\n";
	    foreach my $j (sort { $$mib{$i}{$a} <=> $$mib{$i}{$b} } keys(%{$$mib{$i}})) {
 		print "<tr><td>$$mib{$i}{$j}</td><td>$j</td></tr>";
	    }
	    print "</table>\n";
	} else {
	    print "$$mib{$i}";
	}
	print "</td></tr>\n";
    }
    print "</table>\n";
}

# given a user, get all the groups he belongs to.
sub getgroupsforuser {
    my (@ret, $cursor, $row);
    my ($dbh, $remuser) = @_;
    ( $cursor = $dbh->prepare( "SELECT * FROM usergroups where (user = '$remuser')"))
	or die "\nnot ok: $DBI::errstr\n";
    ( $cursor->execute )
	or print( "\tnot ok: $DBI::errstr\n" );

    while (  $row = $cursor->fetchrow_hashref ) {
	push(@ret, $row->{'groupname'});
    }
    @ret;
}

# given a host, get all the groups it belongs to.
sub gethostsforgroup {
    my (@ret, $cursor, $row);
    my ($dbh, $group) = @_;
    ( $cursor = $dbh->prepare( "SELECT * FROM hostgroups where (groupname = '$group')"))
	or die "\nnot ok: $DBI::errstr\n";
    ( $cursor->execute )
	or print( "\tnot ok: $DBI::errstr\n" );

    while (  $row = $cursor->fetchrow_hashref ) {
	push(@ret, $row->{'host'});
    }
    @ret;
}

# display the host add entry box
sub addhostentryform {
    my $group = shift;
    print "<form method=\"get\" action=\"" . self_url() . "\">\n";
    print "Add new host to group: <input type=\"text\" name=\"newhost\">";
    print "<input type=\"hidden\" name=\"group\" value=\"$group\">";
    print "</form>";
}

#is remuser a admin?
sub isadmin {
    my ($dbh, $user, $group) = @_;
    return 0 if (!defined($user) || !defined($group));
    return 1 if ($dbh->do("select * from usergroups where user = '$user' and groupname = '$group' and isadmin = 'Y'") ne "0E0");
    return 0;
}

#is user a member of this group?
sub isuser {
    my ($dbh, $user, $group) = @_;
    return 0 if (!defined($user) || !defined($group));
    return 1 if ($dbh->do("select * from usergroups where user = '$user' and groupname = '$group'") ne "0E0");
    return 0;
}

# displayconfigarray(HOSTS, NAMES, CONFIG):
#
#   displays an array of generic check buttons to turn on/off certain
#   variables.
sub displayconfigarray {
    my $dbh = shift;
    my $hosts = shift;
    my $names = shift;
    my %config = @_;

    my $cmd;
    if ($config{'-check'}) {
	( $cmd = $dbh->prepare( $config{'-check'} ) )
	    or die "\nnot ok: $DBI::errstr\n";
    }

    print "<table $ucdsnmp::manager::tableparms>\n";
    print "<tr><td></td>";
    my ($i, $j);
    foreach $j (@$names) {
	my $nj = $j;
	$nj = $j->[0] if ($config{'-arrayrefs'} || $config{'-arrayref2'});
	print "<td>$nj</td>";
    }
    foreach my $i (@$hosts) {
	my $ni = $i;
	$ni = $i->[0] if ($config{'-arrayrefs'} || $config{'-arrayref1'});
	print "<tr><td>$ni</td>";
	foreach $j (@$names) {
	    my $nj = $j;
	    $nj = $j->[0] if ($config{'-arrayrefs'} || $config{'-arrayref2'});
	    my $checked = "checked" if (defined($cmd) && $cmd->execute($ni,$nj) ne "0E0");
	    print "<td><input type=checkbox $checked value=y name=" . $config{prefix} . $ni . $nj . "></td>\n";
	}
	print "</tr>\n";
    }	
    print "</tr>";
    print "</table>";
}


#
# display the setup information page for a given group.
#
sub setupgroup {
    my $dbh = shift;
    my $group = shift;
    
    my ($hosts, $names) = gethostandgroups($dbh, $group);

    print "<form method=\"post\" action=\"" . self_url() . "\">\n";
    print "<input type=hidden text=\"setupgroupsubmit\" value=\"y\">";
    displayconfigarray($dbh, $hosts, $names, 
		       -arrayrefs, 1,
		       -check, "select * from hosttables where (host = ? and tablename = ? and groupname = '$group')");
    print "<input type=hidden name=group value=\"$group\">\n";
    print "<input type=submit value=submit name=\"setupgroupsubmit\">\n";
    print "</form>";
}

# a wrapper around fetching arrays of everything in a table.
sub getarrays {
    my $dbh = shift;
    my $table = shift;
    my %config = @_;
    my $selectwhat = $config{'-select'} || "*";
    my $handle;
    
    $handle = getcursor($dbh, "SELECT $selectwhat FROM $table $config{-clauses}");
    return $handle->fetchall_arrayref;
}

#
# get a list of all tablenames and hostnames for a given group.
#
sub gethostandgroups {
    my $dbh = shift;
    my $group = shift;
    my ($tbnms);

    my $names = getarrays('hosttables', 
			  "-select", 'distinct tablename',
			  "-clauses", "where groupname = '$group'");

    my $hosts = getarrays('hostgroups', 
			  "-select", 'distinct host',
			  "-clauses", "where groupname = '$group'");
    
    return ($hosts, $names);
}

sub setupgroupsubmit {
    my $dbh = shift;
    my $group = shift;
    
    my ($hosts, $names) = gethostandgroups($group);
    foreach my $i (@$hosts) {
	$dbh->do("delete from hosttables where host = '${$i}[0]' and groupname = '$group'");
    }
    my $rep = $dbh->prepare("insert into hosttables(host,tablename,groupname) values(?,?,'$group')");

    foreach my $i (@$hosts) {
	foreach my $j (@$names) {
	    if (param("${$i}[0]" . "${$j}[0]")) {
		$rep->execute("${$i}[0]", "${$j}[0]");
            }
	}
    }
    
}

#
# save user pref data submitted by the user
#
sub setupusersubmit {
    my ($dbh, $remuser, $group) = @_;
    my $tables = getarrays('hosttables', 
			   "-select", 'distinct tablename',
			   "-clauses", "where groupname = '$group'");
    
    $dbh->do("delete from userprefs where user = '$remuser' and groupname = '$group'");
    my $rep = $dbh->prepare("insert into userprefs(user, groupname, tablename, columnname, displayit) values('$remuser', '$group', ?, ?, 'N')");

    my ($i, $j);
    foreach my $i (@$tables) {
	my $sth = $dbh->prepare("select * from ${$i}[0] where 1 = 0");
	$sth->execute();

	foreach $j (@{$sth->{NAME}}) {
	    if (param("${$i}[0]" . "$j")) {
		$rep->execute("${$i}[0]", "$j");
	    }
	}
    }
}

sub Exit {
    my ($dbh, $group) = @_;
    my $tq = self_url();
    $tq =~ s/\?.*//;
    print "<hr>\n";
    print "<a href=\"$tq\">[TOP]</a>\n";
    print "<a href=\"$tq?userprefs=1\">[options]</a>\n";
    if (defined($group)) {
	print "<a href=\"$tq?group=$group\">[group: $group]</a>\n";
	print "<a href=\"$tq?group=$group&summarizegroup=1\">[summarize $group]</a>\n";
    }
    $dbh->disconnect() if (defined($dbh));
    return OK();
#    exit shift;
}

#
# setup user preferences by displaying a configuration array of
# checkbuttons for each table.
#
sub setupuserpreferences {
    my ($dbh, $user, $group) = @_;
    my $tables = getarrays('hosttables', 
			   "-select", 'distinct tablename',
			   "-clauses", "where groupname = '$group'");

    print "<h3>Select the columns from the tables that you want to <b>hide</b> below and click on submit:</h3>\n";
    print "<form method=\"post\" action=\"" . self_url() . "\">\n";

    my ($i, $j);
    foreach my $i (@$tables) {
	my $sth = $dbh->prepare("select * from ${$i}[0] where 1 = 0");
	$sth->execute();
	displayconfigarray([${$i}[0]], $sth->{NAME},
			   -check, "select * from userprefs where (tablename = ? and columnname = ? and user = '$user' and groupname = '$group' and displayit = 'N')");
    print "<br>\n";
    }
    print "<input type=hidden name=group value=\"$group\">\n";
    print "<input type=submit value=submit name=\"setupuserprefssubmit\">\n";
    print "</form>";
}
