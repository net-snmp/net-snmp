
# displaytable(TABLENAME, CONFIG...):
#
#   stolen from sqltohtml in the ucd-snmp package
#

package displaytable;

BEGIN {
    use Exporter ();
    use vars qw(@ISA @EXPORT_OK $tableparms $headerparms);
    @ISA = qw(Exporter);
    @EXPORT=qw(&displaytable &displaygraph);

    require DBI;
    require CGI;

    use PNGgraph();
    use PNGgraph::lines();
    use PNGgraph::bars();
    use PNGgraph::points();
    use PNGgraph::linespoints();
    use PNGgraph::area();
    use PNGgraph::pie();
};

$tableparms="border=1 bgcolor=\"#c0c0e0\"";
$headerparms="border=1 bgcolor=\"#b0e0b0\"";

sub displaygraph {
    my $dbh = shift;
    my $tablename = shift;
    my %config = @_;
    my $type = $config{'-type'} || "lines";
    my $x = $config{'-x'} || "640";
    my $y = $config{'-y'} || "480";
    my $bgcolor = $config{'-bgcolor'} || "white";
    my $datecol = $config{'-xcol'} || "updated";
    my $xtickevery = $config{'-xtickevery'} || 50;
    my ($thetable);

    return -1 if (!defined($dbh) || !defined($tablename) || 
		  !defined ($config{'-columns'}) || 
		  ref($config{'-columns'}) ne "ARRAY" ||
		  !defined ($config{'-indexes'}) || 
		  ref($config{'-indexes'}) ne "ARRAY");


    my $cmd = "SELECT " . 
	join(",",@{$config{'-columns'}},
	     @{$config{'-indexes'}}, $datecol) .
		 " FROM $tablename $config{'-clauses'}";
    print STDERR "$cmd\n";
    ( $thetable = $dbh->prepare($cmd))
	or return -1;
    ( $thetable->execute )
	or return -1;

    my %data;
    my $count = 0;

    while( $row = $thetable->fetchrow_hashref() ) {
	# XXX: multiple indexe columns -> unique name
	# save all the row's data based on the index column(s)
	foreach my $j (@{$config{'-columns'}}) {
	    if ($config{'-difference'} || $config{'-rate'}) {
		if (defined($lastval{$row->{$config{'-indexes'}[0]}}{$j}{'value'})) {
		    $data{$row->{$config{'-indexes'}[0]}}{$row->{$datecol}}{$j}=
			$row->{$j} - 
			    $lastval{$row->{$config{'-indexes'}[0]}}{$j}{'value'};
		    if ($config{'-positive_only'} &&
			$data{$row->{$config{'-indexes'}[0]}}{$row->{$datecol}}{$j} < 0) {
			$data{$row->{$config{'-indexes'}[0]}}{$row->{$datecol}}{$j} = 0;
		    }
		    if ($config{'-rate'}) {
			$data{$row->{$config{'-indexes'}[0]}}{$row->{$datecol}}{$j} = $data{$row->{$config{'-indexes'}[0]}}{$row->{$datecol}}{$j}*$config{'-rate'}/($row->{$datecol} - $lastval{$row->{$config{'-indexes'}[0]}}{$j}{'index'});
		    }
		}
		$lastval{$row->{$config{'-indexes'}[0]}}{$j}{'value'} = $row->{$j};
		$lastval{$row->{$config{'-indexes'}[0]}}{$j}{'index'} = $row->{$datecol};
	    } else {
		$data{$row->{$config{'-indexes'}[0]}}{$row->{$datecol}}{$j} = $row->{$j};
	    }
	}
	push @xdata,$row->{$datecol};
    }

    my @pngdata;
    push @pngdata, \@xdata;

    my @datakeys = keys(%data);

#    open(O,">/tmp/data");
    foreach my $i (@datakeys) {
	foreach my $j (@{$config{'-columns'}}) {
	    my @newrow;
	    foreach my $k (@xdata) {
#		print O "i=$i k=$k j=$j :: $data{$i}{$k}{$j}\n";
		push @newrow, ($data{$i}{$k}{$j} || 0);
	    }
	    push @pngdata,\@newrow;
	}
    }
#    close O;

    if ($#pngdata > 0) {
    # create the graph itself
	my $graph = new PNGgraph::lines($x, $y);
	$graph->set('bgclr' => $bgcolor);
	foreach my $i (qw(title x_label_skip x_labels_vertical x_tick_number x_number_format y_number_format x_min_value x_max_value y_min_value y_max_value)) {
	    $graph->set("$i" => $config{"-$i"}) if ($config{"-$i"});
	}
	if ($config{'-pngparms'}) {
	    $graph->set(@{$config{'-pngparms'}});
	}
	print $graph->plot(\@pngdata);
	return $#pngdata;
    }
    return -1;
}

sub displaytable {
    my $dbh = shift;
    my $tablename = shift;
    my %config = @_;
    my $clauses = $config{'-clauses'};
    my $sortfn = $config{'-sort'};
    my $dolink = $config{'-dolink'};
    my $datalink = $config{'-datalink'};
    my $beginhook = $config{'-beginhook'};
    my $endhook = $config{'-endhook'};
    my $selectwhat = $config{'-select'};
    my $printonly = $config{'-printonly'};
    $selectwhat = "*" if (!defined($selectwhat));
    my $tableparms = $config{'-tableparms'} || $displaytable::tableparms;
    my $headerparms = $config{'-headerparms'} || $displaytable::headerparms;
    my ($thetable, $data, $ref, $prefs, $xlattable);

    if ($config{'-dontdisplaycol'}) {
	($prefs = $dbh->prepare($config{'-dontdisplaycol'}) )
	    or die "\nnot ok: $DBI::errstr\n";
    }

    # get a list of data from the table we want to display
    ( $thetable = $dbh->prepare("SELECT $selectwhat FROM $tablename $clauses"))
	or return -1;
    ( $thetable->execute )
	or return -1;

    # get a list of data from the table we want to display
    if ($config{'-xlat'}) {
	( $xlattable = 
	 $dbh->prepare("SELECT newname FROM $config{'-xlat'} where oldname = ?"))
	    or die "\nnot ok: $DBI::errstr\n";
    }
    
    # editable setup
    my $edited = 0;
    my $editable = 0;
    my (@editkeys, @valuekeys, $uph);
    my %edithash;
    if (defined($config{'-CGI'}) &&  ref($config{'-CGI'}) eq "CGI"
	&& defined($config{'-editable'}) && 
	ref($config{'-editable'}) eq ARRAY) {
	$editable = 1;
	$q = $config{'-CGI'};
	if ($q->param('edited_' . toalpha($tablename))) {
	    $edited = 1;
	}
	@editkeys = @{$config{'-editable'}};
	foreach my $kk (@editkeys) {
	    $edithash{$kk} = 1;
#	    print "edithash $kk<br>\n";
	}
    }

    # table header
    my $doheader = 1;
    my @keys;
    my $rowcount = 0;
    $thetable->execute();
    if ($editable) {
	print "<input type=hidden name=\"edited_" . toalpha($tablename) . "\" value=1>\n";
    }

    while( $data = $thetable->fetchrow_hashref() ) {
	$rowcount++;
	if ($edited && !defined($uph)) {
	    foreach my $kk (keys(%$data)) {
		push (@valuekeys, $kk) if (!defined($edithash{$kk}));
	    }
	    my $cmd = "update $tablename set " . 
		join(" = ?, ",@valuekeys) . 
		    " = ? where " . 
			join(" = ? and ",@editkeys) .
			    " = ?";
	    $uph = $dbh->prepare($cmd);
#	    print "setting up: $cmd<br>\n";
	}
	if ($doheader) {
	    if (defined($sortfn) && ref($sortfn) eq "CODE") {
		@keys = (sort $sortfn keys(%$data));
	    } elsif ($config{'-selectorder'}) {
		$_ = $selectwhat;
		@keys = split(/, */);
	    } else {
		@keys = (sort keys(%$data));
	    }
	    if (!defined($config{'-notitle'})) {
		print "<br><b>";
		print "<a href=\"$ref\">" if (defined($dolink) && 
					      defined($ref = &$dolink($tablename)));
		if ($config{'-xlat'}) {
		    my $toval = $xlattable->execute($tablename);
		    if ($toval > 0) {
			print $xlattable->fetchrow_array;
		    } else {
			print "$tablename";
		    }
		} else {
		    print "$tablename";
		}
		print "</a>" if (defined($ref));
		print "</b>\n";
	    }
	    print "<br>\n";
	    print "<table $tableparms>\n";
	    if (!$config{'-noheaders'}) {
		print "<tr $headerparms>";
	    }
	    if (defined($beginhook)) {
		&$beginhook($dbh, $tablename);
	    }
	    if (!$config{'-noheaders'}) {
		foreach $l (@keys) {
		    if (!defined($prefs) || 
			$prefs->execute($tablename, $l) eq "0E0") {
			print "<th>";
			print "<a href=\"$ref\">" if (defined($dolink) && 
						      defined($ref = &$dolink($l)));
			if ($config{'-xlat'}) {
			    my $toval = $xlattable->execute($l);
			    if ($toval > 0) {
				print $xlattable->fetchrow_array;
			    } else {
				print "$l";
			    }
			} else {
			    print "$l";
			}
			print "</a>" if (defined($ref));
			print "</th>";
		    }
		}
	    }
	    if (defined($endhook)) {
		&$endhook($dbh, $tablename);
	    }
	    if (!$config{'-noheaders'}) {
		print "</tr>\n";
	    }
	    $doheader = 0;
	}

	print "<tr>";
	if (defined($beginhook)) {
	    &$beginhook($dbh, $tablename, $data);
	}
	if ($edited) {
#	    print "updating ", join(", ", 
#				     getquery($q, $data, \@editkeys, @valuekeys)), ":",
#	    join(", ",getvalues($data, @editkeys)), "<br>\n";
	    
	    my $ret = $uph->execute(getquery($q, $data, \@editkeys, @valuekeys), 
				    getvalues($data, @editkeys));
#	    print "ret: $ret, $DBI::errstr<br>\n";
	}
	foreach $key (@keys) {
	    if (!defined($prefs) || 
		$prefs->execute($tablename, $key) eq "0E0") {
		print "<td>";
		print "<a href=\"$ref\">" if (defined($datalink) && 
					      defined($ref = &$datalink($key, $data->{$key})));
		if (!$edited && $editable && !defined($edithash{$key})) {
		    my $ukey = to_unique_key($key, $data, 
					     @{$config{'-editable'}});
		    print "<input type=text name=\"$ukey\" value=\"$data->{$key}\">";
		} else {
		    if ($data->{$key} ne "") {
			print $data->{$key};
		    } else {
			print "&nbsp";
		    }
		}
		print "</a>" if (defined($ref));
		print "</td>";
	    }
	}

	if (defined($endhook)) {
	    &$endhook($dbh, $tablename, $data);
	}
	print "</tr>\n";
	last if (defined($config{'-maxrows'}) && 
		 $rowcount >= $config{'-maxrows'});
    }
    if ($rowcount > 0) {
	print "</table>\n";
    }
    return $rowcount;
}

sub to_unique_key {
    my $ret = shift;
    $ret .= "_";
    my $data = shift;
    foreach my $i (@_) {
	$ret .= "_" . $data->{$i};
    }
    return toalpha($ret);
}

sub toalpha {
    my $ret = join("",@_);
    $ret =~ s/([^A-Za-z0-9_])/ord($1)/eg;
    return $ret;
}

sub getvalues {
    my $hash = shift;
    my @ret;
    foreach my $i (@_) {
	push @ret, $hash->{$i};
    }
    return @ret;
}

sub getquery {
    my $q = shift;
    my $data = shift;
    my $keys = shift;
    my @ret;
    foreach my $i (@_) {
	push @ret, $q->param(to_unique_key($i, $data, @$keys));
    }
    return @ret;
}
1;
