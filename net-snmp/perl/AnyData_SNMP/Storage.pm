#########################################################################
package AnyData::Storage::SNMP;
#########################################################################

## XXX: TODO:
##   scalar sets?
##   multi-hosts

$AnyData::Storage::VERSION = '0.01';
use strict;

use vars qw(@basecols);

@AnyData::Storage::SNMP::basecols = qw(hostname iid);
$AnyData::Storage::SNMP::iidptr = 1; # must match array column of above
@AnyData::Storage::SNMP::basetypes = qw(OCTETSTR OBJECTID);
$AnyData::Storage::SNMP::debug = 0;
$AnyData::Storage::SNMP::debugre = undef;

use Data::Dumper;
use AnyData::Storage::File;
use SNMP;
SNMP::initMib();

sub new {
    DEBUG("calling AnyData::Storage::SNMP new\n");
    DEBUG("new storage: ",Dumper(\@_),"\n");
    my $class = shift;
    my $self  = shift || {};
    $self->{open_mode} = 'c';
    return bless $self, $class;
}

sub open_table {
    DEBUG("calling AnyData::Storage::SNMP open_table\n");
    my ($self, $parser, $table, $mode, $tname) = @_;
    $self->{'process_table'} = $tname;
    DEBUG("open_table: ",Dumper(\@_),"\n");
}

sub get_col_names {
    DEBUG("calling AnyData::Storage::SNMP get_col_names\n");
    my ($self, $parser, $tname) = @_;
    DEBUG("get_col_names\n",Dumper(\@_),"\n");
    $tname = $self->{'process_table'} if (!$tname);

    # get cached previous results
    return $self->{col_names}{$tname} if (defined($self->{col_names}{$tname}));

    # table name
    $tname = $self->{'process_table'} if (!$tname);

    # mib node setup
    my $mib = $SNMP::MIB{$tname} || return warn "no such table $tname";
    my $entry = $mib->{'children'}[0];

    # base columns and types
    my @cols = @AnyData::Storage::SNMP::basecols;
    my @types = @AnyData::Storage::SNMP::basetypes;
    my %donecol;
    my $count = $#cols;

    foreach my $index (@{$entry->{'indexes'}}) {
	push @cols, $index;
	push @types, $SNMP::MIB{$index}{type};
	$donecol{$index} = 1;
	$count++;
	if ($SNMP::MIB{$index}{parent}{label} eq $entry->{label}) {
	    # this index is a member of this table
	    $self->{columnmap}[$count] = $index;
	    $self->{coloffset} += 1;
	}
    }

    # search children list
    foreach my $child  ( sort { $a->{'subID'} <=> $b->{'subID'} } @{$entry->{'children'}}) {
	push @{$self->{real_cols}}, $child->{'label'};
	next if ($donecol{$child->{label}});
	push @cols, $child->{'label'};
	push @types, $child->{'type'};
	$count++;
	$self->{columnmap}[$count] = $child->{'label'};
    }

    # save for later.
    $parser->{col_names} = \@cols;
    $self->{col_types} = \@types;
    $self->{col_names} = \@cols;
    return \@cols;
}

sub set_col_nums {
    DEBUG("calling AnyData::Storage::SNMP set_col_nums\n");
    DEBUG("set_col_nums\n",Dumper(\@_),"\n");
    my ($self, $tname) = @_;
    return $self->{col_nums} if (defined($self->{col_nums}));
    my $mib = $SNMP::MIB{$tname};
    my $entry = $mib->{'children'}[0];
    my (%cols, %mibnodes);
    my $cnt = -1;

    foreach my $i (@{$self->{col_names}}) {
	$cols{$i} = ++$cnt;
    }

    $self->{col_nums} = \%cols;
    return \%cols;
}

# not needed?
sub get_file_handle {
    DEBUG("calling AnyData::Storage::SNMP get_file_handle\n");
    DEBUG("get_file_handle\n",Dumper(\@_),"\n");
    return shift;
}

# not needed?
sub get_file_name {
    DEBUG("calling AnyData::Storage::SNMP get_file_name\n");
    DEBUG("get_file_name\n",Dumper(\@_),"\n");
    my $self = shift;
    return $self->{process_table} || $self->{table_name};
}

sub truncate {
    DEBUG("calling AnyData::Storage::SNMP truncate\n");
    my ($self) = @_;
    DEBUG("trunacte, ", Dumper(@_));

    # We must know how to delete rows or else this is all pointless.
#     return $self->{col_nums}{$tname} if (defined($self->{col_nums}{$tname}));
    my $tablemib = $SNMP::MIB{$self->{process_table}};
    my $entrymib = $tablemib->{'children'}[0];
    my ($delcolumn, $delcolumnname, $delcolumnvalue);

    foreach my $child  (@{$entrymib->{'children'}}) {
	if ($child->{'textualConvention'} eq 'RowStatus') {
	    $delcolumn = $child->{subID};
	    $delcolumnname = $child->{label};
	    $delcolumnvalue = 6; # destroy
	    last;
	}
    }
    if (!$delcolumn) {
	return warn "Can't (or don't know how to) delete from table $self->{process_table}.  Failing.\n";
    }

    # we should have a session, or else something is really wierd but...
    $self->{'sess'} = $self->make_session() if (!$self->{'sess'});

    # for each key left in our cache, delete it
    foreach my $key (keys(%{$self->{'existtest'}})) {
	# xxx: fullyqualified oid better
	my $vblist = new SNMP::VarList([$delcolumnname, $key,
					$delcolumnvalue]);
	DEBUG("truncate $key: \n", Dumper($vblist));
	$self->{'sess'}->set($vblist) || warn $self->{'sess'}->{ErrorStr};
    }
    return;
}

sub make_session {
    DEBUG("calling AnyData::Storage::SNMP make_session\n");
    my $self = shift;
    my @args;
    foreach my $key (qw(DestHost SecName Version SecLevel AuthPass Community RemotePort Timeout Retries RetryNoSuch SecEngineId ContextEngineId Context AuthProto PrivProto PrivPass)) {
	push @args, $key, $self->{$key} if ($self->{$key});
    }
    push @args, @_;
    return new SNMP::Session(@args);
}

sub file2str {
    DEBUG("calling AnyData::Storage::SNMP file2str\n");
    my ($self, $parser, $cols) = @_;
    my @retcols;
    DEBUG("file2str\n",Dumper(\@_),"\n");
    if (!$self->{lastnode}) {
#	my @vbstuff = @{$parser->{'col_names'}};
#	splice (@vbstuff,0,1+$#AnyData::Storage::SNMP::basecols);
#	map { $_ = [ $_ ] } @vbstuff;
#	$self->{lastnode} = new SNMP::VarList(@vbstuff);
#	splice (@$cols,0,1+$#AnyData::Storage::SNMP::basecols);
	if ($#$cols == -1) {
	    $cols = $self->{'col_names'};
	    # remove base columns
	    splice (@$cols,0,1+$#AnyData::Storage::SNMP::basecols);
	    # remove not accessible columns
	    foreach my $col (@$cols) {
		my $mib = $SNMP::MIB{$col};
		push @retcols, $col if ($mib->{'access'} =~ /Read|Create/);
	    }
	} else {
	    @retcols = @$cols;
	    # remove base columns
	    foreach my $c (@AnyData::Storage::SNMP::basecols) {
		@retcols = grep(!/^$c$/, @retcols);
	    }
	    # remove non-accessible columns
	    @retcols = grep {$SNMP::MIB{$_}{'access'} =~ /Read|Create/} @retcols;
	}
	map { $_ = [ $_ ] } @retcols;
	$self->{lastnode} = new SNMP::VarList(@retcols);
    }

    $self->{'sess'} = $self->make_session() if (!$self->{'sess'});

    # perform SNMP operation
    my $lastnode = $self->{'lastnode'}[0][0];
    my $result;
    $result = $self->{'sess'}->getnext($self->{lastnode});
    if (!defined($result)) {
	warn " getnext of $self->{lastnode}[0][0] . $self->{lastnode}[0][0] returned undef\n";
    }
    DEBUG(" result: ",Dumper($self->{lastnode}),"\n");

    # XXX: check for holes!

    # need proper oid compare here for all nodes
    return undef if ($self->{'lastnode'}[0][0] ne $lastnode);
    
    # add in basecols information:
    my @ret = ('localhost',$self->{'lastnode'}[0][1]);
    DEBUG("Dump row results: ",Dumper($self->{'lastnode'}),"\n");

    # build result array from result varbind contents
    map { $ret[$self->{'col_nums'}{$_->[0]}] = $_->[2]; } @{$self->{'lastnode'}};

    # store instance ID for later use if deletion is needed later.
    $self->{'existtest'}{$self->{'lastnode'}[0][1]} = 1;

    DEBUG("Dump row results2: ",Dumper(\@ret),"\n");
    return \@ret;
}

sub push_row {
    DEBUG("calling AnyData::Storage::SNMP push_row\n");
    DEBUG("push_row: ",Dumper(\@_),"\n");
    DEBUG("push_row\n");
    my ($self, $values, $parser, $cols) = @_;
    my @callers = caller(3);
    my $mode = $callers[3];
    if ($mode =~ /DELETE/) {
	DEBUG("not deleting $values->[$AnyData::Storage::SNMP::iidptr]\n");
	delete $self->{'existtest'}{$values->[$AnyData::Storage::SNMP::iidptr]};
	return;
    }

    my @origvars;
    if ($#$cols == -1) {
	# no column info passed in.  Update everything (mode probably INSERTS).
#	@origvars = @{$self->{'col_names'}}};
#	splice (@origvars,0,1+$#AnyData::Storage::SNMP::basecols);
	
	map { push @origvars, $_ if $SNMP::MIB{$_}{'access'} =~ /Write|Create/; } @{$self->{'real_cols'}} ;

	DEBUG("set cols: ", Dumper(\@origvars));
    } else {
	# only update the columns in question.  (mode probably UPDATE)
	@origvars = @$cols;
    }

    my @vars;
    foreach my $var (@origvars) {
	my $access = $SNMP::MIB{$var}{'access'};
	# not in this table, probably (hopefully) an index from another:
	next if ($SNMP::MIB{$var}{'parent'}{'parent'}{'label'} ne 
		 $self->{process_table});
	DEBUG("$var -> $access\n");
	if ($access =~ /(Write|Create)/) {
	    push @vars, $var;
	} elsif ($mode eq 'insert') {
	    DEBUG("XXX: error if not index\n");
	} elsif ($mode eq 'update') {
	    DEBUG("update to non-writable column attempted (SNMP error coming)\n");	
	}
    }

    # generate index OID component if we don't have it.
    if ($values->[$AnyData::Storage::SNMP::iidptr] eq '') {
	$values->[$AnyData::Storage::SNMP::iidptr] = 
	    $self->make_iid($self->{process_table}, $values);
    }

    # add in values to varbind columns passed in from incoming parameters
    map {
	my $num = $self->{'col_nums'}{$_};
	DEBUG("types: $_ -> $num -> ", $self->{'col_types'}[$num], 
	      " -> val=", $values->[$num], "\n");
	# build varbind: column-oid, instance-id, value type, value
	$_ = [$_, $values->[1], $values->[$num],
	      $self->{'col_types'}[$num]];
    } @vars;

    # create the varbindlist
    my $vblist = new SNMP::VarList(@vars);

    
    DEBUG("set: ", Dumper($vblist));
    $self->{'sess'} = $self->make_session() if (!$self->{'sess'});
    if (!$self->{'sess'}) {
	warn "couldn't create SNMP session";
    } elsif (!$self->{'sess'}->set($vblist)) {
	my $err = "$self->{process_table}: " . $self->{'sess'}->{ErrorStr};
	if ($self->{'sess'}->{ErrorInd}) {
	    $err = $err . " (at varbind #" 
		. $self->{'sess'}->{ErrorInd}  . " = " ;
	    my $dump = Data::Dumper->new([$vblist->[$self->{'sess'}->{ErrorInd} -1]]);
	    $err .= $dump->Indent(0)->Terse(1)->Dump;
	}
	warn $err;
    }
}

sub seek {
    DEBUG("calling AnyData::Storage::SNMP seek\n");
    my ($self, $parser) = @_;
    DEBUG("seek\n",Dumper(\@_),"\n");
}

sub make_iid {
    DEBUG("calling AnyData::Storage::SNMP make_iid\n");
    my ($self, $tname, $vals) = @_;
    
    # Get indexes
    my $mib = $SNMP::MIB{$tname};
    my $entry = $mib->{'children'}[0];
    my $indexes = $entry->{'indexes'};
    my $iid;

    # XXX: implied

    foreach my $index (@$indexes) {
	warn "A null index value was found, which I doubt is correct." if (!defined($vals->[$self->{col_nums}{$index}]));
	my $val = $vals->[$self->{col_nums}{$index}];
	my $type = $SNMP::MIB{$index}->{'type'};
	DEBUG("index type: $index -> $type -> $val -> " . length($val) . "\n");
	if ($type eq "OCTETSTR") {
	    $iid .= "." . length($val) . "." . join(".", unpack("c*", $val));
	} elsif ($type eq "OBJID") {
	    $iid .= "." . (scalar grep(/\./,$val) + 1) . "." . $val;
	} else {
	    # should be only an INTEGER?
	    $iid .= "." . $val;
	}
    }
    DEBUG("made iid: $iid\n");
    return $iid;
}

sub DEBUG {
    my @info = caller(1);
    if ($AnyData::Storage::SNMP::debug
	|| ($AnyData::Storage::SNMP::debugre &&
	    $_[0] =~ /$AnyData::Storage::SNMP::debugre/)) {
	DEBUGIT(\@info, @_);
    }
}

sub DEBUGIT {
    my $info;
    if (ref($_[0]) eq 'ARRAY') {
	$info = shift @_;
    } else {
	my @y;
	my $c=0;
	print STDERR "debug chain: ";
	for(@y = caller($c); $#y > -1; $c++, @y = caller($c)) {
	    print STDERR "  $c: $y[3]\n";
	}
	my @x = caller(1);
	$info = \@x;
    }
    print STDERR "$info->[3]: ";
    print STDERR @_;
}
1;
