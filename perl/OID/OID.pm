package NetSNMP::OID;

use 5.006;
use strict;
use warnings;
use Carp;

require Exporter;
require DynaLoader;
use AutoLoader;

sub compare($$);

use overload
    '<=>' => \&compare,
    '""' => \&quote_oid
;
   

use SNMP;

sub quote_oid {
    my $this = shift;
    return $this->{'oidptr'}->to_string();
}

our @ISA = qw(Exporter DynaLoader);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use NetSNMP::OID ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	snmp_oid_compare
        compare
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	snmp_oid_compare
        compare
);
our $VERSION = '0.01';

sub new {
    my $type = shift;
    my $self = {};
    my $arg = shift;
    SNMP::init_snmp();
    bless($self, $type);
    $self->{'oidptr'} = NetSNMP::OID::newptr($arg);
    return $self;
}

sub snmp_oid_compare($$) {
    my ($oid1, $oid2) = @_;
    return _snmp_oid_compare($oid1->{oidptr}, $oid2->{oidptr});
}

sub compare($$) {
    my ($v1, $v2) = @_;
    snmp_oid_compare($v1, $v2);
}

sub to_array($) {
    my $self = shift;
    return $self->{oidptr}->to_array();
}

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.  If a constant is not found then control is passed
    # to the AUTOLOAD in AutoLoader.

    my $constname;
    our $AUTOLOAD;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "& not defined" if $constname eq 'constant';
    my $val = constant($constname, @_ ? $_[0] : 0);
    if ($! != 0) {
	if ($! =~ /Invalid/ || $!{EINVAL}) {
	    $AutoLoader::AUTOLOAD = $AUTOLOAD;
	    goto &AutoLoader::AUTOLOAD;
	}
	else {
	    croak "Your vendor has not defined NetSNMP::OID macro $constname";
	}
    }
    {
	no strict 'refs';
	# Fixed between 5.005_53 and 5.005_61
	if ($] >= 5.00561) {
	    *$AUTOLOAD = sub () { $val };
	}
	else {
	    *$AUTOLOAD = sub { $val };
	}
    }
    goto &$AUTOLOAD;
}

bootstrap NetSNMP::OID $VERSION;

# Preloaded methods go here.

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is stub documentation for your module. You better edit it!

=head1 NAME

NetSNMP::OID - Perl extension for manipulating OIDs

=head1 SYNOPSIS

  use NetSNMP::OID;

  my $oid = new NetSNMP::OID('sysContact.0');

  if ($oid < new NetSNMP::OID('ifTable')) {
      do_something();
  }

  my @numarray = $oid->to_array();

=head1 DESCRIPTION

The NetSNMP::OID class is a simple wrapper around a C-based net-snmp
oid.  The OID is internally stored as a C array of integers for speed
purposes when doing comparisons, etc.  The standard logical expression
operators (<, >, ==, ...) are overloaded such that lexographical
comparisons may be done with them.

=head2 EXPORT

int snmp_oid_compare(oid1, oid2)
int compare(oid1, oid2)

=head1 AUTHOR

Wes Hardaker, E<lt>hardaker@users.sourceforge.netE<gt>

=head1 SEE ALSO

L<SNMP>, L<perl>.

=head1 Copyright

Copyright (c) 2002 Networks Associates Technology, Inc.  All
Rights Reserved.  This program is free software; you can
redistribute it and/or modify it under the same terms as Perl
itself.

=cut
