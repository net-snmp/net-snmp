package NetSNMP::agent::netsnmp_request_info;

require 5.005_62;
use strict;
use warnings;
use Carp;

require Exporter;
require DynaLoader;
use AutoLoader;

use NetSNMP::OID (':all');

sub getOID {
  return NetSNMP::OID::newwithptr(getOIDptr($_[0]));
}


1;
__END__
=head1 NAME

NetSNMP::agent::netsnmp_request_info - Perl extension for request information

=head1 SYNOPSIS

  use NetSNMP::agent;
  my $agent = new NetSNMP::agent('Name' -> 'my_agent_name');
  ... TBD ...

=head1 AUTHOR

Please mail the net-snmp-users@lists.sourceforge.net mailing list for
help, questions or comments about this module.

Wes Hardaker, hardaker@users.sourceforge.net

=cut
