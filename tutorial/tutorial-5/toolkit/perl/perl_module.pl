#!/usr/bin/perl
#
# This is an example of perl module support for the net-snmp agent.
#
# To load this into a running agent with embedded perl support turned
# on, simply put the following line (without the leading # mark) your
# snmpd.conf file:
#
#   perl do "/path/to/perl_module.pl";
#

my $regat = '.1.3.6.1.4.1.8072.999';

BEGIN {
    print STDERR "starting perl_module.pl\n";
}

use NetSNMP::OID (':all');
use NetSNMP::agent (':all');
use NetSNMP::ASN (':all');

print STDERR "perl_module.pl loaded ok\n";

# set to 1 to get extra debugging information
$debugging = 1;

# if we're not embedded, this will get auto-set below to 1
$subagent = 0;

# where we are going to hook onto
my $regoid = new NetSNMP::OID('.1.3.6.1.4.1.8072.999');
print STDERR "registering at ",$regoid,"\n" if ($debugging);

# If we're not running embedded within the agent, then try to start
# our own subagent instead.
if (!$agent) {
    $agent = new NetSNMP::agent('Name' => 'test', # reads test.conf
				'AgentX' => 1);   # make us a subagent
    $subagent = 1;
    print STDERR "started us as a subagent ($agent)\n"
}

# we register ourselves with the master agent we're embedded in.  The
# global $agent variable is how we do this:
$agent->register('myname',$regoid, \&my_snmp_handler);


if ($subagent) {
    # We need to perform a loop here waiting for snmp requests.  We
    # aren't doing anything else here, but we could.
    $SIG{'INT'} = \&shut_it_down;
    $SIG{'QUIT'} = \&shut_it_down;
    $running = 1;
    while($running) {
	$agent->agent_check_and_process(1);  # 1 = block
	print STDERR "mainloop excercised\n" if ($debugging);
    }
    $agent->shutdown();
}

######################################################################
# define a subroutine to actually handle the incoming requests to our
# part of the OID tree.  This subroutine will get called for all
# requests within the OID space under the registration oid made above.
sub my_snmp_handler {
    my ($handler, $registration_info, $request_info, $requests) = @_;
    my $request;

    print STDERR "refs: ",join(", ", ref($handler), ref($registration_info), 
			       ref($request_info), ref($requests)),"\n";

    print STDERR "processing a request of type " . $request_info->getMode() . "\n"
	if ($debugging);

    for($request = $requests; $request; $request = $request->next()) {
      my $oid = $request->getOID();
      print STDERR "  processing request of $oid\n";

      if ($request_info->getMode() == MODE_GET) {
	# if the requested oid is equals to ours, then return the data
	if ($oid == new NetSNMP::OID($regat . ".1.2.1")) {
	  print STDERR "   -> hello world\n" if ($debugging);
	  $request->setValue(ASN_OCTET_STR, "hello world");
	}
      } elsif ($request_info->getMode() == MODE_GETNEXT) {
	# if the requested oid is lower than ours, then return ours
	if ($oid < new NetSNMP::OID($regat . ".1.2.1")) {
	  print STDERR "   $regat.1.2.1 -> hello world\n" if ($debugging);
	  $request->setOID($regat . ".1.2.1");
	  $request->setValue(ASN_OCTET_STR, "hello world");
	}
      }
    }

    print STDERR "  finished processing\n"
	if ($debugging);
}

sub shut_it_down {
  $running = 0;
  print STDERR "shutting down\n" if ($debugging);
}
