#!/usr/bin/perl

# HEADER Perl UDP IPv4 Test

use strict;
use warnings;
use NetSNMPTestTransport;

my $test = new NetSNMPTestTransport(agentaddress => "udp:localhost:0");
$test->require_feature("NETSNMP_TRANSPORT_UDP_DOMAIN");
$test->run_tests();
