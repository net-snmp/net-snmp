#!/usr/bin/perl

# HEADER Basic perl functionality to a UDP agent

use strict;
use warnings;
use NetSNMPTest;
use Test;
use SNMP;

# Skip if SET support is disabled
my $srcdir = $ENV{'NETSNMP_SRC_DIR'} || $ENV{'srcdir'} || "..";
my $config_h = "$srcdir/include/net-snmp/net-snmp-config.h";
if (open(my $fh, '<', $config_h)) {
    while (<$fh>) {
        if (/#define NETSNMP_DISABLE_SET_SUPPORT 1/ || /#define NETSNMP_NO_WRITE_SUPPORT 1/) {
            print "1..0 # SKIP SET support is disabled\n";
            exit 0;
        }
    }
    close($fh);
}

NetSNMPTest->require_feature("USING_MIBII_VACM_CONF_MODULE");
NetSNMPTest->require_feature("USING_MIBII_SYSTEM_MIB_MODULE");

my $value;

plan(tests => 10);

ok(1,1,"started up");

# use a basic UDP port
my $destination = "udp:localhost:9897";

my $test = new NetSNMPTest(agentaddress => $destination);

# set it up with a snmpv3 USM user
$test->config_agent("createuser testuser MD5 notareallpassword");
$test->config_agent("rwuser testuser");
$test->config_agent("syscontact itworked");

$test->DIE("failed to start the agent") if (!$test->start_agent());

# now create a session to test things with
my $session = new SNMP::Session(DestHost => $destination,
                                Version => '3',
				SecName => 'testuser',
				SecLevel => 'authNoPriv',
				AuthProto => 'MD5',
				AuthPass => 'notareallpassword');

ok(ref($session), 'SNMP::Session', "created a session");


######################################################################
# GET test
$value = $session->get('sysContact.0');

ok($value, 'itworked');

######################################################################
# GETNEXT test
$value = $session->getnext('sysContact');

ok($value, 'itworked');

######################################################################
# SET test
$value = $session->get('sysLocation.0');

ok($value ne 'yep', 1, 'Ensuring the sysLocation setting is not "yep"');

my $varbind = new SNMP::Varbind(['sysLocation', '0', 'yep', 'OCTETSTR']);


$value = $session->set($varbind);

ok(($value == 0), 1, 'return value from set was a success');

$value = $session->get('sysLocation.0');

ok($value, 'yep');

######################################################################
# GETBULK test
$varbind = new SNMP::Varbind(['sysContact']);
my @values = $session->getbulk(0, 3, $varbind);

ok($#values == 2);
ok($values[0] eq 'itworked');
ok($values[2] eq 'yep');

######################################################################
# gettable() test



######################################################################
# cleanup
$test->stop_agent();
