#!/usr/bin/perl
#
# Net-SNMP Perl Test
#
# Written by Alex Burger
# alex_b@users.sourceforge.net
#
# 3/26/2004
#
##############################################################################
$| = 1;

use SNMP;

$ENV{'MIBS'} = 'ALL';

&SNMP::initMib();

$SNMP::best_guess = 2;
$include_module   = 1;

my $test;
my $long_names;
my $include_module;

print "\n\nTesting translateObj\n";
print "********************\n";

$test = 'sysDescr';
$expect = '.1.3.6.1.2.1.1.1';
$long_names = 0;
$include_module = 0;

$translated = &SNMP::translateObj("$test",$long_names,$include_module);
if ($translated eq $expect)
{
  print "Test passed.  Result: $translated\n";
}
else
{
  print "Test FAILED!  Expected: $expect\n";
  print "              Received: $translated\n";
}

print "\n";

