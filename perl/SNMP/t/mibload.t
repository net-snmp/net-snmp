#!./perl

# Written by John Stoffel (jfs@fluent.com) - 10/13/1997

BEGIN {
    unless(grep /blib/, @INC) {
        chdir 't' if -d 't';
        @INC = '../lib' if -d '../lib';
    }
}

use Test;
BEGIN {plan tests => 5}
use SNMP;

$SNMP::verbose = 0;
#$n = 3;  # Number of tests to run

#print "1..$n\n";
#if ($n == 0) { exit 0; } else { $n = 1; }

my $junk_oid = ".1.3.6.1.2.1.1.1.1.1.1";
my $oid = '.1.3.6.1.2.1.1.1';
my $name = 'sysDescr';
my $junk_name = 'fooDescr';
my $mib_file = 't/mib.txt';
my $junk_mib_file = 'mib.txt';
my @mibdir = ('/usr/local/share/snmp/mibs/');
my @mibfile = ('/usr/local/share/snmp/mibs/IPV6-TCP-MIB.txt');

######################################################################
# See if we can find a mib to use, return of 0 means the file wasn't
# found or isn't readable. 

$res = SNMP::setMib($junk_mib_file,1);
#printf "%s %d\n", (!$res) ? "ok" :"not ok", $n++;
ok(defined(!$res));
#print("\n");
######################################################################
# Now we give the right name

$res = SNMP::setMib($mib_file,1);
#printf "%s %d\n", ($res) ? "ok" :"not ok", $n++;
ok(defined($res));
#print("\n");
######################################################################
# See if we can find a mib to use

$res = SNMP::setMib($mib_file,0);
#printf "%s %d\n", ($res) ? "ok" :"not ok", $n++;
ok(defined($res));
#print("\n");
######################## 4 ################################
# add a mib dir

$res = SNMP::addMibDirs($mibdir[0]);
#print(" dir is $mibdir[0]\n");
SNMP::loadModules("IP-MIB", "IF-MIB", "IANAifType-MIB", "RFC1213-MIB");
#SNMP::unloadModules(RMON-MIB);
#etherStatsDataSource shouldn't be found.
#present only in 1271 & RMON-MIB.
$res = $SNMP::MIB{etherStatsDataSource};
#print("Module ID is: $res\n");
ok(!defined($res));
#print("\n");
########################  5  ############################
# add mib file

$res = SNMP::addMibFiles($mibfile[0]);
#print("the file is: $mibfile[0]\n");
$res = $SNMP::MIB{ipv6TcpConnState}{moduleID};
#print("Module ID is: $res\n");
ok($res =~ /^IPV6-TCP-MIB/);
########################  6  ##########################


