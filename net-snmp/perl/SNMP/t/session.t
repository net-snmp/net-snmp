#!./perl

BEGIN {
    unless(grep /blib/, @INC) {
        chdir 't' if -d 't';
        @INC = '../lib' if -d '../lib';
    }
}
use Test;
BEGIN { plan tests => 4}
use SNMP;
use vars qw($agent_port $comm $agent_host);
require "t/startagent.pl";


my $badcomm = 'KKK';
my $junk_oid = ".1.3.6.1.2.1.1.1.1.1.1";
my $oid = '.1.3.6.1.2.1.1.1';
my $junk_name = 'fooDescr';
my $junk_host = 'no.host.here';
my $junk_port = '9999999';
my $junk_AuthPass = 'open_sesame';
my $junk_PrivPass = 'abrakadabara';
my $junk_SecName = 'dude';
my $name = "gmarzot\@nortelnetworks.com";
my $version = 7;

$SNMP::debugging = 0;

# create list of varbinds for GETS, val field can be null or omitted
my $vars = new SNMP::VarList (
			   ['sysDescr', '0', ''],
			   ['sysContact', '0'],
			   ['sysName', '0'],
			   ['sysLocation', '0'],
			   ['sysServices', '0'],
			   ['ifNumber', '0'],
			   ['ifDescr', '1'],
			   ['ifSpeed', '1'],
			  );

#########################== 1 ===#########################################
# Create a bogus session, undef means the host can't be found.
# removed! this test can hang for a long time if DNS is not functioning
# my $s1 = new SNMP::Session (DestHost => $junk_host );
# ok(!defined($s1));
#print("\n");
#####################== 2 ====############################################
# Fire up a session.
    my $s2 =
    new SNMP::Session (DestHost=>$agent_host,Community=>$comm,RemotePort=>$agent_port);
    ok(defined($s2));
######################==  3 ==== ##########################################

# Fire up another session with a junk port.
#my $s3 = new SNMP::Session (RemotePort => 999999999999);

#my $s3 = new SNMP::Session (Version => 3 , RemotePort => 999999999999 );
#ok(!defined($s3));
#print STDERR "Error string1 = $s3->{ErrorStr}:$s3->{ErrorInd}\n";
#print("\n");
#####################=== 4 ====###########################################
#create a V3 session by setting an IP address not running an agent (How??)
my $s4 = new SNMP::Session (Version => 3, RemotePort => 1002, Retries => 0);
ok(!defined($s4));
#print STDERR "Error string1 = $s4->{ErrorStr}:$s4->{ErrorInd}\n";
#print("\n");
######################  5  ###########################################
#create a session with bad version
my $s5 = new SNMP::Session (Version=>$version);
ok(!defined($s5));
#print("\n");
########################  6  ########################################
#Test for authorization
#my $s6 = new SNMP::Session (Version=>3, SecLevel => 'authPriv', SecName => $junk_SecName, PrivPass => $junk_PrivPass, AuthPass => $junk_AuthPass);

my $s6 = new SNMP::Session (Version=>3, SecLevel => 'authPriv', SecName => $junk_SecName, PrivPass => '', AuthPass => '' );
ok(!defined($s6));
#print STDERR "Error string2 = $s6->{ErrorStr}:$s6->{ErrorInd}\n";
#print("\n");
#####################  7  ############################################

snmptest_cleanup();
