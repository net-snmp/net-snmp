#!./perl

BEGIN {
    unless(grep /blib/, @INC) {
        chdir 't' if -d 't';
        @INC = '../lib' if -d '../lib';
    }
}

use Test;
BEGIN { plan tests => 9 }
use SNMP;

my $host = 'localhost';
my $comm = 'v1_private';
my $port = 8000;
my $junk_oid = ".1.3.6.1.2.1.1.1.1.1.1";
my $oid = '.1.3.6.1.2.1.1.1';
my $junk_name = 'fooDescr';
my $junk_host = 'no.host.here';
my $name = "gmarzot\@nortelnetworks.com";

my $snmpd_cmd;

if ((-e "t/snmpd.pid") && (-r "t/snmpd.pid")) {
# Making sure that any running agents are killed.
    system "kill `cat t/snmpd.pid` > /dev/null 2>&1";
    unlink "t/snmpd.pid";
}

if (open(CMD,"<t/snmpd.cmd")) {
    ($snmpd_cmd) = (<CMD> =~ /SNMPD => (\S+)\s*/);
    if (-r $snmpd_cmd and -x $snmpd_cmd) {
	system "$snmpd_cmd -r -l t/snmpd.log -C -c t/snmpd.conf -p $port -P t/snmpd.pid > /dev/null 2>&1";
    } else {
	undef $snmpd_cmd;
    }
    close CMD;
}

$SNMP::debugging = 0;
$n = 9;  # Number of tests to run

#print "1..$n\n";
#if ($n == 0) { exit 0; }

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


##############################  1  #####################################
# Fire up a session.
my $s1 = new SNMP::Session (DestHost=>$host,Community=>$comm,RemotePort=>$port);
ok(defined($s1),1);
#print("\n");
#####################################################################
# if no snmpd then skip dynamic tests
unless ($snmpd_cmd) {
    print STDERR "[no agent running]";
    for (3..$n) {
	skip(1,0);
    }
    exit(0);
}


#############################  2  #######################################
# Try getnext on sysDescr.0

my $next = $s1->getnext('sysDescr.0');
#print ("The next OID is : $next\n");
ok($s1->{ErrorStr} eq '');
#print STDERR "Error string1 = $s1->{ErrorStr}:$s1->{ErrorInd}\n";
#print("\n");

###########################  3  ########################################
#$v1 = $s1->getnext('sysLocation.0');
#print ("The next OID is : $v1\n");
my $v2 = $s1->getnext('sysServices.0');
#print ("The next OID is : $v2\n");
ok($s1->{ErrorStr} eq '');
#print STDERR "Error string2 = $s1->{ErrorStr}:$s1->{ErrorInd}\n";
#print("\n");


############################  4  #######################################
# try it on an unknown OID
my $v3 = $s1->getnext('Srivathsan.0');
#print ("The unknown  OID is : $v3\n");
ok($s1->{ErrorStr} =~ /^Unknown/);
#print STDERR "Error string5 = $s1->{ErrorStr}:$s1->{ErrorInd}\n";
#print("\n");
############################# 5  #######################################
# On a non-accessible value
#my $kkk = $s1->getnext('vacmSecurityName.1');
#print("kkk is $kkk\n");
#ok($s1->{ErrorInd} != 0);
#print STDERR "Error string5 = $s1->{ErrorStr}:$s1->{ErrorInd}\n";
#print("\n");

#############################  6  ####################################
# We should get back sysDescr.0 here.
my $var = new SNMP::Varbind(['sysDescr']);
my $res2 = $s1->getnext($var);
#print("res2 is : $res2\n");
ok((not $s1->{ErrorStr} and not $s1->{ErrorInd}));
ok((defined $var->iid and $var->iid eq 0));
ok((defined $var->val and $var->val eq $res2));

#############################  7  ######################################
# get the next one after that as well for a second check
my $res3 = $s1->getnext($var);
#print("res3 is : $res3\n");
ok((defined $var->tag and $var->tag eq 'sysObjectID'));
ok((defined $var->val and $var->val eq $res3));


if ((-e "t/snmpd.pid") && (-r "t/snmpd.pid")) {
# Making sure that any running agents are killed.
    system "kill `cat t/snmpd.pid` > /dev/null 2>&1";
}

