#!./perl

# Written by John Stoffel (jfs@fluent.com) - 10/13/1997

BEGIN {
    unless(grep /blib/, @INC) {
        chdir 't' if -d 't';
        @INC = '../lib' if -d '../lib';
    }
}

# to print the description...
$SNMP::save_descriptions = 1;

use Test;
BEGIN {plan tests => 26}
use SNMP;

SNMP::initMib();

$SNMP::verbose = 0;

#$n = 3;  # Number of tests to run
$| = 1;
#print "1..$n\n";
#if ($n == 0) { exit 0; } else { $n = 1; }

my $junk_oid = ".1.3.6.1.2.1.1.1.1.1.1";
my $oid = '.1.3.6.1.2.1.1.1';
my $name = 'sysDescr';
my $junk_name = 'fooDescr';
my $mib_file = 't/mib.txt';
my $junk_mib_file = 'mib.txt';
my %access_list = ("ro" => "ReadOnly",
	    "rw" => "ReadWrite",
	    "na" => "NoAccess",
	    "wo" => "WriteOnly",
	    "n" => "Notify",
	    "c" => "Create");

my %status_list = ("m" => "Mandatory",
		   "op" => "Optional",
		   "ob" => "Obsolete",
		   "d" => "Deprecated",
		   "c" => "Current");

my %type_list = ("oid" => "OBJECTID",
		 "ostr" => "OCTETSTR",
		 "int" => "INTEGER",
		 "na" => "NETADDR",
		 "ip" => "IPADDR",
		 "c" => "COUNTER",
		 "g" => "GAUGE",
		 "tt" =>"TIMETICKS",
		 "op" =>"OPAQUE",
		 "ud" =>"undef");

my %syntax_list = ("ds" => "DisplayString",
		   "ts" => "TimeStamp",
		   "int" => "INTEGER",
		   "oid" => "OBJECT IDENTIFIER",
		   "c32" => "Counter32",
		   "c" => "COUNTER",
		   "ti" => "TestAndIncr",
		   "g" => "Gauge",
		   "pa" => "PhysAddress",
		   "tt" => "TimeTicks",
		   "na" => "NETADDR",
		   "ia" => "IPADDR");

#############################  1  ######################################
#check if 
my $res = $SNMP::MIB{sysDescr}{label};
#print("Label is:$res\n");
ok("sysDescr" eq $res);
#print("\n");
#############################  2  ######################################
$res =  $SNMP::MIB{sysDescr}{objectID};
#print("OID is: $res\n");
ok(defined($res));
#print("\n");
#############################  3  ######################################
$res =  $SNMP::MIB{sysDescr}{access};
#print("access is: $res\n");
ok($access_list{"ro"} eq $res);
#print("\n");
##############################  4  ###################################
$res =  $SNMP::MIB{sysLocation}{access};
#$res =  $SNMP::MIB{sysORIndex}{access};
#print("access is: $res\n");
ok($access_list{"rw"} eq "$res");
#print("\n");
##############################  5  ###################################
$res =  $SNMP::MIB{sysLocation}{type};
#print("type is: $res\n");
ok($type_list{"ostr"} eq $res);
#print("\n");
#############################  6  ####################################
$res =  $SNMP::MIB{sysLocation}{status};
#print("status is: $res\n");
ok($status_list{"c"} eq $res);
#print("\n");
#############################  7  #################################
$res =  $SNMP::MIB{sysORTable}{access};
#print("access is: $res\n");
ok($access_list{"na"} eq $res);
#print("\n");
#############################  8  ###############################
$res = $SNMP::MIB{sysLocation}{subID};
#print("subID is: $res\n");
ok(defined($res));
#print("\n");
############################  9  ##############################
$res = $SNMP::MIB{sysLocation}{syntax};
#print("syntax is: $res\n");
ok($syntax_list{"ds"} eq $res);
#print("\n");
############################  10  ###########################
$res = $SNMP::MIB{ipAdEntAddr}{syntax};
#print("syntax is: $res\n");
ok($syntax_list{"ia"} eq $res);
#print("\n");
##########################  11  ##########################

## *****************  WEIRD **************

$res = $SNMP::MIB{atNetAddress}{syntax};
#print("syntax is: $res\n");
ok($syntax_list{"ia"} eq $res);
#print("\n");
########################   12  ###############################
$res = $SNMP::MIB{ipReasmOKs}{syntax};
#print("syntax is: $res\n");
ok($syntax_list{"c"} eq $res);
#print("\n");
######################   13  ##############################
$res = $SNMP::MIB{sysDescr}{moduleID};
#print("Module ID is: $res\n");
ok(defined($res));
#print("\n");
######################  14   #########################
$des = $SNMP::MIB{atNetAddress}{description};
#print("des is --> $des\n");
ok(defined($des));
#print("\n");

######################  15   #########################
$res = $SNMP::MIB{atNetAddress}{nextNode};
#print("res is --> $res\n");
ok($res =~ /^HASH/);
#print("\n");

########################  16   #########################
$res = $SNMP::MIB{sysDescr}{children};
#print("res is --> $res\n");
ok($res =~ /^ARRAY/);
#print("\n");
####################  17   #########################
 
### ***************  SEE ***************

#$res = $SNMP::MIB{sysDes}{lalalala};
# the above was creating STORE problems. Should look into it.
$res = $SNMP::MIB{sysDescr}{lalalala};
#print("res is --> $res\n");
ok(!defined($res));
#print("\n");


######################  18   #########################
$res = $SNMP::MIB{sysDescr}{hint};
#print("res is --> $res\n");
ok($res =~ /^255a/);
#print("\n");
######################  19   #########################

$res = $SNMP::MIB{ifPhysAddress}{hint};
#print("res is --> $res\n");
ok($res =~ /^1x:/);
#print("\n");


######################  some translate tests  #######

#####################  20  #########################
# Garbage names return Undef.

my $type1 = SNMP::getType($junk_name);
ok(!defined($type1));
#printf "%s %d\n", (!defined($type1)) ? "ok" :"not ok", $n++;

######################################################################
# getType() supports numeric OIDs now

my $type2 = SNMP::getType($oid);
ok($type2 =~ /OCTETSTR/);
#printf "%s %d\n", ($type2 =~ /OCTETSTR/) ? "ok" :"not ok", $n++;

######################################################################
# This tests that sysDescr returns a valid type.

my $type3 = SNMP::getType($name);
ok(defined($type3));
#printf "%s %d\n", defined($type3) ? "ok" :"not ok", $n++;

######################################################################
# Translation tests from Name -> oid -> Name
######################################################################
# name -> OID
$oid_tag = SNMP::translateObj($name);
ok($oid eq $oid_tag);
#printf "%s %d\n", ($oid eq $oid_tag) ? "ok" :"not ok", $n++;

######################################################################
# bad name returns 'undef'

$oid_tag = '';
$oid_tag = SNMP::translateObj($junk_name);
ok(!defined($oid_tag));
#printf "%s %d\n", (!defined($oid_tag)) ? "ok" :"not ok", $n++;
######################################################################
# OID -> name

$name_tag = SNMP::translateObj($oid);
ok($name eq $name_tag);
#printf "%s %d\n", ($name eq $name_tag) ? "ok" :"not ok", $n++;

######################################################################
# bad OID -> Name

$name_tag = SNMP::translateObj($junk_oid);
ok($name ne $name_tag);
#printf "%s %d\n", ($name ne $name_tag) ? "ok" :"not ok", $n++;
