#!/usr/bin/perl

# HEADER Perl XS and module regression tests

use strict;
use warnings;
use IO::Socket::INET;
use NetSNMPTest;
use SNMP;
use NetSNMP::OID;
use NetSNMP::ASN (':all');
use NetSNMP::agent;
use Test;

my $srcdir = $ENV{'NETSNMP_SRC_DIR'} || $ENV{'srcdir'} || "..";
my $config_h = "$srcdir/include/net-snmp/net-snmp-config.h";
if (open(my $fh, '<', $config_h)) {
    while (<$fh>) {
        if (/#define NETSNMP_DISABLE_SET_SUPPORT 1/ ||
            /#define NETSNMP_NO_WRITE_SUPPORT 1/ ||
            /#define NETSNMP_DISABLE_SNMPV2C 1/) {
            print "1..0 # SKIP required SET or SNMPv2c support is disabled\n";
            exit 0;
        }
    }
    close($fh);
}

NetSNMPTest->require_feature("USING_MIBII_VACM_CONF_MODULE");
NetSNMPTest->require_feature("USING_MIBII_SYSTEM_MIB_MODULE");
NetSNMPTest->require_feature("USING_UTILITIES_OVERRIDE_MODULE");

plan(tests => 35);

# Set up test configuration directory and inline NetSNMP::agent first so that
# init_agent("snmpd") registers VACM config handlers before init_snmp() runs.
my $test = new NetSNMPTest(
    agentaddress => "udp:localhost:0",
    snmpdflags   => "-I-smux",
);
$test->config_agent("rwcommunity public");
$test->config_agent("smuxsocket 127.0.0.1:0");

my $probe_sock = IO::Socket::INET->new(
    Proto     => 'udp',
    LocalAddr => '127.0.0.1',
    LocalPort => 0,
);
my $inline_port = $probe_sock->sockport();
$probe_sock->close();

$ENV{'SNMPCONFPATH'} = $test->{'dir'};
$ENV{'SNMP_PERSISTENT_DIR'} = $test->{'persistentdir'};

my $inline_agent = new NetSNMP::agent(
    Name  => 'snmpd',
    Ports => "udp:127.0.0.1:$inline_port",
);
ok(defined($inline_agent));

$test->config_agent("sysContact initial_contact");
$test->config_agent("override .1.3.6.1.4.1.99999.1.0 integer 42");
$test->config_agent("override -rw .1.3.6.1.4.1.99999.2.0 ipaddress 127.0.0.1");

# ----------------------------------------------------------------------
# 1. NetSNMP::OID boundary and regression tests (perl/OID/OID.xs)
# ----------------------------------------------------------------------

# Test nsop_append (string) and nsop_append_oid (NetSNMP::OID) overflow checks
# MAX_OID_LEN is 128 sub-identifiers.
my $oid100 = new NetSNMP::OID(".1.3.6.1" . (".1" x 96));
ok(defined($oid100) && $oid100->length() == 100);

# Appending 30 sub-identifiers via string would exceed MAX_OID_LEN (130 > 128)
$oid100 += (".2" x 30);
ok($oid100->length(), 100);

# Appending 30 sub-identifiers via NetSNMP::OID would exceed MAX_OID_LEN (130 > 128)
my $oid30 = new NetSNMP::OID(".1.3" . (".2" x 28));
ok(defined($oid30) && $oid30->length() == 30);
$oid100 += $oid30;
ok($oid100->length(), 100);

# Appending invalid OID string should not modify the OID
$oid100 += ".__invalid_oid_suffix_xyz__";
ok($oid100->length(), 100);

# Appending exactly 28 sub-identifiers reaches MAX_OID_LEN (128)
my $oid28 = new NetSNMP::OID(".1.3" . (".2" x 26));
ok(defined($oid28) && $oid28->length() == 28);
$oid100 += $oid28;
ok($oid100->length(), 128);

# Appending 1 more sub-identifier at MAX_OID_LEN must be rejected
$oid100 += ".1";
ok($oid100->length(), 128);

# Test nsop_get_indexes: valid table instance vs bare column / non-table OID
my $if_inst_oid = new NetSNMP::OID("ifDescr.7");
my $idxs = $if_inst_oid->get_indexes();
ok(ref($idxs) eq 'ARRAY' && scalar(@$idxs) == 1 && $idxs->[0] == 7);

# Bare column OID has 0 index sub-identifiers (oid1->len == nodecount)
my $bare_col_oid = new NetSNMP::OID("ifDescr");
my $bare_idx = $bare_col_oid->get_indexes();
ok(!defined($bare_idx) || ref($bare_idx) ne 'ARRAY');

# Non-table scalar OID
my $scalar_oid = new NetSNMP::OID("sysDescr.0");
my $scalar_idx = $scalar_oid->get_indexes();
ok(!defined($scalar_idx) || ref($scalar_idx) ne 'ARRAY');

# Augmented table entry (ifXEntry AUGMENTS ifEntry)
my $aug_oid = new NetSNMP::OID("ifName.5");
my $aug_idxs = $aug_oid->get_indexes();
ok(ref($aug_idxs) eq 'ARRAY' && scalar(@$aug_idxs) == 1 && $aug_idxs->[0] == 5);

my $bare_aug_oid = new NetSNMP::OID("ifName");
my $bare_aug_idx = $bare_aug_oid->get_indexes();
ok(!defined($bare_aug_idx) || ref($bare_aug_idx) ne 'ARRAY');

# ----------------------------------------------------------------------
# 2. SNMP.xs & SNMP.pm regression tests against snmpd
# ----------------------------------------------------------------------

$test->DIE("failed to start the agent") if (!$test->start_agent());

my $sess = new SNMP::Session(
    DestHost  => $test->{'agentaddress'},
    Version   => '2c',
    Community => 'public',
);
ok(defined($sess));

# Test __snprint_value with UseEnums => 1 and TimeStamp => 1 (commits 58b4f656ed82, 2b8b6f62f0e3)
my $enum_ts_sess = new SNMP::Session(
    DestHost  => $test->{'agentaddress'},
    Version   => '2c',
    Community => 'public',
    UseEnums  => 1,
    TimeStamp => 1,
);
ok(defined($enum_ts_sess));

# Unmapped OID returning ASN_INTEGER with UseEnums => 1 and TimeStamp => 1
my $unmapped_vb = new SNMP::Varbind(['.1.3.6.1.4.1.99999.1', '0']);
my $val = $enum_ts_sess->get($unmapped_vb);
ok($val, 42);
# Verify VARBIND_TYPE_F (index 3) was NOT overwritten by TimeStamp, and VARBIND_TIME_F (index 4) is set
ok($unmapped_vb->[3], 'INTEGER');
ok(defined($unmapped_vb->[4]) && $unmapped_vb->[4] > 0);

# Also test getnext and getbulk with UseEnums => 1 and TimeStamp => 1 on the unmapped OID
my $gn_vb = new SNMP::Varbind(['.1.3.6.1.4.1.99999.1']);
my $gn_val = $enum_ts_sess->getnext($gn_vb);
ok($gn_val, 42);
ok($gn_vb->[3] eq 'INTEGER' && defined($gn_vb->[4]) && $gn_vb->[4] > 0);

my $gb_vb = new SNMP::Varbind(['.1.3.6.1.4.1.99999.1']);
my $gb_val = $enum_ts_sess->getbulk(0, 1, $gb_vb);
ok($gb_val, 42);

# Test oversized numeric OID (> 128 sub-identifiers) in __scan_num_objid / __tag2oid (commit 2dd4a049fcca)
my $huge_oid_str = ".1.3.6.1" . (".1" x 135);
ok(!defined(SNMP::_translate_obj($huge_oid_str, 0, 0, 1, 0, 0)));

# Oversized instance sub-identifier string in __tag2oid
my $huge_iid_vb = new SNMP::Varbind(['sysDescr', join('.', (1) x 135)]);
my $huge_iid_res = $sess->get($huge_iid_vb);
ok(!defined($huge_iid_res) && $sess->{ErrorNum} != 0);

# Oversized numeric OID in SNMP::getType (calls __tag2oid -> __scan_num_objid)
ok(!defined(SNMP::getType($huge_oid_str)));

# Test __add_var_val_str with TYPE_IPADDR and undef value (commit cea9c6406cc3)
my $null_ip_vb = new SNMP::Varbind(['.1.3.6.1.4.1.99999.2', '0', undef, 'IPADDR']);
eval {
    $sess->set($null_ip_vb);
};
ok($@ eq '');

# Test synchronous bulkwalk and error cleanup path in snmp_bulkwalk (commits f6603cb086df, b243bc6ef342)
my @bw_res = $sess->bulkwalk(1, 4, [['sysUpTime'], ['sysContact']]);
ok(scalar(@bw_res) == 2 && ref($bw_res[0]) eq 'SNMP::VarList' && $bw_res[1][0][2] eq 'initial_contact');

my $bw_err = $sess->bulkwalk(0, 4, [['__nonexistent_oid_tag_xyz__']]);
ok(ref($bw_err) eq 'ARRAY' && !defined($bw_err->[0]) && $sess->{ErrorNum} != 0);

# Test concurrent async bulkwalks (> 4 simultaneous contexts to trigger _context_add realloc)
# and async MainLoop timeout recalculation (commits b243bc6ef342, 41a0d16384b5)
my $async_done = 0;
my $target_contexts = 6;
for (my $i = 0; $i < $target_contexts; $i++) {
    my $req_id = $sess->bulkwalk(0, 4, [['sysContact']], [
        sub {
            my ($vlist) = @_;
            if (defined($vlist) && ref($vlist) eq 'ARRAY' &&
                $vlist->[0][0][2] eq 'initial_contact') {
                $async_done++;
            }
            if ($async_done >= $target_contexts) {
                SNMP::finish();
            }
        }
    ]);
    $test->DIE("async bulkwalk $i failed to start") if (!defined($req_id));
}
SNMP::MainLoop(5);
ok($async_done, $target_contexts);

# ----------------------------------------------------------------------
# 3. NetSNMP::agent regression tests (perl/agent/agent.xs)
# ----------------------------------------------------------------------

my $bad_int_res     = -1;
my $trail_int_res   = -1;
my $bad_uint_res    = -1;
my $bad_u64_res     = -1;
my $huge_oid_setres = -1;
my $good_int_res    = -1;
my $src_ip_str      = '';

my $reg = $inline_agent->register(
    "test_xs_reg",
    ".1.3.6.1.4.1.8072.9999",
    sub {
        my ($handler, $registration_info, $request_info, $requests) = @_;
        my $src_packed = $request_info->getSourceIp();
        if (defined($src_packed) && length($src_packed) == 4) {
            $src_ip_str = join('.', unpack('C4', $src_packed));
        }
        # Also exercise getDestIp() without requiring specific kernel socket options
        my $dst_packed = $request_info->getDestIp();

        for (my $request = $requests; $request; $request = $request->next()) {
            if ($request_info->getMode() == MODE_GET) {
                # Invalid numeric strings must return 0 (commit 10beaebf3cc9)
                $bad_int_res     = $request->setValue(ASN_INTEGER, "not_a_number");
                $trail_int_res   = $request->setValue(ASN_INTEGER, "123trailing");
                $bad_uint_res    = $request->setValue(ASN_UNSIGNED, "not_unsigned");
                $bad_u64_res     = $request->setValue(ASN_COUNTER64, "not_u64");
                $huge_oid_setres = $request->setValue(ASN_OBJECT_ID, $huge_oid_str);
                # Valid integer string must return 1
                $good_int_res    = $request->setValue(ASN_INTEGER, "777");
            }
        }
    }
);
ok(defined($reg));

my $inline_sess = new SNMP::Session(
    DestHost  => "udp:127.0.0.1:$inline_port",
    Version   => '2c',
    Community => 'public',
);
my $inline_got_val;
$inline_sess->get('.1.3.6.1.4.1.8072.9999.1.0', [
    sub {
        my ($vlist) = @_;
        if (defined($vlist) && ref($vlist) eq 'SNMP::VarList') {
            $inline_got_val = $vlist->[0][2];
        }
    }
]);

# Process incoming request on the inline agent and then the response on the session
for (my $step = 0; $step < 5 && !defined($inline_got_val); $step++) {
    $inline_agent->agent_check_and_process(1);
}

ok($src_ip_str, '127.0.0.1');
ok($bad_int_res == 0 && $trail_int_res == 0);
ok($bad_uint_res == 0 && $bad_u64_res == 0 && $huge_oid_setres == 0);
ok($good_int_res, 1);
ok($inline_got_val, 777);

$inline_agent->shutdown();
$test->stop_agent();
