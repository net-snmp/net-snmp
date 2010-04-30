#!/usr/bin/perl

system("rm -rf ~/.snmp/tls");
system("rm -rf /tmp/.snmp");

system("cp ~/Projects/SNMP-DTLS/trunk/net-snmp/local/net-snmp-cert /home/gmarzot/bin");

$str = "\ngenca (in -C /tmp/.snmp) : ca-snmp\n\n";
print("$str");
die("$str\n") if system("net-snmp-cert genca -C /tmp/.snmp --cn ca-snmp --email ca\@ca.com --host host.a.b.com  --san DNS:ca.a.b.com --san EMAIL:ca\@ca.com");

$str = "\ngenca: ca-snmp\n\n";
print("$str");
die("$str\n") if system("net-snmp-cert genca --cn ca-snmp --email ca\@ca.com --host host.a.b.com  --san DNS:ca.a.b.com --san EMAIL:ca\@ca.com");

$str = "\ngenca: ca-snmp-2 (signed w/ ca-snmp)\n\n";
print("$str");
die("$str\n") if system("net-snmp-cert genca --ca ca-snmp --cn ca-snmp-2 --email ca2\@ca.com --host host2.a.b.com  --san DNS:ca2.a.b.com --san EMAIL:ca2\@ca.com");

$str = "\ngencsr: snmpapp\n\n";
print("$str");
die("$str\n") if system("net-snmp-cert gencsr -t snmpapp --cn 'admin' --email admin@net-snmp.org --host admin-host.net-snmp.org  --san EMAIL:a\@b.com --san IP:1.2.3.4 --san DNS:admin.a.b.org");

$str = "\nsigncsr: snmpapp w/ca-snmp\n\n";
print("$str");
die("$str\n") if system("net-snmp-cert signcsr --ca ca-snmp --csr snmpapp  --install");

$str = "\nsigncsr: snmpapp w/ca-snmp-2\n\n";
print("$str");
die("$str\n") if system("net-snmp-cert signcsr --ca ca-snmp-2 --csr snmpapp --san EMAIL:noinstall\@b.com --san IP:5.6.7.8");

$str = "\ngencert: snmptrapd (self-signed)\n\n";
print("$str");
die("$str\n") if system("net-snmp-cert gencert -t snmptrapd --cn 'NOC' --email 'noc\@net-snmp.org' --host noc-host.net-snmp.org  --san DNS:noc.a.b.org --san 'EMAIL:noc\@net-snmp.org'");

$str = "\ngencert: snmpd (signed w/ ca-snmp-2)\n\n";
print("$str");
die("$str\n") if system("net-snmp-cert gencert -t snmpd --ca ca-snmp-2 --email snmpd\@net-snmp.org --host snmpd-host.net-snmp.org  --san DNS:snmpd.a.b.org --san EMAIL:snmpd\@net-snmp.org");

$str = "\nshow CAs\n\n";
print("$str");
die("$str\n") if system("net-snmp-cert showca --issuer --subject");

$str = "show Certs\n\n";
print("$str");
die("$str\n") if system("net-snmp-cert showcert --issuer --subject");
