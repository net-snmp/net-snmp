#!./perl

use strict;
use warnings;
use Exporter;

our @ISA = 'Exporter';
our @EXPORT_OK = qw($agent_host $agent_port $mibdir $snmpd_cmd $snmptrapd_cmd);
our ($agent_host, $agent_port, $mibdir, $snmpd_cmd, $snmptrapd_cmd);

if (open(CMD, "<../SNMP/t/snmptest.cmd")) {
  while (my $line = <CMD>) {
    if ($line =~ /HOST\s*=>\s*(.*?)\s+$/) {
      $agent_host = $1;
    } elsif ($line =~ /MIBDIR\s*=>\s*(.*?)\s+$/) {
      $mibdir = $1;
    } elsif ($line =~ /AGENT_PORT\s*=>\s*(.*?)\s+$/) {
      $agent_port = $1;
    } elsif ($line =~ /SNMPD\s*=>\s*(.*?)\s+$/) {
      $snmpd_cmd = $1;
    } elsif ($line =~ /SNMPTRAPD\s*=>\s*(.*?)\s+$/) {
      $snmptrapd_cmd = $1;
    }
  } # end of while
  close CMD;
} else {
  die ("Could not start agent. Couldn't find snmptest.cmd file\n");
}
