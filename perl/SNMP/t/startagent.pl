
$agent_host = 'localhost';
$agent_port = 7000;
$trap_port = 8000;
$comm = 'v1_private';
$comm2 = 'v2_private';
$comm3 = 'v3_private';
local $snmpd_cmd;
local $snmptrapd_cmd;
my $line;

sub snmptest_cleanup {
    sleep 1; # strangely we need to wait for pid files to appear ??
    if ((-e "t/snmpd.pid") && (-r "t/snmpd.pid")) {
        # Making sure that any running agents are killed.
	# warn "killing snmpd:", `cat t/snmpd.pid`, "\n";
	system "kill `cat t/snmpd.pid` > /dev/null 2>&1";
	unlink "t/snmpd.pid";
    }
    if ((-e "t/snmptrapd.pid") && (-r "t/snmptrapd.pid")) {
        # Making sure that any running agents are killed.
	# warn "killing snmptrap:", `cat t/snmptrapd.pid`, "\n";
	system "kill `cat t/snmptrapd.pid` > /dev/null 2>&1";
	unlink "t/snmptrapd.pid";
    }
}
snmptest_cleanup();
#Open the snmptest.cmd file and get the info
if ($^O =~ /win32/i) {
# get the host, agent_port and trap-port.
    if (open(CMD, "<t/snmptest.cmd")) {
	while ($line = <CMD>) {
            if ($line =~ /HOST => \d+\.\d+\.\d+\.\d+/) {
# host is of IP address form
		($agent_host) = ($line =~ /HOST => (\d+\.\d+\.\d+\.\d+)\s*/);
		print("host is: $agent_host\n");
	    } elsif ($line =~ /HOST => \w+\s*/) {
		($agent_host) = ($line =~ /HOST => (\w+)\s*/);
	    } elsif ($line =~ /AGENT/) {
		($agent_port) = ($line =~ /AGENT_PORT => (\d+)\s*/);
	    } elsif ($line =~ /TRAP/) {
		($trap_port) = ($line =~ /TRAP_PORT => (\d+)\s*/);
	    }
	} # end of while
	close CMD;
    } else {
	die ("Could not start agent. Couldn't find snmptest.cmd file\n");
    }

} else {
    open(CMD,"<t/snmptest.cmd")
	|| warn("could not open snmptest.cmd, will not be able run tests");
    while(<CMD>) {
	if (($snmpd_cmd) = (/SNMPD => (\S+)\s*/)) {
	    if (-r $snmpd_cmd and -x $snmpd_cmd) {
		system "$snmpd_cmd -r -l t/snmptest.log -C -c t/snmptest.conf -p $agent_port -P t/snmpd.pid > /dev/null 2>&1";
		# warn "started snmpd:", `cat t/snmpd.pid`, "\n";

	    } else {
		warn("Couldn't run snmpd\n");
	    }
	} elsif (($snmptrapd_cmd) = (/SNMPTRAPD => (\S+)\s*/)) {
	    if (-r $snmptrapd_cmd and -x $snmptrapd_cmd) {
		system "$snmptrapd_cmd -p $trap_port -u t/snmptrapd.pid -c t/snmptest.conf -C > /dev/null 2>&1";
		# warn "started snmptrapd:", `cat t/snmptrapd.pid`, "\n";
	    } else {
		warn("Couldn't run snmptrapd\n");
	    }
	}
    }
    close CMD;
} #end of else

1;

