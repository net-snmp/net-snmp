##
## SNMPD perl initialization file.
##

use lib ("../perl/agent/blib/arch");
use lib ("../perl/agent/blib/lib");
use lib ("../perl/default_store/blib/arch");
use lib ("../perl/default_store/blib/lib");

use NetSNMP::agent;
$agent = new NetSNMP::agent('dont_init_agent' => 1,
			    'dont_init_lib' => 1);

print "***in perl " . ref($agent) . "\n";
