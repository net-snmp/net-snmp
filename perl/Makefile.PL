use ExtUtils::MakeMaker;
use Config;
use Getopt::Long;
require 5;

%MakeParams = InitMakeParams();

WriteMakefile(%MakeParams);

sub InitMakeParams {
    $nsconfig="net-snmp-config"; # in path by default
    my %Params = (
		  'NAME' => 'Bundle::NetSNMP',
		  'DIR' => [qw(default_store SNMP ASN OID agent)]
		  );
    # bogus, but these options need to be passed to the lower levels
    GetOptions("NET-SNMP-CONFIG=s" => \$nsconfig,
	       "NET-SNMP-IN-SOURCE=s" => \$insource);

    return(%Params);
}
