package NetSNMP::agent;

use strict;
use Carp;

require Exporter;
require DynaLoader;
use AutoLoader;

use NetSNMP::default_store (':all');
use NetSNMP::agent::default_store (':all');
use NetSNMP::OID (':all');
use NetSNMP::agent::netsnmp_request_infoPtr;

use vars qw(@ISA %EXPORT_TAGS @EXPORT_OK @EXPORT $VERSION $AUTOLOAD);

@ISA = qw(Exporter AutoLoader DynaLoader);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use NetSNMP::agent ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
%EXPORT_TAGS = ( 'all' => [ qw(
	MODE_GET
	MODE_GETBULK
	MODE_GETNEXT
	MODE_SET_ACTION
	MODE_SET_BEGIN
	MODE_SET_COMMIT
	MODE_SET_FREE
	MODE_SET_RESERVE1
	MODE_SET_RESERVE2
	MODE_SET_UNDO
	SNMP_ERR_NOERROR
	SNMP_ERR_TOOBIG
	SNMP_ERR_NOSUCHNAME
	SNMP_ERR_BADVALUE
	SNMP_ERR_READONLY
	SNMP_ERR_GENERR
	SNMP_ERR_NOACCESS
	SNMP_ERR_WRONGTYPE
	SNMP_ERR_WRONGLENGTH
	SNMP_ERR_WRONGENCODING
	SNMP_ERR_WRONGVALUE
	SNMP_ERR_NOCREATION
	SNMP_ERR_INCONSISTENTVALUE
	SNMP_ERR_RESOURCEUNAVAILABLE
	SNMP_ERR_COMMITFAILED
	SNMP_ERR_UNDOFAILED
	SNMP_ERR_AUTHORIZATIONERROR
	SNMP_ERR_NOTWRITABLE
) ] );

@EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

@EXPORT = qw(
	MODE_GET
	MODE_GETBULK
	MODE_GETNEXT
	MODE_SET_ACTION
	MODE_SET_BEGIN
	MODE_SET_COMMIT
	MODE_SET_FREE
	MODE_SET_RESERVE1
	MODE_SET_RESERVE2
	MODE_SET_UNDO
	SNMP_ERR_NOERROR
	SNMP_ERR_TOOBIG
	SNMP_ERR_NOSUCHNAME
	SNMP_ERR_BADVALUE
	SNMP_ERR_READONLY
	SNMP_ERR_GENERR
	SNMP_ERR_NOACCESS
	SNMP_ERR_WRONGTYPE
	SNMP_ERR_WRONGLENGTH
	SNMP_ERR_WRONGENCODING
	SNMP_ERR_WRONGVALUE
	SNMP_ERR_NOCREATION
	SNMP_ERR_INCONSISTENTVALUE
	SNMP_ERR_RESOURCEUNAVAILABLE
	SNMP_ERR_COMMITFAILED
	SNMP_ERR_UNDOFAILED
	SNMP_ERR_AUTHORIZATIONERROR
	SNMP_ERR_NOTWRITABLE
);
$VERSION = '5.1';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.  If a constant is not found then control is passed
    # to the AUTOLOAD in AutoLoader.

    my $constname;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "& not defined" if $constname eq 'constant';
    my $val = constant($constname, @_ ? $_[0] : 0);
    if ($! != 0) {
	if ($! =~ /Invalid/ || $!{EINVAL}) {
	    $AutoLoader::AUTOLOAD = $AUTOLOAD;
	    goto &AutoLoader::AUTOLOAD;
	}
	else {
	    croak "Your vendor has not defined NetSNMP::agent macro $constname";
	}
    }
    {
	no strict 'refs';
	# Fixed between 5.005_53 and 5.005_61
#	if ($] >= 5.00561) {
#	    *$AUTOLOAD = sub () { $val };
#	}
#	else {
	    *$AUTOLOAD = sub { $val };
#	}
    }
    goto &$AUTOLOAD;
}

{
    my $haveinit = 0;

    sub mark_init_agent_done {
	$haveinit = 1;
    }

    sub maybe_init_agent {
	return if ($haveinit);
	$haveinit = 1;

	snmp_enable_stderrlog();
	my $flags = $_[0];
	if ($flags->{'AgentX'}) {
	    netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE, 1);
	}
	init_agent($flags->{'Name'} || "perl");
	if ($flags->{'Ports'}) {
	    netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_PORTS, $flags->{'Ports'});
	}
	init_mib();
    }
}

{
    my $haveinit = 0;

    sub mark_init_lib_done {
	$haveinit = 1;
    }

    sub maybe_init_lib {
	return if ($haveinit);
	$haveinit = 1;

	my $flags = $_[0];
	init_snmp($flags->{'Name'} || "perl");
	if (netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE) != 1) {
	    init_master_agent();
	}
    }
}

sub new {
    my $type = shift;
    my ($self);
    %$self = @_;
    bless($self, $type);
    if ($self->{'dont_init_agent'}) {
	$self->mark_init_agent_done();
    } else {
	$self->maybe_init_agent();
    }
    if ($self->{'dont_init_lib'}) {
	$self->mark_init_lib_done();
    }
    return $self;
}

sub register($$$$) {
    my ($self, $name, $oid, $sub) = @_;
    my $reg = NetSNMP::agent::netsnmp_handler_registration::new($name, $oid, $sub);
    $reg->register() if ($reg);
    return $reg;
}

sub main_loop {
    my $self = shift;
    while(1) {
	$self->agent_check_and_process(1);
    }
}

sub agent_check_and_process {
    my ($self, $blocking) = @_;
    $self->maybe_init_lib();
    __agent_check_and_process($blocking || 0);
}

bootstrap NetSNMP::agent $VERSION;

# Preloaded methods go here.

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is stub documentation for your module. You better edit it!

=head1 NAME

NetSNMP::agent - Perl extension for the net-snmp agent.

=head1 SYNOPSIS

  use NetSNMP::agent;

  my $agent = new NetSNMP::agent('Name' => 'my_agent_name');


=head1 DESCRIPTION

This module implements a snmp agent and/or can be embedded within the
net-snmp agent.

The agent may be registered as a sub-agent, or an embedded agent.

=head1 EXAMPLES

=head2 Sub-agent example

    	use NetSNMP::agent (':all');
	sub myhandler {
	    my ($handler, $registration_info, $request_info, $requests) = @_;
	    my $request;

	    for($request = $requests; $request; $request = $request->next()) {
		my $oid = $request->getOID();
		if ($request_info->getMode() == MODE_SET_ACTION) {
		    # ...
		    $request->setError($request_info, SNMP_ERR_NOTWRITABLE);
		}
	    }

	}

	my $agent = new NetSNMP::agent(
    				'Name' => "my_agent_name",
    				'AgentX' => 1
    				);
	}

    	$agent->register("my_agent_name", ".1.3.6.1.2.1", \&myhandler);

	my $running = 1;
	while($running) {
    		$agent->agent_check_and_process(1);
	}

	$agent->shutdown();


=head2 Embedded agent example

	use NetSNMP::agent;
	my $agent;

	sub myhandler {
	    my ($handler, $registration_info, $request_info, $requests) = @_;
	    # ...
	}

	$agent = new NetSNMP::agent(
    				'Name' => 'my_agent_name'
    				);

    	$agent->register("my_agent_name", ".1.3.6.1.2.1", \&myhandler);

	$agent->main_loop();


=head1 CONSTRUCTOR

    new ( OPTIONS )
	This is the constructor for a new NetSNMP::agent object.

    Possible options are:

    	Name	- Name of the agent (optional, defaults to "perl")
    	AgentX	- Make us a sub-agent (0 = false, 1 = true)
    	Ports	- Ports this agent will listen on (FIXME: example? format?)

    Example:

	$agent = new NetSNMP::agent(
    				 'Name' => 'my_agent_name',
    				 'AgentX' => 1
    				 );


=head1 METHODS

    register ( )
    	Registers the callback handler with given OID.

    	$agent->register();

	FIXME: how are errors returned?

    agent_check_and_process ( BLOCKING )
    	Run one iteration of the main loop.

    	BLOCKING - Blocking or non-blocking call. 1 = true, 0 = false.

    	$agent->agent_check_and_process(1);

    main_loop ()
    	Runs the agent in a loop. Does not return.

    shutdown ()
	Shuts down the sub-agent.

	$agent->shutdown();

    next ()
    	Returns the next request or undef if there is no next request.

    	$request = $request->next();

    getMode ()
    	Returns the mode of the request. See the MODES section for list of valid modes.

	$mode = $request->getMode();

    getOID ()
	Returns the oid of the request.

	$oid = $request->getOID();

    getRootOID ()
    	FIXME ???

    	$root_oid = $request->getRootOID();

    getOIDptr ()
    	FIXME ???

    	$oid_ptr = $request->getOIDptr();

    getDelegated ()
	FIXME ???

	$delegated = $request->getDelegated();

    getValue ()
	Returns the value of the request. Used for example when setting values.

    	$value = $request->getValue();

    	FIXME: how to get the type of the value? Is it even available?

    getProcessed ()
    	FIXME ???

    	$processed = $request->getProcessed();

    getStatus ()
	FIXME ???

	$status = $request->getStatus();

    getRepeat ()
	FIXME ???

    	$repeat = $request->getRepeat();

    setOid ( OID )
	Set the oid for request. Used for example when walking through list of OIDs.

	$request->setOID($next_oid);

    setProcessed ( PROCESSED )
	FIXME ???

	PROCESSED - 0 = false, 1 = true

	$request->setProcessed(1);

    setDelegated ( DELEGATED )
    	FIXME ???

    	DELEGATED - 0 = false, 1 = true

    	$request->setDelegated(1);

    setValue ( TYPE, DATA )
	Sets the data to be returned to the daemon.

    	Returns 1 on success, 0 on error.

    	TYPE - Type of the data. See NetSNMP::ASN for valid types.
    	DATA - The data to return.

	$ret = $request->setValue(ASN_OCTET_STR, "test");

    setRepeat ( REPEAT )
	FIXME ???

	REPEAT -  repeat count FIXME

	$request->setRepeat(5);

    setError ( REQUEST_INFO, ERROR_CODE )
	Sets the given error code for the request. See the ERROR CODES section for list of valid codes.

    	$request->setError($request_info, SNMP_ERR_NOTWRITABLE);

=head1 CALLBACKS

    handler ( HANDLER, REGISTRATION_INFO, REQUEST_INFO, REQUESTS )

    	The handler is called with the following parameters:

	HANDLER 		- FIXME
    	REGISTRATION_INFO 	- what are the correct meanings of these?
    	REQUEST_INFO		-
    	REQUESTS		-

    Example handler:

	sub myhandler {
	    my ($handler, $registration_info, $request_info, $requests) = @_;
	    # ...
	}


=head1 MODES

	MODE_GET
	MODE_GETBULK
	MODE_GETNEXT
	MODE_SET_ACTION
	MODE_SET_BEGIN
	MODE_SET_COMMIT
	MODE_SET_FREE
	MODE_SET_RESERVE1
	MODE_SET_RESERVE2
	MODE_SET_UNDO

=head1 ERROR CODES

	SNMP_ERR_NOERROR
	SNMP_ERR_TOOBIG
	SNMP_ERR_NOSUCHNAME
	SNMP_ERR_BADVALUE
	SNMP_ERR_READONLY
	SNMP_ERR_GENERR
	SNMP_ERR_NOACCESS
	SNMP_ERR_WRONGTYPE
	SNMP_ERR_WRONGLENGTH
	SNMP_ERR_WRONGENCODING
	SNMP_ERR_WRONGVALUE
	SNMP_ERR_NOCREATION
	SNMP_ERR_INCONSISTENTVALUE
	SNMP_ERR_RESOURCEUNAVAILABLE
	SNMP_ERR_COMMITFAILED
	SNMP_ERR_UNDOFAILED
	SNMP_ERR_AUTHORIZATIONERROR
	SNMP_ERR_NOTWRITABLE

=head1 AUTHOR

Please mail the net-snmp-users@lists.sourceforge.net mailing list for
help, questions or comments about this module.

Module written by Wes Hardaker <hardaker@users.sourceforge.net>

Documentation written by Toni Willberg <toniw@iki.fi>

=head1 SEE ALSO

NetSNMP::OID(3), NetSNMP::ASN(3), perl(1).

=cut
