package NetSNMP::default_store;

require 5.005_62;
use strict;
use warnings;
use Carp;

require Exporter;
require DynaLoader;
use AutoLoader;

our @ISA = qw(Exporter DynaLoader);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use NetSNMP::default_store ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	DEFAULT_STORE_H
	DS_APPLICATION_ID
	DS_LIBRARY_ID
	DS_LIB_ALARM_DONT_USE_SIG
	DS_LIB_APPTYPE
	DS_LIB_AUTHPASSPHRASE
	DS_LIB_COMMUNITY
	DS_LIB_CONFIGURATION_DIR
	DS_LIB_CONTEXT
	DS_LIB_DEFAULT_PORT
	DS_LIB_DONT_BREAKDOWN_OIDS
	DS_LIB_DONT_CHECK_RANGE
	DS_LIB_DONT_READ_CONFIGS
	DS_LIB_DUMP_PACKET
	DS_LIB_ESCAPE_QUOTES
	DS_LIB_EXTENDED_INDEX
	DS_LIB_LOG_TIMESTAMP
	DS_LIB_MIB_COMMENT_TERM
	DS_LIB_MIB_ERRORS
	DS_LIB_MIB_PARSE_LABEL
	DS_LIB_MIB_REPLACE
	DS_LIB_MIB_WARNINGS
	DS_LIB_NO_TOKEN_WARNINGS
	DS_LIB_NUMERIC_TIMETICKS
	DS_LIB_OPTIONALCONFIG
	DS_LIB_PASSPHRASE
	DS_LIB_PERSISTENT_DIR
	DS_LIB_PRINT_BARE_VALUE
	DS_LIB_PRINT_FULL_OID
	DS_LIB_PRINT_HEX_TEXT
	DS_LIB_PRINT_NUMERIC_ENUM
	DS_LIB_PRINT_NUMERIC_OIDS
	DS_LIB_PRINT_SUFFIX_ONLY
	DS_LIB_PRIVPASSPHRASE
	DS_LIB_QUICK_PRINT
	DS_LIB_RANDOM_ACCESS
	DS_LIB_REGEX_ACCESS
	DS_LIB_REVERSE_ENCODE
	DS_LIB_SAVE_MIB_DESCRS
	DS_LIB_SECLEVEL
	DS_LIB_SECMODEL
	DS_LIB_SECNAME
	DS_LIB_SNMPVERSION
	DS_MAX_IDS
	DS_MAX_SUBIDS
	DS_TOKEN_ID
	ds_get_boolean
	ds_get_int
	ds_get_string
	ds_get_void
	ds_register_config
	ds_register_premib
	ds_set_boolean
	ds_set_int
	ds_set_string
	ds_set_void
	ds_shutdown
	ds_toggle_boolean
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	DEFAULT_STORE_H
	DS_APPLICATION_ID
	DS_LIBRARY_ID
	DS_LIB_ALARM_DONT_USE_SIG
	DS_LIB_APPTYPE
	DS_LIB_AUTHPASSPHRASE
	DS_LIB_COMMUNITY
	DS_LIB_CONFIGURATION_DIR
	DS_LIB_CONTEXT
	DS_LIB_DEFAULT_PORT
	DS_LIB_DONT_BREAKDOWN_OIDS
	DS_LIB_DONT_CHECK_RANGE
	DS_LIB_DONT_READ_CONFIGS
	DS_LIB_DUMP_PACKET
	DS_LIB_ESCAPE_QUOTES
	DS_LIB_EXTENDED_INDEX
	DS_LIB_LOG_TIMESTAMP
	DS_LIB_MIB_COMMENT_TERM
	DS_LIB_MIB_ERRORS
	DS_LIB_MIB_PARSE_LABEL
	DS_LIB_MIB_REPLACE
	DS_LIB_MIB_WARNINGS
	DS_LIB_NO_TOKEN_WARNINGS
	DS_LIB_NUMERIC_TIMETICKS
	DS_LIB_OPTIONALCONFIG
	DS_LIB_PASSPHRASE
	DS_LIB_PERSISTENT_DIR
	DS_LIB_PRINT_BARE_VALUE
	DS_LIB_PRINT_FULL_OID
	DS_LIB_PRINT_HEX_TEXT
	DS_LIB_PRINT_NUMERIC_ENUM
	DS_LIB_PRINT_NUMERIC_OIDS
	DS_LIB_PRINT_SUFFIX_ONLY
	DS_LIB_PRIVPASSPHRASE
	DS_LIB_QUICK_PRINT
	DS_LIB_RANDOM_ACCESS
	DS_LIB_REGEX_ACCESS
	DS_LIB_REVERSE_ENCODE
	DS_LIB_SAVE_MIB_DESCRS
	DS_LIB_SECLEVEL
	DS_LIB_SECMODEL
	DS_LIB_SECNAME
	DS_LIB_SNMPVERSION
	DS_MAX_IDS
	DS_MAX_SUBIDS
	DS_TOKEN_ID
);
our $VERSION = '0.01';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.  If a constant is not found then control is passed
    # to the AUTOLOAD in AutoLoader.

    my $constname;
    our $AUTOLOAD;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "& not defined" if $constname eq 'constant';
    my $val = constant($constname, @_ ? $_[0] : 0);
    if ($! != 0) {
	if ($! =~ /Invalid/ || $!{EINVAL}) {
	    $AutoLoader::AUTOLOAD = $AUTOLOAD;
	    goto &AutoLoader::AUTOLOAD;
	}
	else {
	    croak "Your vendor has not defined NetSNMP::default_store macro $constname";
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

bootstrap NetSNMP::default_store $VERSION;

# Preloaded methods go here.

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is stub documentation for your module. You better edit it!

=head1 NAME

NetSNMP::default_store - Perl extension for blah blah blah

=head1 SYNOPSIS

  use NetSNMP::default_store;
  $port = ds_get_int(DS_LIBRARY_ID, DS_LIB_DEFAULT_PORT);
  ds_set_int(DS_LIBRARY_ID, DS_LIB_DEFAULT_PORT, 161);

=head1 DESCRIPTION

This module is a wrapper around the net-snmp default store routines.
See the net-snmp default_store manual page for details on what the
various functions do and the values that can be set/retrieved.

=head2 EXPORT

None by default.

=head2 Exportable constants

  DEFAULT_STORE_H
  DS_APPLICATION_ID
  DS_LIBRARY_ID
  DS_LIB_ALARM_DONT_USE_SIG
  DS_LIB_APPTYPE
  DS_LIB_AUTHPASSPHRASE
  DS_LIB_COMMUNITY
  DS_LIB_CONFIGURATION_DIR
  DS_LIB_CONTEXT
  DS_LIB_DEFAULT_PORT
  DS_LIB_DONT_BREAKDOWN_OIDS
  DS_LIB_DONT_CHECK_RANGE
  DS_LIB_DONT_READ_CONFIGS
  DS_LIB_DUMP_PACKET
  DS_LIB_ESCAPE_QUOTES
  DS_LIB_EXTENDED_INDEX
  DS_LIB_LOG_TIMESTAMP
  DS_LIB_MIB_COMMENT_TERM
  DS_LIB_MIB_ERRORS
  DS_LIB_MIB_PARSE_LABEL
  DS_LIB_MIB_REPLACE
  DS_LIB_MIB_WARNINGS
  DS_LIB_NO_TOKEN_WARNINGS
  DS_LIB_NUMERIC_TIMETICKS
  DS_LIB_OPTIONALCONFIG
  DS_LIB_PASSPHRASE
  DS_LIB_PERSISTENT_DIR
  DS_LIB_PRINT_BARE_VALUE
  DS_LIB_PRINT_FULL_OID
  DS_LIB_PRINT_HEX_TEXT
  DS_LIB_PRINT_NUMERIC_ENUM
  DS_LIB_PRINT_NUMERIC_OIDS
  DS_LIB_PRINT_SUFFIX_ONLY
  DS_LIB_PRIVPASSPHRASE
  DS_LIB_QUICK_PRINT
  DS_LIB_RANDOM_ACCESS
  DS_LIB_REGEX_ACCESS
  DS_LIB_REVERSE_ENCODE
  DS_LIB_SAVE_MIB_DESCRS
  DS_LIB_SECLEVEL
  DS_LIB_SECMODEL
  DS_LIB_SECNAME
  DS_LIB_SNMPVERSION
  DS_MAX_IDS
  DS_MAX_SUBIDS
  DS_TOKEN_ID

=head2 Exportable functions

  int ds_get_boolean(int storeid, int which)
  int ds_get_int(int storeid, int which)
  char *ds_get_string(int storeid, int which)
  void *ds_get_void(int storeid, int which)
  int ds_register_config(unsigned char type, const char *ftype, const char *token,
                       int storeid, int which)
  int ds_register_premib(unsigned char type, const char *ftype, const char *token,
                       int storeid, int which)
  int ds_set_boolean(int storeid, int which, int value)
  int ds_set_int(int storeid, int which, int value)
  int ds_set_string(int storeid, int which, const char *value)
  int ds_set_void(int storeid, int which, void *value)
  void ds_shutdown(void)
  int ds_toggle_boolean(int storeid, int which)

=head1 AUTHOR

Wes Hardaker, hardaker@users.sourceforge.net

=head1 SEE ALSO

perl(1), default_store(3).

=cut
