#!/usr/bin/perl

# HEADER Perl TLS/TCP Test

$agentaddress = "tlstcp:127.0.0.1:0";
$feature = "NETSNMP_TRANSPORT_TLSTCP_DOMAIN";

do "$ENV{'srcdir'}/testing/fulltests/tls/S300tlsperl.pl";
