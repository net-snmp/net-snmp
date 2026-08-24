#!/usr/bin/perl

# HEADER Perl DTLS/UDP Test

$agentaddress = "dtlsudp:127.0.0.1:0";
$feature = "NETSNMP_TRANSPORT_DTLSUDP_DOMAIN";

do "$ENV{'srcdir'}/testing/fulltests/tls/S300tlsperl.pl";
