# uses kstat on solaris for get_uptime
$self->{LIBS} .= ' -lkstat -lgen -lcrypto -lkvm -ldb -lm -lelf
 -lnsl -lsocket';
