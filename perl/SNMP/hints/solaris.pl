# uses kstat on solaris for get_uptime
$self->{LIBS} .= ' -lkstat';
