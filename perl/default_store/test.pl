# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..10\n"; }
END {print "not ok 1\n" unless $loaded;}
use NetSNMP::default_store (':all');
$loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

print ((ds_set_string(1, 1, "hi there") == 0) ? "ok 2\n" : "not ok 2\n"); 
print ((ds_get_string(1, 1) eq "hi there") ? "ok 3\n" : "not ok 3\n"); 
print ((ds_set_int(1, 1, 42) == 0) ? "ok 4\n" : "not ok 4\n"); 
print ((ds_get_int(1, 1) == 42) ? "ok 5\n" : "not ok 5\n"); 
print ((ds_get_int(1, 2) == 0) ? "ok 6\n" : "not ok 6\n"); 
print ((DS_LIB_REGEX_ACCESS == 15) ? "ok 7\n" : "not ok 7\n"); 
print ((ds_get_int(DS_APPLICATION_ID, 1) == 42) ? "ok 8\n" : "not ok 8\n"); 
print ((ds_set_int(DS_LIBRARY_ID, DS_LIB_DEFAULT_PORT, 9161) == 0) ? "ok 9\n" : "not ok 9\n"); 
print ((ds_get_int(DS_LIBRARY_ID, DS_LIB_DEFAULT_PORT) == 9161) ? "ok 10\n" : "not ok 10\n"); 
