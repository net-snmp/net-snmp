#!/usr/bin/perl

# Move dependencies from the Makefile to the Makefile.in file, saving
# a backup in Makefile.depend.bak.

rename("Makefile.depend","Makefile.depend.bak");
open(F,"Makefile.depend.bak");
open(G,"Makefile");
open(O,">Makefile.depend"); 
$_ = <F>;
while(!/^\# DO NOT DELETE THIS LINE/) { 
    print O $_; 
    $_ = <F>; 
}
print O $_;
$_ = <G>; 
while(!/^\# DO NOT DELETE THIS LINE/) { 
    $_ = <G>; 
} 

while (<G>) {
    next if (/:\s*$/);
    s/\.o:/.lo:/;
    print O $_;
} 
