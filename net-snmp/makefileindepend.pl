#!/usr/bin/perl

# Move dependencies from the Makefile to the Makefile.in file, saving
# a backup in Makefile.in.bak.

rename("Makefile.in","Makefile.in.bak");
open(F,"Makefile.in.bak");
open(G,"Makefile");
open(O,">Makefile.in"); 
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
