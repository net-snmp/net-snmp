#!/usr/bin/perl

# hack: strip include dependancies that are probably not in our source tree.

if (/^\# DO NOT DELETE THIS LINE/) {
    $doit=1;
}

if ($doit == 1) {
    s#/usr/(include|lib|local)/[\S]+##g;
    print if (! /^[^:]+\.lo:\s*$/);
} else {
    print;
}
