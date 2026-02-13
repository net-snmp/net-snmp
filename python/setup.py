from setuptools import setup, Extension, find_packages
import os
import re
import sys

intree=0
basedir = ""
defines = []

args = sys.argv[:]
for arg in args:
    if arg.find('--basedir=') == 0:
        basedir = arg.split('=')[1] + '/'
        sys.argv.remove(arg)
        intree=1

netsnmp_libs = os.popen(basedir + 'net-snmp-config --libs').read()
base_cflags = os.popen(basedir + 'net-snmp-config --base-cflags').read()
for opt in base_cflags.split(' '):
    if opt[0:2] == "-D":
        e = opt[2:].split('=')
        if e[0] != "linux":
            if len(e) == 1:
                defines += [(e[0], 1)]
            else:
                defines += [(e[0], e[1])]

if intree:
    libdir = os.popen(basedir + 'net-snmp-config --build-lib-dirs ' + basedir).read()
    libdir += " "
    libdir += os.popen(basedir + 'net-snmp-config --ldflags').read()
    incdir = os.popen(basedir + 'net-snmp-config --build-includes ' + basedir).read()
    incdir += " "
    incdir += os.popen(basedir + 'net-snmp-config --base-cflags ').read()
    libs = re.findall(r"(?:^|\s+)-l(\S+)", netsnmp_libs)
    libdirs = re.findall(r"(?:^|\s+)-L(\S+)", libdir)
    incdirs = re.findall(r"(?:^|\s+)-I(\S+)", incdir)
else:
    libdirs = re.findall(r"(?:^|\s+)-L(\S+)", netsnmp_libs)
    incdirs = []
    libs = re.findall(r"(?:^|\s+)-l(\S+)", netsnmp_libs)

setup(
    ext_modules = [
       Extension("netsnmp.client_intf", ["netsnmp/client_intf.c"],
                 define_macros=defines,
                 library_dirs=libdirs,
                 include_dirs=incdirs,
                 libraries=libs )
       ]
    )
