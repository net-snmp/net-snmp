#
# Warning: you may need more libraries than are included here on the
# build line.  The agent frequently needs various libraries in order
# to compile pieces of it, but is OS dependent and we can't list all
# the combinations here.  Instead, look at the libraries that were
# used when linking the snmpd master agent and copy those to this
# file.
#

CC=gcc

CFLAGS=-I/usr/local/include -g

OBJS1=snmpdemoapp.o
OBJS2=ustMain.o ustScalarSet.o
OBJS3=asyncapp.o
TARGETS=ustMain snmpdemoapp asyncapp

# if ucd-snmp was compiled with openssl support
CRYPTO=-L/usr/local/ssl/lib -lcrypto

# for Solaris
#SYSLIBS=-lsocket -lnsl -lkstat
# for BSD
#SYSLIBS=-lkvm
# for Linux and many other OSes
#SYSLIBS=-ldl

# shared library flags (assumes gcc)
DLFLAGS=-fPIC -shared

all: $(TARGETS)

snmpdemoapp: $(OBJS1)
	$(CC) -o snmpdemoapp $(OBJS1) -L/usr/local/lib -lsnmp $(SYSLIBS) $(CRYPTO)

asyncapp: $(OBJS3)
	$(CC) -o asyncapp $(OBJS3) -L/usr/local/lib -lsnmp $(SYSLIBS) $(CRYPTO)

ustMain: $(OBJS2)
	$(CC) -o ustMain $(OBJS2) -L/usr/local/lib -lucdagent -lucdmibs -lsnmp $(SYSLIBS) $(CRYPTO)

clean:
	rm $(OBJS2) $(OBJS2) $(TARGETS)

ustScalarSet.so: ustScalarSet.c Makefile
	$(CC) $(CFLAGS) $(DLFLAGS) -c -o ustScalarSet.o ustScalarSet.c
	$(CC) $(CFLAGS) $(DLFLAGS) -o ustScalarSet.so ustScalarSet.o
