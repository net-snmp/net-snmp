#
# Warning: you may need more libraries than are included here on the
# build line.  The agent frequently needs various libraries in order
# to compile pieces of it, but is OS dependent and we can't list all
# the combinations here.  Instead, look at the libraries that were
# used when linking the snmpd master agent and copy those to this
# file.
#

CFLAGS=-I/usr/local/include -g

OBJS1=snmpdemoapp.o
OBJS2=ustMain.o ustScalarSet.o
OBJS3=asyncapp.o
TARGETS=ustMain snmpdemoapp asyncdemo
# for Solaris
#SYSLIBS=-lsocket -lnsl -lkstat
# for BSD
#SYSLIBS=-lkvm

all: $(TARGETS)

snmpdemoapp: $(OBJS1)
	cc -o snmpdemoapp $(OBJS1) -lsnmp $(SYSLIBS)

asyncapp: $(OBJS3)
	cc -o asyncapp $(OBJS3) -lsnmp $(SYSLIBS)

ustMain: $(OBJS2)
	cc -o ustMain $(OBJS2) -lucdagent -lucdmibs -lsnmp $(SYSLIBS)

clean:
	rm $(OBJS2) $(OBJS2) $(TARGETS)
