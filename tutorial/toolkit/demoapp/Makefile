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
TARGETS=ustMain snmpdemoapp

all: $(TARGETS)

snmpdemoapp: $(OBJS1)
	cc -o snmpdemoapp $(OBJS1) -lsnmp

ustMain: $(OBJS2)
	cc -o ustMain $(OBJS2) -lsnmp -lucdagent -lucdmibs

clean:
	rm $(OBJS2) $(OBJS2) $(TARGETS)
