#
# Warning: you may need more libraries than are included here on the
# build line.  The agent frequently needs various libraries in order
# to compile pieces of it, but is OS dependent and we can't list all
# the combinations here.  Instead, look at the libraries that were
# used when linking the snmpd master agent and copy those to this
# file.
#

CC=gcc

OBJS1=snmpdemoapp.o
OBJS2=ustMain.o XXX.o
OBJS3=asyncapp.o
TARGETS=ustMain snmpdemoapp asyncapp

CFLAGS=`net-snmp-config --cflags`
BUILDLIBS=`net-snmp-config --libs`
BUILDAGENTLIBS=`net-snmp-config --agent-libs`

# shared library flags (assumes gcc)
DLFLAGS=-fPIC -shared

all: $(TARGETS)

snmpdemoapp: $(OBJS1)
	$(CC) -o snmpdemoapp $(OBJS1) $(BUILDLIBS)

asyncapp: $(OBJS3)
	$(CC) -o asyncapp $(OBJS3) $(BUILDLIBS)

ustMain: $(OBJS2)
	$(CC) -o ustMain $(OBJS2)  $(BUILDAGENTLIBS)

clean:
	rm $(OBJS2) $(OBJS2) $(TARGETS)

ustScalarSet.so: ustScalarSet.c Makefile
	$(CC) $(CFLAGS) $(DLFLAGS) -c -o ustScalarSet.o ustScalarSet.c
	$(CC) $(CFLAGS) $(DLFLAGS) -o ustScalarSet.so ustScalarSet.o
