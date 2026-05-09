# Build the entity AgentX subagent against the local net-snmp tree.
# Run from the top of the net-snmp source directory:
#   make -f entity_subagent.mk          # dynamically linked (default)
#   make -f entity_subagent.mk static   # statically linked, portable binary

SRCDIR  := $(shell pwd)

CFLAGS  := -g -Wall \
           -I$(SRCDIR)/include \
           -I$(SRCDIR) \
           -DHAVE_CONFIG_H

# Shared-library build flags
LDFLAGS_SHARED := \
    -L$(SRCDIR)/agent/.libs \
    -L$(SRCDIR)/snmplib/.libs \
    -lnetsnmpmibs \
    -lnetsnmpagent \
    -lnetsnmp \
    -Wl,-rpath,$(SRCDIR)/agent/.libs \
    -Wl,-rpath,$(SRCDIR)/snmplib/.libs \
    -lm -lssl -lcrypto -lpci -lnl-route-3 -lnl-3 -lsensors

# Static build: pull the net-snmp .a archives directly; everything else static too
LDFLAGS_STATIC := \
    -Wl,-Bstatic \
    $(SRCDIR)/agent/.libs/libnetsnmpmibs.a \
    $(SRCDIR)/agent/.libs/libnetsnmpagent.a \
    $(SRCDIR)/snmplib/.libs/libnetsnmp.a \
    -Wl,-Bdynamic \
    -lm -lssl -lcrypto -lpci -lnl-route-3 -lnl-3 -lsensors -lperl

# Object files from the already-built entity module
ENTITY_OBJS := \
    agent/mibgroup/hardware/entity/entity.o \
    agent/mibgroup/hardware/entity/entPhysicalTable.o \
    agent/mibgroup/hardware/entity/entAliasMappingTable.o \
    agent/mibgroup/hardware/entity/entLastChangeTime.o \
    agent/mibgroup/hardware/entity/entLogicalTable.o \
    agent/mibgroup/hardware/entity/data_access/entity_linux.o

entity_subagent: entity_subagent.o $(ENTITY_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS_SHARED)

static: entity_subagent.o $(ENTITY_OBJS)
	$(CC) -o entity_subagent $^ $(LDFLAGS_STATIC)

entity_subagent.o: entity_subagent.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f entity_subagent entity_subagent.o

.PHONY: clean static
