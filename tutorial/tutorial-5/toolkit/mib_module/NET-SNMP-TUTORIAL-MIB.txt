NET-SNMP-TUTORIAL-MIB DEFINITIONS ::= BEGIN

-- A Comment!

-- IMPORTS: Include definitions from other mibs here, which is always
-- the first item in a MIB file.
IMPORTS
	netSnmpExamples		              FROM NET-SNMP-EXAMPLES-MIB
	OBJECT-TYPE, Integer32,
	MODULE-IDENTITY                       FROM SNMPv2-SMI
	MODULE-COMPLIANCE, OBJECT-GROUP       FROM SNMPv2-CONF;

--
-- A brief description and update information about this mib.
--
netSnmpTutorialMIB MODULE-IDENTITY
    LAST-UPDATED "200205290000Z"            -- 29 May 2002, midnight
    ORGANIZATION "net-snmp"
    CONTACT-INFO "postal:   Wes Hardaker
                            P.O. Box 382
                            Davis CA  95617

		  email:    net-snmp-coders@lists.sourceforge.net
                 "
    DESCRIPTION  "A simple mib for demonstration purposes.
                 "
    ::= { netSnmpExamples 4 }

-- Define typical mib nodes, like where the objects are going to lie.
-- we'll prefix everything in this mib with nst (net snmp tutorial)
nstMIBObjects     OBJECT IDENTIFIER ::= { netSnmpTutorialMIB 1 }
nstMIBConformance OBJECT IDENTIFIER ::= { netSnmpTutorialMIB 2 }


-- define 3 objects, which will all be implemented in different ways
-- within the tutorial.

nstAgentModules   OBJECT IDENTIFIER ::= { nstMIBObjects 1 }


nstAgentModuleObject OBJECT-TYPE
    SYNTAX      Integer32
    MAX-ACCESS  read-write
    STATUS      current
    DESCRIPTION
	"This is an object that simply supports a writable integer
	 when compiled into the agent.  See
	 http://www.net-snmp.org/tutorial-5/toolkit/XXX for further
	 implementation details."
    DEFVAL { 1 }
    ::= { nstAgentModules 1 }

nstAgentSubagentObject OBJECT-TYPE
    SYNTAX      Integer32
    MAX-ACCESS  read-write
    STATUS      current
    DESCRIPTION
	"This is an object that simply supports a writable integer
	 when attached to the agent.  The object should be accessible
	 when the agentx subagent containing this object is attached.
	 See http://www.net-snmp.org/tutorial-5/toolkit/XXX for
	 further implementation details."
    DEFVAL { 2 }
    ::= { nstAgentModules 2 }

nstAgentPluginObject OBJECT-TYPE
    SYNTAX      Integer32
    MAX-ACCESS  read-write
    STATUS      current
    DESCRIPTION
	"This is an object that simply supports a writable integer
	 when attached to the agent.  This object should be accessible
	 when the dynamic plugin has been loaded into the agent.  See
	 http://www.net-snmp.org/tutorial-5/toolkit/XXX for further
	 implementation details."
    DEFVAL { 3 }
    ::= { nstAgentModules 3 }

--
-- The above definitions produce a section of the mib tree that looks
-- like this (including our parent node, printed using the
-- snmptranslate command):
--
--
-- % snmptranslate -M+. -mNET-SNMP-TUTORIAL-MIB -Tp -IR netSnmpTutorialMIB
-- +-netSnmpTutorialMIB(4)
--   |
--   +-nstMIBObjects(1)
--   | |
--   | +-nstAgentModules(1)
--   |   |
--   |   +- -RW- Integer32 nstAgentModuleObject(1)
--   |   +- -RW- Integer32 nstAgentSubagentObject(2)
--   |   +- -RW- Integer32 nstAgentPluginObject(3)
--   |
--   +-nstMIBConformance(2)


-- You can then use the snmptranslate command to get the numerical or
-- textual OID representation of any piece of the tree:


-- Getting a OID:
--   % snmptranslate -M+. -mNET-SNMP-TUTORIAL-MIB -IR nstSSSecondsSinceChanged
--   .1.3.6.1.4.1.2021.13.4242.1.1.2


-- Getting a textual OID:
--   % snmptranslate -On -M+. -mNET-SNMP-TUTORIAL-MIB -IR nstSSSecondsSinceChanged
--   enterprises.ucdavis.ucdExperimental.netSnmpTutorialMIB.nstMIBObjects.nstScalarSet.nstSSSecondsSinceChanged


-- Getting a description:
--   % snmptranslate -Td -M+. -mNET-SNMP-TUTORIAL-MIB -IR nstSSSecondsSinceChanged 
--   .1.3.6.1.4.1.2021.13.4242.1.1.2
--   SYNTAX  TimeTicks
--   UNITS   "1/100th Seconds"
--   MAX-ACCESS      read-only
--   STATUS  current
--   DESCRIPTION     "This object indicates the number of 1/100th seconds since the
--           nstSSSimpleString object has changed.  If it is has never been
--           modified, it will be the time passed since the start of the
--           agent."



-- END:  Don't forget this!
END
