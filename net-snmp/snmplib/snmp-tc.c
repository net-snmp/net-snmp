#include "config.h"
#include <sys/types.h>
#include "snmp-tc.h"
#include "asn1.h"
#include "snmp.h"
#include "snmp_api.h"


/* blatantly lifted from opensmp */
char
check_rowstatus_transition( int oldValue, int newValue, int storage_type )
{
/*
// From the SNMPv2-TC MIB:
//                                          STATE
//               +--------------+-----------+-------------+-------------
//               |      A       |     B     |      C      |      D
//               |              |status col.|status column|
//               |status column |    is     |      is     |status column
//     ACTION    |does not exist|  notReady | notInService|  is active
// --------------+--------------+-----------+-------------+-------------
// set status    |noError    ->D|inconsist- |inconsistent-|inconsistent-
// column to     |       or     |   entValue|        Value|        Value
// createAndGo   |inconsistent- |           |             |
//               |         Value|           |             |
// --------------+--------------+-----------+-------------+-------------
// set status    |noError  see 1|inconsist- |inconsistent-|inconsistent-
// column to     |       or     |   entValue|        Value|        Value
// createAndWait |wrongValue    |           |             |
// --------------+--------------+-----------+-------------+-------------
// set status    |inconsistent- |inconsist- |noError      |noError
// column to     |         Value|   entValue|             |
// active        |              |           |             |
//               |              |     or    |             |
//               |              |           |             |
//               |              |see 2   ->D|see 8     ->D|          ->D
// --------------+--------------+-----------+-------------+-------------
// set status    |inconsistent- |inconsist- |noError      |noError   ->C
// column to     |         Value|   entValue|             |
// notInService  |              |           |             |
//               |              |     or    |             |      or
//               |              |           |             |
//               |              |see 3   ->C|          ->C|see 6
// --------------+--------------+-----------+-------------+-------------
// set status    |noError       |noError    |noError      |noError   ->A
// column to     |              |           |             |      or
// destroy       |           ->A|        ->A|          ->A|see 7
// --------------+--------------+-----------+-------------+-------------
// set any other |see 4         |noError    |noError      |see 5
// column to some|              |           |             |
// value         |              |      see 1|          ->C|          ->D
// --------------+--------------+-----------+-------------+-------------

//             (1) goto B or C, depending on information available to the
//             agent.

//             (2) if other variable bindings included in the same PDU,
//             provide values for all columns which are missing but
//             required, and all columns have acceptable values, then
//             return noError and goto D.

//             (3) if other variable bindings included in the same PDU,
//             provide legal values for all columns which are missing but
//             required, then return noError and goto C.

//             (4) at the discretion of the agent, the return value may be
//             either:

//                  inconsistentName:  because the agent does not choose to
//                  create such an instance when the corresponding
//                  RowStatus instance does not exist, or

//                  inconsistentValue:  if the supplied value is
//                  inconsistent with the state of some other MIB object's
//                  value, or

//                  noError: because the agent chooses to create the
//                  instance.

//             If noError is returned, then the instance of the status
//             column must also be created, and the new state is B or C,
//             depending on the information available to the agent.  If
//             inconsistentName or inconsistentValue is returned, the row
//             remains in state A.

//             (5) depending on the MIB definition for the column/table,
//             either noError or inconsistentValue may be returned.

//             (6) the return value can indicate one of the following
//             errors:

//                  wrongValue: because the agent does not support
//                  notInService (e.g., an agent which does not support
//                  createAndWait), or

//                  inconsistentValue: because the agent is unable to take
//                  the row out of service at this time, perhaps because it
//                  is in use and cannot be de-activated.

//             (7) the return value can indicate the following error:

//                  inconsistentValue: because the agent is unable to
//                  remove the row at this time, perhaps because it is in
//                  use and cannot be de-activated.

//             (8) the transition to D can fail, e.g., if the values of the
//             conceptual row are inconsistent, then the error code would
//             be inconsistentValue.

//             NOTE: Other processing of (this and other varbinds of) the
//             set request may result in a response other than noError
//             being returned, e.g., wrongValue, noCreation, etc.
*/
    
	switch (newValue) {
		// these two end up being equivelent as far as checking the
		// status goes, although the final states are based on the
		// newValue.
	case RS_ACTIVE:
	case RS_NOTINSERVICE:
		if (oldValue == RS_NOTINSERVICE || 
				oldValue == RS_ACTIVE)
			;
		else
			return SNMP_ERR_INCONSISTENTVALUE;
		break;
		
	case RS_NOTREADY:
		// Illegal set value.
		return SNMP_ERR_INCONSISTENTVALUE;
		break;
		
	case RS_CREATEANDGO:
		if (oldValue != RS_NONEXISTENT)
			// impossible, we already exist.
			return SNMP_ERR_INCONSISTENTVALUE;
		break;
		
	case RS_CREATEANDWAIT:
		if (oldValue != RS_NONEXISTENT)
			// impossible, we already exist.
			return SNMP_ERR_INCONSISTENTVALUE;
		break;
		
	case RS_DESTROY:
		break;
		
	default:
		return SNMP_ERR_INCONSISTENTVALUE;
		break;
	}

	return SNMP_ERR_NOERROR;
}

char
check_storage_transition( int oldValue, int newValue ){
/*
// From the SNMPv2-TC MIB:

//             "Describes the memory realization of a conceptual row.  A
//             row which is volatile(2) is lost upon reboot.  A row which
//             is either nonVolatile(3), permanent(4) or readOnly(5), is
//             backed up by stable storage.  A row which is permanent(4)
//             can be changed but not deleted.  A row which is readOnly(5)
//             cannot be changed nor deleted.

//             If the value of an object with this syntax is either
//             permanent(4) or readOnly(5), it cannot be written.
//             Conversely, if the value is either other(1), volatile(2) or
//             nonVolatile(3), it cannot be modified to be permanent(4) or
//             readOnly(5).  (All illegal modifications result in a
//             'wrongValue' error.)

//             Every usage of this textual convention is required to
//             specify the columnar objects which a permanent(4) row must
//             at a minimum allow to be writable."
*/
	switch (oldValue) {
	case SNMP_STORAGE_PERMANENT:
	case SNMP_STORAGE_READONLY:
		return SNMP_ERR_INCONSISTENTVALUE;
    
	case SNMP_STORAGE_OTHER:
	case SNMP_STORAGE_VOLATILE:
	case SNMP_STORAGE_NONVOLATILE:
		if (newValue == SNMP_STORAGE_PERMANENT ||
				newValue == SNMP_STORAGE_READONLY)
			return SNMP_ERR_INCONSISTENTVALUE;
	}
	
	return SNMP_ERR_NOERROR;
}
