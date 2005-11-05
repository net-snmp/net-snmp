config_add_mib(DISMAN-EVENT-MIB)

#ifndef DISMAN_EVENT_OLD_IMPLEMENTATION

/*
 * wrapper for the disman event mib code files 
 */
config_require(disman/event/mteScalars)
config_require(disman/event/mteTrigger)
config_require(disman/event/mteTriggerTable)
config_require(disman/event/mteTriggerDeltaTable)
config_require(disman/event/mteTriggerExistenceTable)
config_require(disman/event/mteTriggerBooleanTable)
config_require(disman/event/mteTriggerThresholdTable)
config_require(disman/event/mteTriggerConf)
config_require(disman/event/mteEvent)
config_require(disman/event/mteEventTable)
config_require(disman/event/mteEventSetTable)
config_require(disman/event/mteEventNotificationTable)
config_require(disman/event/mteEventConf)
config_require(disman/event/mteObjects)
config_require(disman/event/mteObjectsTable)
config_require(disman/event/mteObjectsConf)

/*
 * conflicts
 */
config_exclude(disman/mteTriggerTable)
config_exclude(disman/mteTriggerDeltaTable)
config_exclude(disman/mteTriggerExistenceTable)
config_exclude(disman/mteTriggerBooleanTable)
config_exclude(disman/mteTriggerThresholdTable)
config_exclude(disman/mteObjectsTable)
config_exclude(disman/mteEventTable)
config_exclude(disman/mteEventNotificationTable)

#else

/*
 * wrapper for the disman event mib code files 
 */
config_require(disman/mteTriggerTable)
config_require(disman/mteTriggerDeltaTable)
config_require(disman/mteTriggerExistenceTable)
config_require(disman/mteTriggerBooleanTable)
config_require(disman/mteTriggerThresholdTable)
config_require(disman/mteObjectsTable)
config_require(disman/mteEventTable)
config_require(disman/mteEventNotificationTable)

/*
 * conflicts
 */
config_exclude(disman/event/mteScalars)
config_exclude(disman/event/mteTrigger)
config_exclude(disman/event/mteTriggerTable)
config_exclude(disman/event/mteTriggerDeltaTable)
config_exclude(disman/event/mteTriggerExistenceTable)
config_exclude(disman/event/mteTriggerBooleanTable)
config_exclude(disman/event/mteTriggerThresholdTable)
config_exclude(disman/event/mteTriggerConf)
config_exclude(disman/event/mteEvent)
config_exclude(disman/event/mteEventTable)
config_exclude(disman/event/mteEventSetTable)
config_exclude(disman/event/mteEventNotificationTable)
config_exclude(disman/event/mteEventConf)
config_exclude(disman/event/mteObjects)
config_exclude(disman/event/mteObjectsTable)
config_exclude(disman/event/mteObjectsConf)

#endif /* DISMAN_EVENT_OLD_IMPLEMENTATION */
