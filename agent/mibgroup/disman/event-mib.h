/*
 * wrapper for the disman event mib code files 
 */
config_require(disman/mteTriggerTable)
config_require(disman/mteTriggerDeltaTable)
config_require(disman/mteTriggerExistenceTable)
config_require(disman/mteTriggerBooleanTable)
config_require(disman/mteTriggerThresholdTable)
config_require(disman/mteObjectsTable)
config_add_mib(DISMAN-EVENT-MIB)
