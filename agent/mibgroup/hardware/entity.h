config_require(hardware/entity/entity);
config_require(hardware/entity/entPhysicalTable);
config_require(hardware/entity/entLastChangeTime);

#if defined(linux)
config_require(hardware/entity/data_access/entity_linux);
#else
config_require(hardware/entity/data_access/entity_null);
#endif
