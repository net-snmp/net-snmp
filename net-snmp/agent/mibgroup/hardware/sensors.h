config_require(hardware/sensors/hw_sensors)

#if defined(solaris)
# if defined(HAVE_PICL_H)
config_require(hardware/sensors/picld_sensors)
# else
config_require(hardware/sensors/kstat_sensors)
# endif
#else
config_require(hardware/sensors/lmsensors_v2)
#endif

/* config_require(hardware/sensors/dummy_sensors) */
