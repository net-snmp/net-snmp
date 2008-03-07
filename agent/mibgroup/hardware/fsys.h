config_require(hardware/fsys/hw_fsys)
#if defined(HAVE_GETVFSSTAT) || defined(HAVE_GETFSSTAT)
config_require(hardware/fsys/fsys_getfsstat)
#else
config_require(hardware/fsys/fsys_mntent)
#endif
