config_require(hardware/fsys/hw_fsys)
#if defined(aix4) || defined(aix5) || defined(aix6)
config_require(hardware/fsys/fsys_mntctl)
#elif defined(HAVE_GETVFSSTAT) || defined(HAVE_GETFSSTAT)
config_require(hardware/fsys/fsys_getfsstat)
#else
config_require(hardware/fsys/fsys_mntent)
#endif
