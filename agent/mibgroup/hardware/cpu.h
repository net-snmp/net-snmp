config_require(hardware/cpu/cpu)

#if defined(linux)
config_require(hardware/cpu/cpu_linux)

#if (defined(darwin7) || defined(darwin6))
config_require(hardware/cpu/cpu_null)

#elif (defined(netbsd) || defined(netbsd1) || defined(netbsdelf) || defined(netbsdelf2)|| defined(netbsdelf3) || defined(openbsd2)|| defined(openbsd3) || defined(openbsd4) || defined(darwin))
config_require(hardware/cpu/cpu_sysctl)

#elif (defined(freebsd2) || defined(freebsd3) || defined(freebsd4)  || defined(freebsd5)|| defined(freebsd6) || defined(darwin))
config_require(hardware/cpu/cpu_nlist)

#elif (defined(aix4) || defined(aix5))
config_require(hardware/cpu/cpu_perfstat)

#elif (defined(solaris2))
config_require(hardware/cpu/cpu_kstat)

#elif (defined(hpux10) || defined(hpux11))
config_require(hardware/cpu/cpu_pstat)

#else
config_require(hardware/cpu/cpu_null)
#endif
