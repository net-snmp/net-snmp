/*
 * disk.c
 */

#include <config.h>

#include <stdio.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <signal.h>
#if HAVE_MACHINE_PARAM_H
#include <machine/param.h>
#endif
#if HAVE_SYS_VMMETER_H
#if !(defined(bsdi2) || defined(netbsd1))
#include <sys/vmmeter.h>
#endif
#endif
#if HAVE_SYS_CONF_H
#include <sys/conf.h>
#endif
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYS_SWAP_H
#include <sys/swap.h>
#endif
#if HAVE_SYS_FS_H
#include <sys/fs.h>
#else
#if HAVE_UFS_FS_H
#include <ufs/fs.h>
#else
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_VNODE_H
#include <sys/vnode.h>
#endif
#ifdef HAVE_UFS_UFS_QUOTA_H
#include <ufs/ufs/quota.h>
#endif
#ifdef HAVE_UFS_UFS_INODE_H
#include <ufs/ufs/inode.h>
#endif
#if HAVE_UFS_FFS_FS_H
#include <ufs/ffs/fs.h>
#endif
#endif
#endif
#if HAVE_MTAB_H
#include <mtab.h>
#endif
#include <sys/stat.h>
#include <errno.h>
#if HAVE_SYS_STATFS_H
#include <sys/statfs.h>
#endif
#if HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif
#if HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif
#if (!defined(HAVE_STATVFS)) && defined(HAVE_STATFS)
#if HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
#if HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif
#define statvfs statfs
#endif
#if HAVE_VM_SWAP_PAGER_H
#include <vm/swap_pager.h>
#endif
#if HAVE_SYS_FIXPOINT_H
#include <sys/fixpoint.h>
#endif
#if HAVE_MALLOC_H
#include <malloc.h>
#endif
#if STDC_HEADERS
#include <string.h>
#endif
#if HAVE_FSTAB_H
#include <fstab.h>
#endif
#if HAVE_MNTENT_H
#include <mntent.h>
#endif
#if HAVE_SYS_MNTTAB_H
#include <sys/mnttab.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include "mibincl.h"
#include "struct.h"
#include "disk.h"
#include "util_funcs.h"
#include "read_config.h"
#include "mib_module_config.h"
#include "auto_nlist.h"
#if USING_UCD_SNMP_ERRORMIB_MODULE
#include "errormib.h"
#else
#define setPerrorstatus(x) perror(x)
#endif
#include "../../../snmplib/system.h"

int numdisks;
struct diskpart disks[MAXDISKS];

void disk_free_config __P((void)) {
  int i;
  
  numdisks = 0;
  for(i=0;i<MAXDISKS;i++) {           /* init/erase disk db */
    disks[i].device[0] = 0;
    disks[i].path[0] = 0;
    disks[i].minimumspace = -1;
    disks[i].minpercent = -1;
  }
}

void disk_parse_config(word,cptr)
  char *word;
  char *cptr;
{
#if HAVE_GETMNTENT
#if HAVE_SYS_MNTTAB_H
  struct mnttab mnttab;
#else
  struct mntent *mntent;
#endif
  FILE *mntfp;
#else
#if HAVE_FSTAB_H
  struct fstab *fstab;
  struct stat stat1;
#endif
#endif
  char tmpbuf[1024];
#if defined(HAVE_GETMNTENT) && !defined(HAVE_SETMNTENT)
  int i;
#endif

#if HAVE_FSTAB_H || HAVE_GETMNTENT
  if (numdisks == MAXDISKS) {
    config_perror("Too many disks specified.");
    sprintf(tmpbuf,"\tignoring:  %s",cptr);
    config_perror(tmpbuf);
  }
  else {
    /* read disk path (eg, /1 or /usr) */
    copy_word(cptr,disks[numdisks].path);
    cptr = skip_not_white(cptr);
    cptr = skip_white(cptr);
    /* read optional minimum disk usage spec */
    if (cptr != NULL) {
      if (strchr(cptr, '%') == 0) {
        disks[numdisks].minimumspace = atoi(cptr);
        disks[numdisks].minpercent = -1;
      }
      else {
        disks[numdisks].minimumspace = -1;
        disks[numdisks].minpercent = atoi(cptr);
      }
    }
    else {
      disks[numdisks].minimumspace = DEFDISKMINIMUMSPACE;
      disks[numdisks].minpercent = -1;
    }
    /* find the device associated with the directory */
#if HAVE_GETMNTENT
#if HAVE_SETMNTENT
    mntfp = setmntent(ETC_MNTTAB, "r");
    disks[numdisks].device[0] = 0;
    while ((mntent = getmntent (mntfp)))
      if (strcmp (disks[numdisks].path, mntent->mnt_dir) == 0) {
        copy_word (mntent->mnt_fsname, disks[numdisks].device);
        DEBUGP("Disk:  %s\n",mntent->mnt_fsname);
        break;
      }
      else {
        DEBUGP("  %s != %s\n", disks[numdisks].path,
                mntent->mnt_dir);
      }
    endmntent(mntfp);
    if (disks[numdisks].device[0] != 0) {
      /* dummy clause for else below */
      numdisks += 1;  /* but inc numdisks here after test */
    }
#else /* getmentent but not setmntent */
    mntfp = fopen (ETC_MNTTAB, "r");
    while ((i = getmntent (mntfp, &mnttab)) == 0)
      if (strcmp (disks[numdisks].path, mnttab.mnt_mountp) == 0)
        break;
      else {
        DEBUGP("  %s != %s\n", disks[numdisks].path, mnttab.mnt_mountp);
      }
    fclose (mntfp);
    if (i == 0) {
      copy_word (mnttab.mnt_special, disks[numdisks].device);
      numdisks += 1;
    }
#endif /* HAVE_SETMNTENT */
#else
#if HAVE_FSTAB_H
    stat(disks[numdisks].path,&stat1);
    setfsent();
    if ((fstab = getfsfile(disks[numdisks].path))) {
      copy_word(fstab->fs_spec,disks[numdisks].device);
      numdisks += 1;
    }
#endif
#endif
    else {
      sprintf(tmpbuf, "Couldn't find device for disk %s",
              disks[numdisks].path);
      config_pwarn(tmpbuf);
      disks[numdisks].minimumspace = -1;
      disks[numdisks].minpercent = -1;
      disks[numdisks].path[0] = 0;
    }
#if HAVE_FSTAB_H
    endfsent();
#endif
  }
#else
  config_perror("'disk' checks not supported on this architecture.");
#endif
}

unsigned char *var_extensible_disk(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
/* IN - pointer to variable entry that points here */
    register oid	*name;
/* IN/OUT - input name requested, output name found */
    register int	*length;
/* IN/OUT - length of input and output oid's */
    int			exact;
/* IN - TRUE if an exact match was requested. */
    int			*var_len;
/* OUT - length of variable or 0 if function returned. */
    int			(**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
/* OUT - pointer to function to set variable, otherwise 0 */
{

  int percent, iserror, disknum=0;
#if !defined(HAVE_SYS_STATVFS_H) && !defined(HAVE_STATFS)
  double totalblks, free, used, avail, availblks;
#endif
  static long long_ret;
  static char errmsg[300];

#if defined(HAVE_STATVFS) || defined(HAVE_STATFS)
#ifdef STAT_STATFS_FS_DATA
  struct fs_data fsd;
  struct {
    u_int f_blocks, f_bfree, f_bavail;
  } vfs;
#else
  struct statvfs vfs;
#endif
#else
#if HAVE_FSTAB_H
  int file;
  union {
     struct fs iu_fs;
     char dummy[SBSIZE];
  } sb;
#define filesys sb.iu_fs
#endif
#endif
  
  if (!checkmib(vp,name,length,exact,var_len,write_method,numdisks))
    return(NULL);
  disknum = name[*length - 1] - 1;
  switch (vp->magic) {
    case MIBINDEX:
      long_ret = disknum+1;
      return((u_char *) (&long_ret));
    case ERRORNAME:       /* DISKPATH */
      *var_len = strlen(disks[disknum].path);
      return((u_char *) disks[disknum].path);
    case DISKDEVICE:
      *var_len = strlen(disks[disknum].device);
      return((u_char *) disks[disknum].device);
    case DISKMINIMUM:
      long_ret = disks[disknum].minimumspace;
      return((u_char *) (&long_ret));
    case DISKMINPERCENT:
      long_ret = disks[disknum].minpercent;
      return((u_char *) (&long_ret));
  }
#if defined(HAVE_SYS_STATVFS_H) || defined(HAVE_STATFS)
#ifdef STAT_STATFS_FS_DATA
  if (statvfs (disks[disknum].path, &fsd) == -1) {
#else
  if (statvfs (disks[disknum].path, &vfs) == -1) {
#endif
    fprintf(stderr,"Couldn't open device %s\n",disks[disknum].device);
    setPerrorstatus("statvfs dev/disk");
    return NULL;
  }
#ifdef STAT_STATFS_FS_DATA
  vfs.f_blocks = fsd.fd_btot;
  vfs.f_bfree  = fsd.fd_bfree;
  vfs.f_bavail = fsd.fd_bfreen;
#endif
#if defined(HAVE_ODS)
  vfs.f_blocks = vfs.f_spare[0];
  vfs.f_bfree  = vfs.f_spare[1];
  vfs.f_bavail = vfs.f_spare[2];
#endif
  percent = vfs.f_bavail <= 0 ? 100 : (int) ((double) (vfs.f_blocks - vfs.f_bfree) /
	    (double) (vfs.f_blocks - (vfs.f_bfree - vfs.f_bavail)) * 100.0 + 0.5);
  iserror = (disks[disknum].minimumspace >= 0 ? vfs.f_bavail < disks[disknum].minimumspace :
	    100-percent <= disks[disknum].minpercent) ? 1 : 0;
  switch (vp->magic) {
    case DISKTOTAL:
      long_ret = vfs.f_blocks;
#ifdef STRUCT_STATVFS_HAS_F_FRSIZE
      if (vfs.f_frsize > 255)
        long_ret = long_ret * (vfs.f_frsize / 1024);
#endif
      return((u_char *) (&long_ret));
    case DISKAVAIL:
      long_ret = vfs.f_bavail;
#ifdef STRUCT_STATVFS_HAS_F_FRSIZE
      if (vfs.f_frsize > 255)
        long_ret = long_ret * (vfs.f_frsize / 1024);
#endif
      return((u_char *) (&long_ret));
    case DISKUSED:
      long_ret = (vfs.f_blocks - vfs.f_bfree);
#ifdef STRUCT_STATVFS_HAS_F_FRSIZE
      if (vfs.f_frsize > 255)
        long_ret = long_ret * (vfs.f_frsize / 1024);
#endif
      return((u_char *) (&long_ret));
    case DISKPERCENT:
      long_ret = percent;
      return ((u_char *) (&long_ret));
    case ERRORFLAG:
      long_ret = iserror;
      return((u_char *) (&long_ret));
    case ERRORMSG:
      if (iserror)
	if (disks[disknum].minimumspace >= 0)
	  sprintf(errmsg,"%s: less than %d free (= %d)",disks[disknum].path,
                  disks[disknum].minimumspace, (int) vfs.f_bavail);
	else
	  sprintf(errmsg,"%s: less than %d%% free (= %d%%)",disks[disknum].path,
		  disks[disknum].minpercent, percent);
      else
        errmsg[0] = 0;
      *var_len = strlen(errmsg);
      return((u_char *) (errmsg));
  }
#else
#if HAVE_FSTAB_H
  /* read the disk information */
  if ((file = open(disks[disknum].device,0)) < 0) {
    fprintf(stderr,"Couldn't open device %s\n",disks[disknum].device);
    setPerrorstatus("open dev/disk");
    return(NULL);
  }
  lseek(file, (long) (SBLOCK * DEV_BSIZE), 0);
  if (read(file,(char *) &filesys, SBSIZE) != SBSIZE) {
    setPerrorstatus("open dev/disk");
    fprintf(stderr,"Error reading device %s\n",disks[disknum].device);
    close(file);
    return(NULL);
  }
  close(file);
  totalblks = filesys.fs_dsize;
  free = filesys.fs_cstotal.cs_nbfree * filesys.fs_frag +
    filesys.fs_cstotal.cs_nffree;
  used = totalblks - free;
  availblks = totalblks * (100 - filesys.fs_minfree) / 100;
  avail = availblks > used ? availblks - used : 0;
  percent = availblks == 0 ? 100 : (int) ((double) used / (double) totalblks * 100.0 + 0.5);
  iserror = (disks[disknum].minimumspace >= 0 ? avail * filesys.fs_fsize / 1024 <
	    disks[disknum].minimumspace : 100-percent <= disks[disknum].minpercent) ? 1 : 0;
  switch (vp->magic) {
    case DISKTOTAL:
      long_ret = (totalblks * filesys.fs_fsize / 1024);
      return((u_char *) (&long_ret));
    case DISKAVAIL:
      long_ret = avail * filesys.fs_fsize/1024;
      return((u_char *) (&long_ret));
    case DISKUSED:
      long_ret = used * filesys.fs_fsize/1024;
      return((u_char *) (&long_ret));
    case DISKPERCENT:
      long_ret = percent;
      return ((u_char *) (&long_ret));
    case ERRORFLAG:
      long_ret = iserror;
      return((u_char *) (&long_ret));
    case ERRORMSG:
      if (iserror)
	if (disks[disknum].minimumspace >= 0)
          sprintf(errmsg,"%s: less than %d free (= %d)",disks[disknum].path,
                  disks[disknum].minimumspace, avail * filesys.fs_fsize/1024);
	else
	  sprintf(errmsg,"%s: less than %d%% free (= %d%%)",disks[disknum].path,
		  disks[disknum].minpercent, percent);
      else
        errmsg[0] = 0;
      *var_len = strlen(errmsg);
      return((u_char *) (errmsg));
  }
#endif
#endif
  return NULL;
}
