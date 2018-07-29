#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/snmp_agent.h>
#include <net-snmp/agent/snmp_vars.h>
#include <sys/dkio.h>
#include "../hr_disk.h"

static struct dk_cinfo HRD_info;
static struct dk_geom HRD_cap;

static int      HRD_savedCtrl_type;
static int      HRD_savedFlags;

void init_hr_disk_entries(void)
{
    Add_HR_Disk_entry("/dev/rdsk/c%dt%dd0s%d", 0, 7, 0, 15,
                      "/dev/rdsk/c%dt%dd0s0", 0, 7);
    Add_HR_Disk_entry("/dev/rdsk/c%dd%ds%d", 0, 7, 0, 15,
                      "/dev/rdsk/c%dd%ds0", 0, 7);
}

void shutdown_hr_disk(void)
{
}

void Save_HR_Disk_Specific(void)
{
    HRD_savedCtrl_type = HRD_info.dki_ctype;
    HRD_savedFlags = HRD_info.dki_flags;
    HRD_savedCapacity = HRD_cap.dkg_ncyl * HRD_cap.dkg_nhead * HRD_cap.dkg_nsect / 2;   /* ??? */
}

void Save_HR_Disk_General(void)
{
    strlcpy(HRD_savedModel, HRD_info.dki_dname, HRD_SAVED_MODEL_SIZE);
}

int Query_Disk(int fd, const char *devfull)
{
    if (ioctl(fd, DKIOCINFO, &HRD_info) < 0)
        return -1;
    return ioctl(fd, DKIOCGGEOM, &HRD_cap);
}

int Is_It_Writeable(void)
{
    return HRD_savedCtrl_type == DKC_CDROM ? 2 /* read only */ :
        1 /* read-write */;
}

int What_Type_Disk(void)
{
    switch (HRD_savedCtrl_type) {
    case DKC_WDC2880:
    case DKC_DSD5215:
#ifdef DKC_XY450
    case DKC_XY450:
#endif
    case DKC_ACB4000:
    case DKC_MD21:
#ifdef DKC_XD7053
    case DKC_XD7053:
#endif
    case DKC_SCSI_CCS:
#ifdef DKC_PANTHER
    case DKC_PANTHER:
#endif
#ifdef DKC_CDC_9057
    case DKC_CDC_9057:
#endif
#ifdef DKC_FJ_M1060
    case DKC_FJ_M1060:
#endif
    case DKC_DIRECT:
    case DKC_PCMCIA_ATA:
        return 3;             /* Hard Disk */
        break;
    case DKC_NCRFLOPPY:
    case DKC_SMSFLOPPY:
    case DKC_INTEL82077:
        return 4;             /* Floppy Disk */
        break;
    case DKC_CDROM:
        return 5;             /* Optical RO */
        break;
    case DKC_PCMCIA_MEM:
        return 8;             /* RAM disk */
        break;
    case DKC_MD:               /* "meta-disk" driver */
        return 1;             /* Other */
        break;
    }

    return 2;                 /* Unknown */
}

int Is_It_Removeable(void)
{
    if (HRD_savedCtrl_type == DKC_CDROM ||
        HRD_savedCtrl_type == DKC_NCRFLOPPY ||
        HRD_savedCtrl_type == DKC_SMSFLOPPY ||
        HRD_savedCtrl_type == DKC_INTEL82077 ||
        HRD_savedCtrl_type == DKC_PCMCIA_MEM ||
        HRD_savedCtrl_type == DKC_PCMCIA_ATA)
        return 1;             /* true */

    return 2;                 /* false */
}
