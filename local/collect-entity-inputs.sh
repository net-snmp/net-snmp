#!/bin/sh

# Collect raw Linux hardware inventory inputs used by
# agent/mibgroup/hardware/entity/data_access/entity_linux.c.
# Run with sudo for complete DMI and dmidecode output.

set -u

section()
{
    printf '\n===== %s =====\n' "$1"
}

section_file()
{
    file=$1
    title=$2

    exec > "$OUTDIR/$file"
    section "$title"
}

read_file()
{
    file=$1
    [ -r "$file" ] || return 0
    value=$(sed -n '1{s/[[:cntrl:]]/ /g;p;q;}' "$file" 2>/dev/null) || return 0
    printf '%s=%s\n' "$file" "$value"
}

read_dir_files()
{
    dir=$1
    [ -d "$dir" ] || return 0

    for file in "$dir"/*; do
        [ -f "$file" ] || continue
        read_file "$file"
    done
}

read_link()
{
    path=$1
    [ -e "$path" ] || return 0
    target=$(readlink "$path" 2>/dev/null || true)
    [ -n "$target" ] && printf '%s -> %s\n' "$path" "$target"
}

read_realpath()
{
    path=$1
    [ -e "$path" ] || return 0
    target=$(readlink -f "$path" 2>/dev/null || true)
    [ -n "$target" ] && printf '%s => %s\n' "$path" "$target"
}

read_vpd_pg80()
{
    file=$1
    [ -r "$file" ] || return 0

    if command -v od >/dev/null 2>&1; then
        printf '%s=' "$file"
        od -An -tx1 -v "$file" 2>/dev/null | sed 's/^ *//;s/  */ /g'
    else
        printf '%s=od: not found\n' "$file"
    fi
}

OUTDIR=${1:-entity-inputs-$(date -u '+%Y%m%dT%H%M%SZ' 2>/dev/null || printf unknown)}
mkdir -p "$OUTDIR"

exec 3>&1

{
    printf '# ENTITY-MIB Linux hardware input collection\n'
    printf '# source=agent/mibgroup/hardware/entity/data_access/entity_linux.c\n'
    printf '# output_dir=%s\n' "$OUTDIR"
    printf '# host=%s\n' "$(hostname 2>/dev/null || printf unknown)"
    printf '# kernel=%s\n' "$(uname -a 2>/dev/null || printf unknown)"
    printf '# date=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || printf unknown)"

    if [ "$(id -u)" -ne 0 ]; then
        printf '# warning=not running as root; dmidecode and some DMI fields may be missing\n'
    fi

    printf '\n# files\n'
    printf 'dmi.txt\n'
    printf 'cpuinfo.txt\n'
    printf 'cpu-cache-sysfs.txt\n'
    printf 'memory-dmidecode.txt\n'
    printf 'pci-sysfs.txt\n'
    printf 'network-sysfs.txt\n'
    printf 'network-ethtool.txt\n'
    printf 'network-proc-dev.txt\n'
    printf 'network-proc-if-inet6.txt\n'
    printf 'network-ip-link.txt\n'
    printf 'network-ip-address.txt\n'
    printf 'ata-sysfs.txt\n'
    printf 'usb-sysfs.txt\n'
    printf 'nvme-sysfs.txt\n'
    printf 'nvme-block-sysfs.txt\n'
    printf 'sensors-hwmon.txt\n'
    printf 'sensors-libsensors.txt\n'
    printf 'power-supply-sysfs.txt\n'
    printf 'rtc-sysfs.txt\n'
    printf 'ptp-sysfs.txt\n'
    printf 'tpm-sysfs.txt\n'
    printf 'input-sysfs.txt\n'
    printf 'graphics-sysfs.txt\n'
    printf 'gpio-sysfs.txt\n'
    printf 'i2c-sysfs.txt\n'
    printf 'block-sysfs.txt\n'
    printf 'dev-disk-by-id.txt\n'
    printf 'proc-diskstats.txt\n'
    printf 'persistent-entity-files.txt\n'
    printf 'reference-lsblk.txt\n'
    printf 'reference-lspci.txt\n'
    printf 'reference-lshw.txt\n'
} > "$OUTDIR/manifest.txt"

if [ "$(id -u)" -ne 0 ]; then
    printf 'warning: not running as root; dmidecode and some DMI fields may be missing\n' >&3
fi

section_file "dmi.txt" "DMI /sys/class/dmi/id"
read_dir_files /sys/class/dmi/id

section_file "cpuinfo.txt" "CPU /proc/cpuinfo"
if [ -r /proc/cpuinfo ]; then
    awk '
        /^processor[[:space:]]*:/ ||
        /^physical id[[:space:]]*:/ ||
        /^core id[[:space:]]*:/ ||
        /^cpu cores[[:space:]]*:/ ||
        /^model name[[:space:]]*:/ ||
        /^vendor_id[[:space:]]*:/ { print }
        /^$/ { print "" }
    ' /proc/cpuinfo
fi

section_file "cpu-cache-sysfs.txt" "CPU cache /sys/devices/system/cpu"
for cpu in /sys/devices/system/cpu/cpu[0-9]*; do
    [ -d "$cpu" ] || continue
    printf '\n[%s]\n' "$(basename "$cpu")"
    read_file "$cpu/topology/physical_package_id"
    for cache in "$cpu"/cache/index*; do
        [ -d "$cache" ] || continue
        printf '\n[%s/%s]\n' "$(basename "$cpu")" "$(basename "$cache")"
        for name in level type size coherency_line_size number_of_sets ways_of_associativity shared_cpu_list; do
            read_file "$cache/$name"
        done
    done
done

section_file "memory-dmidecode.txt" "Memory dmidecode -t memory"
if command -v dmidecode >/dev/null 2>&1; then
    dmidecode -t memory 2>&1
else
    printf 'dmidecode: not found\n'
fi

section_file "pci-sysfs.txt" "PCI /sys/bus/pci/devices"
for dev in /sys/bus/pci/devices/*; do
    [ -d "$dev" ] || continue
    printf '\n[%s]\n' "$(basename "$dev")"
    read_realpath "$dev"
    for name in class vendor device subsystem_vendor subsystem_device revision irq numa_node driver_override current_link_speed current_link_width max_link_speed max_link_width; do
        read_file "$dev/$name"
    done
    read_link "$dev/driver"
    read_link "$dev/iommu_group"
    if [ -d "$dev/net" ]; then
        printf 'net_children='
        first=1
        for iface in "$dev"/net/*; do
            [ -e "$iface" ] || continue
            if [ "$first" -eq 0 ]; then
                printf ','
            fi
            first=0
            printf '%s' "$(basename "$iface")"
        done
        printf '\n'
    fi
done

section_file "network-sysfs.txt" "Network /sys/class/net"
for iface in /sys/class/net/*; do
    [ -d "$iface" ] || continue
    printf '\n[%s]\n' "$(basename "$iface")"
    for name in address addr_assign_type addr_len broadcast carrier dormant duplex flags ifalias ifindex iflink link_mode mtu name_assign_type operstate phys_port_id phys_port_name phys_switch_id proto_down speed testing type; do
        read_file "$iface/$name"
    done
    read_dir_files "$iface/statistics"
    read_link "$iface/device"
    read_realpath "$iface/device"
    [ -d "$iface/wireless" ] && printf '%s/wireless=present\n' "$iface"
done

section_file "network-ethtool.txt" "Network ethtool ioctl-equivalent reference"
for iface in /sys/class/net/*; do
    [ -d "$iface" ] || continue
    name=$(basename "$iface")
    printf '\n[%s]\n' "$name"
    if command -v ethtool >/dev/null 2>&1; then
        ethtool -i "$name" 2>&1
        printf '\n-- link settings --\n'
        ethtool "$name" 2>&1
        printf '\n-- module info --\n'
        ethtool -m "$name" 2>&1
    else
        printf 'ethtool: not found\n'
    fi
done

section_file "network-proc-dev.txt" "Network /proc/net/dev"
if [ -r /proc/net/dev ]; then
    sed -n '1,$p' /proc/net/dev
fi

section_file "network-proc-if-inet6.txt" "Network /proc/net/if_inet6"
if [ -r /proc/net/if_inet6 ]; then
    sed -n '1,$p' /proc/net/if_inet6
fi

section_file "network-ip-link.txt" "Network ip -details link"
if command -v ip >/dev/null 2>&1; then
    ip -details link show 2>&1
else
    printf 'ip: not found\n'
fi

section_file "network-ip-address.txt" "Network ip address"
if command -v ip >/dev/null 2>&1; then
    ip address show 2>&1
else
    printf 'ip: not found\n'
fi

section_file "ata-sysfs.txt" "ATA /sys/class/ata_port and /sys/class/ata_link"
for port in /sys/class/ata_port/ata*; do
    [ -d "$port" ] || continue
    printf '\n[%s]\n' "$(basename "$port")"
    read_realpath "$port"
    read_link "$port/device"
done
for link in /sys/class/ata_link/link*; do
    [ -d "$link" ] || continue
    printf '\n[%s]\n' "$(basename "$link")"
    read_realpath "$link"
    read_file "$link/sata_spd"
done

section_file "usb-sysfs.txt" "USB /sys/bus/usb/devices"
for usb in /sys/bus/usb/devices/*; do
    [ -d "$usb" ] || continue
    printf '\n[%s]\n' "$(basename "$usb")"
    read_realpath "$usb"
    for name in version speed busnum devnum devpath bDeviceClass bDeviceSubClass bDeviceProtocol bInterfaceClass bInterfaceSubClass bInterfaceProtocol idVendor idProduct product manufacturer serial bcdDevice removable uevent; do
        read_file "$usb/$name"
    done
    read_link "$usb/driver"
done

section_file "nvme-sysfs.txt" "NVMe /sys/class/nvme"
for nvme in /sys/class/nvme/*; do
    [ -d "$nvme" ] || continue
    printf '\n[%s]\n' "$(basename "$nvme")"
    read_realpath "$nvme"
    for name in model serial firmware_rev cntlid state address uuid; do
        read_file "$nvme/$name"
    done
    read_link "$nvme/device"
    for ns in "$nvme"/"$(basename "$nvme")"n*; do
        [ -d "$ns" ] || continue
        printf '\n[%s/%s]\n' "$(basename "$nvme")" "$(basename "$ns")"
        for name in wwid uuid eui nguid; do
            read_file "$ns/$name"
        done
    done
done

section_file "nvme-block-sysfs.txt" "NVMe block /sys/block/nvme*"
for block in /sys/block/nvme*; do
    [ -d "$block" ] || continue
    printf '\n[%s]\n' "$(basename "$block")"
    for name in size removable ro queue/logical_block_size queue/physical_block_size queue/rotational device/model device/serial device/firmware_rev; do
        read_file "$block/$name"
    done
    read_link "$block/device"
done

section_file "sensors-hwmon.txt" "Sensors /sys/class/hwmon"
for hwmon in /sys/class/hwmon/hwmon*; do
    [ -d "$hwmon" ] || continue
    printf '\n[%s]\n' "$(basename "$hwmon")"
    read_realpath "$hwmon"
    read_file "$hwmon/name"
    read_link "$hwmon/device"
    for sensor in "$hwmon"/temp*_input "$hwmon"/temp*_label "$hwmon"/fan*_input "$hwmon"/fan*_label "$hwmon"/in*_input "$hwmon"/in*_label "$hwmon"/curr*_input "$hwmon"/curr*_label "$hwmon"/power*_input "$hwmon"/power*_label "$hwmon"/energy*_input "$hwmon"/energy*_label "$hwmon"/humidity*_input "$hwmon"/humidity*_label; do
        [ -f "$sensor" ] || continue
        read_file "$sensor"
    done
done

section_file "sensors-libsensors.txt" "Sensors libsensors reference"
if command -v sensors >/dev/null 2>&1; then
    sensors -u 2>&1
else
    printf 'sensors: not found\n'
fi

section_file "power-supply-sysfs.txt" "Power supply /sys/class/power_supply"
for psy in /sys/class/power_supply/*; do
    [ -d "$psy" ] || continue
    printf '\n[%s]\n' "$(basename "$psy")"
    read_realpath "$psy"
    for name in type manufacturer model_name serial_number technology status capacity energy_full energy_now charge_full charge_now voltage_now current_now; do
        read_file "$psy/$name"
    done
done

section_file "rtc-sysfs.txt" "RTC /sys/class/rtc"
for rtc in /sys/class/rtc/rtc*; do
    [ -d "$rtc" ] || continue
    printf '\n[%s]\n' "$(basename "$rtc")"
    read_realpath "$rtc"
    read_file "$rtc/name"
    read_file "$rtc/device/uevent"
done

section_file "ptp-sysfs.txt" "PTP /sys/class/ptp"
for ptp in /sys/class/ptp/ptp*; do
    [ -d "$ptp" ] || continue
    printf '\n[%s]\n' "$(basename "$ptp")"
    read_realpath "$ptp"
    for name in clock_name max_adjustment pps_available uevent; do
        read_file "$ptp/$name"
    done
done

section_file "tpm-sysfs.txt" "TPM /sys/class/tpm"
for tpm in /sys/class/tpm/tpm*; do
    [ -d "$tpm" ] || continue
    printf '\n[%s]\n' "$(basename "$tpm")"
    read_realpath "$tpm"
    for name in tpm_version_major uevent device/uevent; do
        read_file "$tpm/$name"
    done
    read_realpath "$tpm/device/tpmrm/tpmrm$(basename "$tpm" | sed 's/^tpm//')"
done

section_file "input-sysfs.txt" "Input /sys/class/input"
for input in /sys/class/input/js* /sys/class/input/mouse*; do
    [ -d "$input" ] || continue
    printf '\n[%s]\n' "$(basename "$input")"
    read_realpath "$input"
    for name in uevent device/name device/uniq device/modalias; do
        read_file "$input/$name"
    done
done

section_file "graphics-sysfs.txt" "Graphics /sys/class/graphics"
for graphics in /sys/class/graphics/fb*; do
    [ -d "$graphics" ] || continue
    printf '\n[%s]\n' "$(basename "$graphics")"
    read_realpath "$graphics"
    for name in name modes mode virtual_size bits_per_pixel stride rotate blank state dev uevent; do
        read_file "$graphics/$name"
    done
    read_link "$graphics/device"
    read_realpath "$graphics/device"
done

section_file "gpio-sysfs.txt" "GPIO /sys/class/gpio"
for gpio in /sys/class/gpio/chip* /sys/class/gpio/gpiochip*; do
    [ -d "$gpio" ] || continue
    gpio_realpath=$(readlink -f "$gpio" 2>/dev/null || true)
    case "$gpio_realpath" in
        *soc:firmware*|*virtgpio*|*expgpio*) continue ;;
    esac
    printf '\n[%s]\n' "$(basename "$gpio")"
    [ -n "$gpio_realpath" ] && printf '%s => %s\n' "$gpio" "$gpio_realpath"
    for name in label ngpio base uevent; do
        read_file "$gpio/$name"
    done
    read_link "$gpio/device"
    read_realpath "$gpio/device"
done

section_file "i2c-sysfs.txt" "I2C /sys/class/i2c-dev"
for i2c in /sys/class/i2c-dev/i2c-*; do
    [ -d "$i2c" ] || continue
    printf '\n[%s]\n' "$(basename "$i2c")"
    read_realpath "$i2c"
    read_file "$i2c/name"
    for child in "$i2c"/device/*-*; do
        [ -d "$child" ] || continue
        printf '\n[%s/%s]\n' "$(basename "$i2c")" "$(basename "$child")"
        read_realpath "$child"
        read_file "$child/name"
        read_file "$child/modalias"
    done
done

section_file "block-sysfs.txt" "Block devices /sys/block"
for block in /sys/block/*; do
    [ -d "$block" ] || continue
    case "$(basename "$block")" in
        loop*|ram*) continue ;;
    esac
    printf '\n[%s]\n' "$(basename "$block")"
    read_realpath "$block"
    for name in size removable ro queue/logical_block_size queue/physical_block_size queue/rotational device/model device/vendor device/rev device/serial device/wwid; do
        read_file "$block/$name"
    done
    read_vpd_pg80 "$block/device/vpd_pg80"
    read_link "$block/device"
    read_realpath "$block/device"
done

section_file "dev-disk-by-id.txt" "/dev/disk/by-id symlinks"
for disk in /dev/disk/by-id/*; do
    [ -e "$disk" ] || continue
    read_link "$disk"
    read_realpath "$disk"
done

section_file "proc-diskstats.txt" "Disk aliases /proc/diskstats"
if [ -r /proc/diskstats ]; then
    sed -n '1,$p' /proc/diskstats
fi

section_file "persistent-entity-files.txt" "Net-SNMP persistent entity files"
for dir in /var/lib/net-snmp /var/net-snmp /usr/local/var/lib/net-snmp; do
    [ -d "$dir" ] || continue
    printf '\n[%s]\n' "$dir"
    for name in entity_indexes entity_indexes.tmp entity_state; do
        read_file "$dir/$name"
    done
done

section_file "reference-lsblk.txt" "Reference lsblk"
if command -v lsblk >/dev/null 2>&1; then
    lsblk -O 2>&1
else
    printf 'lsblk: not found\n'
fi

section_file "reference-lspci.txt" "Reference lspci"
if command -v lspci >/dev/null 2>&1; then
    lspci -D -nn -vv 2>&1
else
    printf 'lspci: not found\n'
fi

section_file "reference-lshw.txt" "Reference lshw"
if command -v lshw >/dev/null 2>&1; then
    lshw -sanitize 2>&1
else
    printf 'lshw: not found\n'
fi

exec >&3
printf 'wrote ENTITY-MIB input files to %s\n' "$OUTDIR"
