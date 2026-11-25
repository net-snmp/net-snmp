#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/hardware/sensors.h>
#include "hw_sensors_private.h"

#include <time.h>
#include <sensors/sensors.h>

/*
 * A sensor reading, collected before any sensor entries are created so
 * that names (and the order in which new indexes are assigned) do not
 * depend on the order in which libsensors happens to report chips.
 */
struct sensor_reading {
    char           *label;
    char            chip_name[64];
    char            subfeature_name[64];
    char            name[256];
    double          val;
    int             type;
    int             have_val;
};

void netsnmp_sensor_arch_init( void ) {
    FILE *fp = fopen("/etc/sensors.conf", "r");
    DEBUGMSGTL(("sensors:arch", "Initialise v3 LM Sensors module\n"));
    sensors_init( fp );
}

static int
_reading_cmp_label(const void *a, const void *b)
{
    const struct sensor_reading *ra = a, *rb = b;
    int             res;

    res = strcmp(ra->label, rb->label);
    if (res == 0)
        res = strcmp(ra->chip_name, rb->chip_name);
    if (res == 0)
        res = strcmp(ra->subfeature_name, rb->subfeature_name);
    return res;
}

static int
_reading_cmp_name(const void *a, const void *b)
{
    const struct sensor_reading *ra = a, *rb = b;

    return strcmp(ra->name, rb->name);
}

/*
 * Assign each reading a name that is the same no matter which order the
 * chips were detected in:
 *  - "<label>"                       if the label is unique,
 *  - "<chip>:<label>"                if the label appears on several chips,
 *  - "<chip>:<label>:<subfeature>"   if the label repeats within one chip.
 * The readings must be sorted with _reading_cmp_label().
 */
static void
_name_readings(struct sensor_reading *r, int n)
{
    int             i, j, k;

    for (i = 0; i < n; i = j) {
        for (j = i + 1; j < n && !strcmp(r[i].label, r[j].label); j++)
            ;
        if (j - i == 1) {
            strlcpy(r[i].name, r[i].label, sizeof(r[i].name));
            continue;
        }
        for (k = i; k < j; k++) {
            int             same_chip =
                (k > i && !strcmp(r[k].chip_name, r[k - 1].chip_name)) ||
                (k + 1 < j && !strcmp(r[k].chip_name, r[k + 1].chip_name));

            if (same_chip)
                snprintf(r[k].name, sizeof(r[k].name), "%s:%s:%s",
                         r[k].chip_name, r[k].label, r[k].subfeature_name);
            else
                snprintf(r[k].name, sizeof(r[k].name), "%s:%s",
                         r[k].chip_name, r[k].label);
        }
    }
}

int
netsnmp_sensor_arch_load(netsnmp_cache *cache, void *vp) {
    netsnmp_sensor_info        *sp;
    const sensors_chip_name    *chip;
    const sensors_feature      *data;
    const sensors_subfeature   *data2;
    struct sensor_reading      *readings = NULL, *r;
    int             nreadings = 0, max_readings = 0;
    int             chip_nr = 0;
    int             missing = 0;
    int             rc = 0;
    int             i;

    DEBUGMSGTL(("sensors:arch", "Reload v3 LM Sensors module\n"));
    while ((chip = sensors_get_detected_chips( NULL, &chip_nr))) {
        char            chip_name[64];
	int             a = 0;

        if (sensors_snprintf_chip_name(chip_name, sizeof(chip_name), chip) < 0) {
            DEBUGMSGTL(("sensors:arch:detail", "Can't get chip name\n"));
            continue;
        }

        while ((data = sensors_get_features( chip, &a))) {
	    int             b = 0;

            DEBUGMSGTL(("sensors:arch:detail", "get_features (%s, %d)\n", data->name, data->number));

            while ((data2 = sensors_get_all_subfeatures( chip, data, &b))) {
                char           *label = NULL;
                double          val = 0;
                int             type = NETSNMP_SENSOR_TYPE_OTHER;

                DEBUGMSGTL(("sensors:arch:detail", "  get_subfeatures (%s, %d)\n", data2->name, data2->number));
                /*
                 * Check the type of this subfeature,
                 *   concentrating on the main "input" measurements.
                 */
                switch ( data2->type ) {
                case SENSORS_SUBFEATURE_IN_INPUT:
                    type = NETSNMP_SENSOR_TYPE_VOLTAGE_DC;
                    break;
                case SENSORS_SUBFEATURE_FAN_INPUT:
                    type = NETSNMP_SENSOR_TYPE_RPM;
                    break;
                case SENSORS_SUBFEATURE_TEMP_INPUT:
                    type = NETSNMP_SENSOR_TYPE_TEMPERATURE;
                    break;
                case SENSORS_SUBFEATURE_VID:
                    type = NETSNMP_SENSOR_TYPE_VOLTAGE_DC;
                    break;
                case SENSORS_SUBFEATURE_HUMIDITY_INPUT:
                    type = NETSNMP_SENSOR_TYPE_HUMIDITY;
                    break;
                default:
                    /* Skip everything other than these basic sensor features - ??? */
                    DEBUGMSGTL(("sensors:arch:detail", "  Skip type %x\n", data2->type));
                    continue;
                }

                /*
                 * Get the name and value of this subfeature.
                 * A sensor whose value cannot be read is still recorded,
                 * so that it continues to take part in name assignment,
                 * but no entry is created or updated for it.
                 */
                if (!(label = sensors_get_label(chip, data))) {
                    DEBUGMSGTL(("sensors:arch:detail", "  Can't get name\n"));
                    continue;
                }
                if (nreadings == max_readings) {
                    int             new_max = max_readings ? 2 * max_readings : 32;
                    r = realloc(readings, new_max * sizeof(*readings));
                    if (!r) {
                        snmp_log(LOG_ERR, "Out of memory reading sensors\n");
                        free(label);
                        rc = -1;
                        goto out;
                    }
                    readings = r;
                    max_readings = new_max;
                }
                r = &readings[nreadings++];
                memset(r, 0, sizeof(*r));
                r->label = label;
                r->type = type;
                strlcpy(r->chip_name, chip_name, sizeof(r->chip_name));
                strlcpy(r->subfeature_name, data2->name, sizeof(r->subfeature_name));
                if (sensors_get_value(chip, data2->number, &val) < 0) {
                    DEBUGMSGTL(("sensors:arch:detail", "  Can't get value (%s)\n", label));
                } else {
                    DEBUGMSGTL(("sensors:arch:detail", "%s = %f\n", label, val));
                    r->val = val;
                    r->have_val = 1;
                }
            } /* end while data2 */
        } /* end while data */
    } /* end while chip */

    if (nreadings > 0) {
        qsort(readings, nreadings, sizeof(*readings), _reading_cmp_label);
        _name_readings(readings, nreadings);
    }

    for (i = 0; i < nreadings; i++) {
        r = &readings[i];
        if (!r->have_val)
            continue;
        DEBUGMSGTL(("sensors:arch:detail", "Sensor name: %s\n", r->name));
        sp = sensor_by_name( r->name, NETSNMP_SENSOR_FIND_EXIST );
        if (sp) {
            sp->value = r->val;
            sp->flags|= NETSNMP_SENSOR_FLAG_ACTIVE;
        } else
            missing++;
    }

    if (missing) {
        /*
         * Create any new entries in name order, so that sensors
         *  without a saved index are numbered the same way each time.
         */
        qsort(readings, nreadings, sizeof(*readings), _reading_cmp_name);
        for (i = 0; i < nreadings; i++) {
            r = &readings[i];
            if (!r->have_val)
                continue;
            /*
             * Use this type to create a new sensor entry
             *  (inserting it in the appropriate sub-containers)
             */
            sp = sensor_by_name( r->name, r->type );
            if (sp) {
                sp->value = r->val;
                sp->flags|= NETSNMP_SENSOR_FLAG_ACTIVE;
            }
        }
    }

out:
    for (i = 0; i < nreadings; i++)
        free(readings[i].label);
    free(readings);
    return rc;
}
