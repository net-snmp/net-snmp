/* lmSensors.c
 *
 * This componenet allows net-snmp to report sensor information.
 *
 * It uses one of three different methdologies.  Some platforms make
 * use of an lm_sensors driver to access the information on the
 * health monitoring hardware, such as the LM75 and LM78 chips.
 *
 * For further information see http://secure.netroedge.com/~lm78/
 *
 * The Solaris platform uses the other two methodologies.  Earlier
 * platforms such as the Enterprise 450 use kstat to report sensor
 * information.  Later platforms, such as the V880 use the picld
 * daemon to control system resources and report sensor information.
 * Picld is supported only on Solaris 2.8 and later.
 *
 * The lmSensors component delivers the information documented in the
 * LM-SENSORS-MIB.  The information is divided up as follows:
 *
 * -temperatures (Celsius)
 * -fans (rpm's)
 * -voltages
 * -other
 *
 * The component can record up to 128 instances of each type.
 *
 * This should always be included first before anything else 
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

/*
 * minimal include directives 
 */
#include "util_funcs.h"
#include <time.h>

/*
 * Load required drivers and libraries.
 */

#ifdef solaris2
    #include <kstat.h>
    #ifdef HAVE_PICL_H 
        #include <picl.h> /* accesses the picld daemon */
    #endif 
    #include </usr/platform/sun4u/include/sys/envctrl.h>
#else
    #include <sensors/sensors.h>
    #define CONFIG_FILE_NAME "/etc/sensors.conf"
#endif

#include "lmSensors.h"

#define N_TYPES      (4)

#ifdef solaris2
    #define MAX_NAME     (256)
#else
    #define MAX_NAME     (64)
#endif

#define MAX_SENSORS  (128)

/*
 * lmSensors_variables_oid:
 *   this is the top level oid that we want to register under.  This
 *   is essentially a prefix, with the suffix appearing in the
 *   variable below.
 */


oid             lmSensors_variables_oid[] =
    { 1, 3, 6, 1, 4, 1, 2021, 13, 16 };

/*
 * variable4 lmSensors_variables:
 *   this variable defines function callbacks and type return information 
 *   for the lmSensors mib section 
 */

struct variable4 lmSensors_variables[] = {
    /*
     * magic number        , variable type , ro/rw , callback fn  , L, oidsuffix 
     */
#define   LMTEMPSENSORSINDEX    3
    {LMTEMPSENSORSINDEX, ASN_INTEGER, RONLY, var_lmSensorsTable, 3,
     {2, 1, 1}},
#define   LMTEMPSENSORSDEVICE   4
    {LMTEMPSENSORSDEVICE, ASN_OCTET_STR, RONLY, var_lmSensorsTable, 3,
     {2, 1, 2}},
#define   LMTEMPSENSORSVALUE    5
    {LMTEMPSENSORSVALUE, ASN_GAUGE, RONLY, var_lmSensorsTable, 3,
     {2, 1, 3}},
#define   LMFANSENSORSINDEX     8
    {LMFANSENSORSINDEX, ASN_INTEGER, RONLY, var_lmSensorsTable, 3,
     {3, 1, 1}},
#define   LMFANSENSORSDEVICE    9
    {LMFANSENSORSDEVICE, ASN_OCTET_STR, RONLY, var_lmSensorsTable, 3,
     {3, 1, 2}},
#define   LMFANSENSORSVALUE     10
    {LMFANSENSORSVALUE, ASN_GAUGE, RONLY, var_lmSensorsTable, 3,
     {3, 1, 3}},
#define   LMVOLTSENSORSINDEX    13
    {LMVOLTSENSORSINDEX, ASN_INTEGER, RONLY, var_lmSensorsTable, 3,
     {4, 1, 1}},
#define   LMVOLTSENSORSDEVICE   14
    {LMVOLTSENSORSDEVICE, ASN_OCTET_STR, RONLY, var_lmSensorsTable, 3,
     {4, 1, 2}},
#define   LMVOLTSENSORSVALUE    15
    {LMVOLTSENSORSVALUE, ASN_GAUGE, RONLY, var_lmSensorsTable, 3,
     {4, 1, 3}},
#define   LMMISCSENSORSINDEX    18
    {LMMISCSENSORSINDEX, ASN_INTEGER, RONLY, var_lmSensorsTable, 3,
     {5, 1, 1}},
#define   LMMISCSENSORSDEVICE   19
    {LMMISCSENSORSDEVICE, ASN_OCTET_STR, RONLY, var_lmSensorsTable, 3,
     {5, 1, 2}},
#define   LMMISCSENSORSVALUE    20
    {LMMISCSENSORSVALUE, ASN_GAUGE, RONLY, var_lmSensorsTable, 3,
     {5, 1, 3}},
};

typedef struct {
#ifdef solaris2
    #ifdef HAVE_PICL_H
        char            name[PICL_PROPNAMELEN_MAX]; /*required for picld*/
        int             value;
    #else
       char            name[MAX_NAME];
       int             value;
    #endif
#else
    char            name[MAX_NAME];
    int             value;
#endif
} _sensor;

typedef struct {
    int             n;
    _sensor         sensor[MAX_SENSORS];
} _sensor_array;

static _sensor_array sensor_array[N_TYPES];
static clock_t  timestamp;

static int      sensor_init(void);
static void     sensor_load(void);
static void     _sensor_load(clock_t t);


/*
 * init_lmSensors():
 *   Initialization routine.  This is called when the agent starts up.
 *   At a minimum, registration of your variables should take place here.
 */
void
init_lmSensors(void)
{
   sensor_init(); 

    /*
     * register ourselves with the agent to handle our mib tree 
     */
    REGISTER_MIB("lmSensors", lmSensors_variables, variable4,
                 lmSensors_variables_oid);
}

/*
 * var_lmSensorsTable():
 *   Handle this table separately from the scalar value case.
 *   The workings of this are basically the same as for var_lmSensors above.
 */
unsigned char  *
var_lmSensorsTable(struct variable *vp,
                   oid * name,
                   size_t * length,
                   int exact,
                   size_t * var_len, WriteMethod ** write_method)
{
    static long     long_ret;
    static unsigned char string[SPRINT_MAX_LEN];
    int             i;  /* generates a variable not used error message in Solaris - that's OK */

    int             s_index;
    int             s_type = -1;
    int             n_sensors;

    _sensor         s;

    sensor_load();

    switch (vp->magic) {
    case LMTEMPSENSORSINDEX:
    case LMTEMPSENSORSDEVICE:
    case LMTEMPSENSORSVALUE:
        s_type = 0;
        n_sensors = sensor_array[0].n;
        break;

    case LMFANSENSORSINDEX:
    case LMFANSENSORSDEVICE:
    case LMFANSENSORSVALUE:
        s_type = 1;
        n_sensors = sensor_array[1].n;
        break;

    case LMVOLTSENSORSINDEX:
    case LMVOLTSENSORSDEVICE:
    case LMVOLTSENSORSVALUE:
        s_type = 2;
        n_sensors = sensor_array[2].n;
        break;

    case LMMISCSENSORSINDEX:
    case LMMISCSENSORSDEVICE:
    case LMMISCSENSORSVALUE:
        s_type = 3;
        n_sensors = sensor_array[3].n;
        break;

    default:
        s_type = -1;
        n_sensors = 0;
    }

    if (header_simple_table(vp, name, length, exact,
                            var_len, write_method,
                            n_sensors) == MATCH_FAILED)
        return NULL;

    if (s_type < 0)
        return NULL;

    s_index = name[*length - 1] - 1;
    s = sensor_array[s_type].sensor[s_index];

    switch (vp->magic) {
    case LMTEMPSENSORSINDEX:
    case LMFANSENSORSINDEX:
    case LMVOLTSENSORSINDEX:
    case LMMISCSENSORSINDEX:
        long_ret = s_index;
        return (unsigned char *) &long_ret;

    case LMTEMPSENSORSDEVICE:
    case LMFANSENSORSDEVICE:
    case LMVOLTSENSORSDEVICE:
    case LMMISCSENSORSDEVICE:
        strncpy(string, s.name, SPRINT_MAX_LEN - 1);
        *var_len = strlen(string);
        return (unsigned char *) string;

    case LMTEMPSENSORSVALUE:
    case LMFANSENSORSVALUE:
    case LMVOLTSENSORSVALUE:
    case LMMISCSENSORSVALUE:
        long_ret = s.value;
        return (unsigned char *) &long_ret;

    default:
        ERROR_MSG("Unable to handle table request");
    }

    return NULL;
}

static int
sensor_init(void)
{
#ifdef solaris2
    clock_t         t = time(NULL);
#else
    int             res;
    char            filename[] = CONFIG_FILE_NAME;
    clock_t         t = clock();
    FILE           *fp = fopen(filename, "r");
    if (!fp)
        return 1;

    if (res = sensors_init(fp))
        return 2;
/* #endif */

    _sensor_load(t);
#endif
    return 0;
}

static void
sensor_load(void)
{
#ifdef solaris2
    clock_t         t = time(NULL);
#else
    clock_t	t = clock();
#endif

    if (t > timestamp + 6) /* this may require some tuning*/
        _sensor_load(t);

    return;
}
#ifdef solaris2
/* *******  picld sensor procedures * */
#ifdef HAVE_PICL_H
static int
process_individual_fan(picl_nodehdl_t childh, char propname[PICL_PROPNAMELEN_MAX])
{
        picl_nodehdl_t  sensorh;
        picl_propinfo_t sensor_info;

        int speed;
        int typ = 1; /*fan*/

        picl_errno_t    error_code,ec2;

        error_code = (picl_get_propinfo_by_name(childh,"AtoDSensorValue",&sensor_info,&sensorh));
        if (error_code == PICL_SUCCESS) {
             ec2 = picl_get_propval(sensorh,&speed,sizeof(speed));
             if (ec2 == PICL_SUCCESS){
                 sensor_array[typ].sensor[sensor_array[typ].n].value = speed;
                 snprintf(sensor_array[typ].sensor[sensor_array[typ].n].name,
                    (PICL_PROPNAMELEN_MAX - 1),"%s",propname);
                 sensor_array[typ].sensor[sensor_array[typ].n].name[PICL_PROPNAMELEN_MAX - 1] = '\0';
                 sensor_array[typ].n++;
                 } /*end if ec2*/
             else
                 DEBUGMSG(("ucd-snmp/lmSensors", "sensor value read error code->%d\n",ec2));
            } /* end if */
        else
            DEBUGMSG(("ucd-snmp/lmSensors", "sensor lookup failed  error code->%d\n",error_code));
} /*process individual fan*/

static int
process_temperature_sensor(picl_nodehdl_t childh,char propname[PICL_PROPNAMELEN_MAX])
{
        picl_nodehdl_t  sensorh;
        picl_propinfo_t sensor_info;

        int temp;
        int typ = 0; /*temperature*/

        picl_errno_t    error_code,ec2;

        error_code = (picl_get_propinfo_by_name(childh,"Temperature",&sensor_info,&sensorh));
        if (error_code == PICL_SUCCESS) {
             ec2 = picl_get_propval(sensorh,&temp,sizeof(temp));
             if (ec2 == PICL_SUCCESS){
                 sensor_array[typ].sensor[sensor_array[typ].n].value = temp;
                 snprintf(sensor_array[typ].sensor[sensor_array[typ].n].name,
                    (PICL_PROPNAMELEN_MAX - 1),"%s",propname);
                 sensor_array[typ].sensor[sensor_array[typ].n].name[PICL_PROPNAMELEN_MAX - 1] = '\0';
                 sensor_array[typ].n++;
                 } /*end if ec2*/
             else
                 DEBUGMSG(("ucd-snmp/lmSensors", "sensor value read error code->%d\n",ec2));
            } /* end if */
        else
            DEBUGMSG(("ucd-snmp/lmSensors", "sensor lookup failed  error code->%d\n",error_code));
}  /* process temperature sensor */

static int
process_digital_sensor(picl_nodehdl_t childh,char propname[PICL_PROPNAMELEN_MAX])
{
        picl_nodehdl_t  sensorh;
        picl_propinfo_t sensor_info;

        int temp; /*volts?*/
        int typ = 2; /*volts*/

        picl_errno_t    error_code,ec2;

        error_code = (picl_get_propinfo_by_name(childh,
             "AtoDSensorValue",&sensor_info,&sensorh));
        if (error_code == PICL_SUCCESS) {
             ec2 = picl_get_propval(sensorh,&temp,sizeof(temp));
             if (ec2 == PICL_SUCCESS){
                 sensor_array[typ].sensor[sensor_array[typ].n].value = temp;
                 snprintf(sensor_array[typ].sensor[sensor_array[typ].n].name,
                    (PICL_PROPNAMELEN_MAX - 1),"%s",propname);
                 sensor_array[typ].sensor[sensor_array[typ].n].name[PICL_PROPNAMELEN_MAX - 1] = '\0';
                 sensor_array[typ].n++;
                 }
             else
                 DEBUGMSG(("ucd-snmp/lmSensors", 
                   "sensor value read error code->%d\n",ec2));
            } /* end if */
        else
            DEBUGMSG(("ucd-snmp/lmSensors", 
              "sensor lookup failed  error code->%d\n",error_code));
}  /* process digital sensor */

static int
process_sensors(picl_nodehdl_t nodeh)
{
        picl_nodehdl_t  childh;
        picl_nodehdl_t  nexth;

        char            propname[PICL_PROPNAMELEN_MAX];
        char            propclass[PICL_CLASSNAMELEN_MAX];
        picl_errno_t    error_code;

        /* look up first child node */
        error_code = picl_get_propval_by_name(nodeh, PICL_PROP_CHILD, &childh,
                                        sizeof (picl_nodehdl_t));
        if (error_code != PICL_SUCCESS) {
                return (error_code);
        }

        /* step through child nodes, get the name first */
        while (error_code == PICL_SUCCESS) {
                error_code = picl_get_propval_by_name(childh, PICL_PROP_NAME,
                                                propname, (PICL_PROPNAMELEN_MAX - 1));
                if (error_code != PICL_SUCCESS) {  /*we found a node with no name.  Impossible.! */
                        return (error_code);
                }

                if (strcmp(propname,PICL_NODE_PLATFORM)==0){ /*end of the chain*/
                        return (255);
                }

                error_code = picl_get_propval_by_name(childh, PICL_PROP_CLASSNAME,
                                                propclass, sizeof (propclass));
                if (error_code != PICL_SUCCESS) {  /*we found a node with no class.  Impossible.! */
                        return (error_code);
                }

 /*               printf("found %s of class %s\n",propname,propclass); */

                if (strstr(propclass,"fan-tachometer"))
                    process_individual_fan(childh,propname);
                if (strstr(propclass,"temperature-sensor"))
                    process_temperature_sensor(childh,propname);
                if (strstr(propclass,"digital-sensor"))
                    process_digital_sensor(childh,propname);
/*
                if (strstr(propclass,"led"))
                    process_led(childh,propname);
                if (strstr(propclass,"i2c"))
                    process_i2c(childh,propname);
                if (strstr(propclass,"switch"))
                    process_switch(childh,propname);
                if (strstr(propclass,"gpio"))
                    process_gpio(childh,propname); 
*/


                /* look for children of children (note, this is recursive) */
 
                if (process_sensors(childh) == PICL_SUCCESS) {
                        return (PICL_SUCCESS);
                }

                /* get next child node at this level*/
                error_code = picl_get_propval_by_name(childh, PICL_PROP_PEER,
                                        &nexth, sizeof (picl_nodehdl_t));
                if (error_code != PICL_SUCCESS) {/* no more children - buh bye*/
                        return (error_code);
                }
                childh = nexth;
        }
        return (error_code);
}
#endif */
/* ******** end of picld sensor procedures * */
#endif /* solaris2 */

static void
_sensor_load(clock_t t)
{
#ifdef solaris2
int i,j;
int typ;
int temp;
int other;
int er_code;
char *fantypes[]={"CPU","PWR","AFB"};
kstat_ctl_t *kc;
kstat_t *kp;
envctrl_fan_t *fan_info;
envctrl_ps_t *power_info;
envctrl_encl_t *enc_info;

#ifdef HAVE_PICL_H
    picl_errno_t     error_code;
    picl_nodehdl_t  rooth;
#endif 

DEBUGMSG(("ucd-snmp/lmSensors", "Reading the sensors\n"));

/* initialize the array */
    for (i = 0; i < N_TYPES; i++){
        sensor_array[i].n = 0;
        for (j=0; j < MAX_SENSORS; j++){
            sensor_array[i].sensor[j].name[0] = '\0';
            sensor_array[i].sensor[j].value = 0;
             }
        } /*end for i*/

/* try picld (if supported), if that doesn't work, try kstat */
#ifdef HAVE_PICL_H 

er_code = picl_initialize();

if (er_code == PICL_SUCCESS) {

    error_code = picl_get_root(&rooth);

    if (error_code != PICL_SUCCESS) {
        DEBUGMSG(("ucd-snmp/lmSensors", "picld couldn't get root error code->%d\n",error_code));
        }
    else{
        error_code = process_sensors(rooth);

        if (error_code != 255) 
            DEBUGMSG(("ucd-snmp/lmSensors", "picld had an internal problem error code->%d\n",error_code));
        } /* end else */


    picl_shutdown();

} 
/* end of IFDEF for picld goes here */

else{  /* try kstat instead */

    DEBUGMSG(("ucd-snmp/lmSensors", "picld couldn't initialize because error code->%d\n",er_code));

DEBUGMSG(("ucd-snmp/lmSensors", "couldn't initialize picld, trying kstat"));

#endif  /* end of picld section */
/* initialize kstat */

kc = kstat_open();
if (kc == 0) {
    DEBUGMSG(("ucd-snmp/lmSensors", "couldn't open kstat"));
    } /* endif kc */
else{
    kp = kstat_lookup(kc, ENVCTRL_MODULE_NAME, 0, ENVCTRL_KSTAT_FANSTAT);
    if (kp == 0) {
        DEBUGMSGTL(("ucd-snmp/lmSensors", "couldn't lookup fan kstat"));
        } /* endif lookup fans */
    else{
        if (kstat_read(kc, kp, 0) == -1) {
            DEBUGMSGTL(("ucd-snmp/lmSensors", "couldn't read fan kstat"));
            } /* endif kstatread fan */
        else{
            typ = 1;
            fan_info = (envctrl_fan_t *) kp->ks_data;
            sensor_array[typ].n = kp->ks_ndata;
            for (i=0; i < kp->ks_ndata; i++){
                DEBUGMSG(("ucd-snmp/lmSensors", "found instance %d fan type %d speed %d OK %d bustedfan %d\n",
                    fan_info->instance, fan_info->type,fan_info->fanspeed,fan_info->fans_ok,fan_info->fanflt_num));
                sensor_array[typ].sensor[i].value = fan_info->fanspeed;
                snprintf(sensor_array[typ].sensor[i].name,(MAX_NAME - 1),
                   "fan type %s number %d",fantypes[fan_info->type],fan_info->instance);
                sensor_array[typ].sensor[i].name[MAX_NAME - 1] = '\0';
                fan_info++;
                } /* end for fan_info */
            } /* end else kstatread fan */
        } /* end else lookup fans*/


    kp = kstat_lookup(kc, ENVCTRL_MODULE_NAME, 0, ENVCTRL_KSTAT_PSNAME);
    if (kp == 0) {
        DEBUGMSGTL(("ucd-snmp/lmSensors", "couldn't lookup power supply kstat"));
        } /* endif lookup power supply */
    else{
        if (kstat_read(kc, kp, 0) == -1) {
            DEBUGMSGTL(("ucd-snmp/lmSensors", "couldn't read power supply kstat"));
            } /* endif kstatread fan */
        else{
            typ = 2;
            power_info = (envctrl_ps_t *) kp->ks_data;
            sensor_array[typ].n = kp->ks_ndata;
            for (i=0; i < kp->ks_ndata; i++){
                DEBUGMSG(("ucd-snmp/lmSensors", "found instance %d psupply temp %d %dW OK %d share %d limit %d\n",
                    power_info->instance, power_info->ps_tempr,power_info->ps_rating,
                    power_info->ps_ok,power_info->curr_share_ok,power_info->limit_ok));
                sensor_array[typ].sensor[i].value = power_info->ps_tempr;
                snprintf(sensor_array[typ].sensor[i].name,(MAX_NAME-1),
                         "power supply %d",power_info->instance);
                sensor_array[typ].sensor[i].name[MAX_NAME - 1] = '\0';
                power_info++;
                } /* end for power_info */
            } /* end else kstatread power supply */
        } /* end else lookup power supplies*/

    kp = kstat_lookup(kc, ENVCTRL_MODULE_NAME, 0, ENVCTRL_KSTAT_ENCL);
    if (kp == 0) {
        DEBUGMSGTL(("ucd-snmp/lmSensors", "couldn't lookup enclosure kstat"));
        } /* endif lookup enclosure */
    else{
        if (kstat_read(kc, kp, 0) == -1) {
            DEBUGMSGTL(("ucd-snmp/lmSensors", "couldn't read enclosure kstat"));
            } /* endif kstatread enclosure */
        else{
            enc_info = (envctrl_encl_t *) kp->ks_data; 
            temp = 0;
            other = 0;
            for (i=0; i < kp->ks_ndata; i++){
               switch (enc_info->type){
               case ENVCTRL_ENCL_FSP:
                   DEBUGMSG(("ucd-snmp/lmSensors", "front panel value %d\n",enc_info->value));
                   typ = 3; /* misc */
                   sensor_array[typ].sensor[other].value = enc_info->value;
                   strncpy(sensor_array[typ].sensor[other].name,"FSP",MAX_NAME-1);
                   sensor_array[typ].sensor[other].name[MAX_NAME-1]='\0'; /* null terminate */
                   other++;
                   break;
               case ENVCTRL_ENCL_AMBTEMPR:
                   DEBUGMSG(("ucd-snmp/lmSensors", "ambient temp %d\n",enc_info->value));
                   typ = 0; /* temperature sensor */
                   sensor_array[typ].sensor[temp].value = enc_info->value;
                   strncpy(sensor_array[typ].sensor[temp].name,"Ambient",MAX_NAME-1);
                   sensor_array[typ].sensor[temp].name[MAX_NAME-1]='\0'; /* null terminate */
                   temp++;
                   break;
               case ENVCTRL_ENCL_BACKPLANE4:
                   DEBUGMSG(("ucd-snmp/lmSensors", "There is a backplane4\n"));
                   typ = 3; /* misc */
                   sensor_array[typ].sensor[other].value = enc_info->value;
                   strncpy(sensor_array[typ].sensor[other].name,"Backplane4",MAX_NAME-1);
                   sensor_array[typ].sensor[other].name[MAX_NAME-1]='\0'; /* null terminate */
                   other++;
                   break;
               case ENVCTRL_ENCL_BACKPLANE8:
                   DEBUGMSG(("ucd-snmp/lmSensors", "There is a backplane8\n"));
                   typ = 3; /* misc */
                   sensor_array[typ].sensor[other].value = enc_info->value;
                   strncpy(sensor_array[typ].sensor[other].name,"Backplane8",MAX_NAME-1);
                   sensor_array[typ].sensor[other].name[MAX_NAME-1]='\0'; /* null terminate */
                   other++;
                   break;
               case ENVCTRL_ENCL_CPUTEMPR:
                   DEBUGMSG(("ucd-snmp/lmSensors", "CPU%d temperature %d\n",enc_info->instance,enc_info->value));
                   typ = 0; /* temperature sensor */
                   sensor_array[typ].sensor[temp].value = enc_info->value;
                   snprintf(sensor_array[typ].sensor[temp].name,MAX_NAME,"CPU%d",enc_info->instance);
                   sensor_array[typ].sensor[other].name[MAX_NAME-1]='\0'; /* null terminate */
                   temp++;
                   break;
               default:
                   DEBUGMSG(("ucd-snmp/lmSensors", "unknown element instance &d type &d value %d\n",
                       enc_info->instance, enc_info->type, enc_info->value));
                   break;
               } /* end switch */
               enc_info++;
               } /* end for enc_info */
               sensor_array[3].n = other;
               sensor_array[0].n = temp;
            } /* end else kstatread enclosure */
        } /* end else lookup enclosure*/

    kstat_close(kc);
#ifdef HAVE_PICL_H
    } /* end else kc not needed if no picld*/
#endif
} /* end else kstat */
#else /* solaris2 */

    const sensors_chip_name *chip;
    const sensors_feature_data *data;
    int             chip_nr = 0;

    int             i;
    for (i = 0; i < N_TYPES; i++)
        sensor_array[i].n = 0;

    while (chip = sensors_get_detected_chips(&chip_nr)) {
	int             a = 0;
	int             b = 0;
        while (data = sensors_get_all_features(*chip, &a, &b)) {
            char           *label = NULL;
            double          val;

            if ((data->mode & SENSORS_MODE_R) &&
                (data->mapping == SENSORS_NO_MAPPING) &&
                !sensors_get_label(*chip, data->number, &label) &&
                !sensors_get_feature(*chip, data->number, &val)) {
                int             type = -1;
                float           mul;
                _sensor_array  *array;


                if (strstr(label, "V")) {
                    type = 2;
                    mul = 1000.0;
                }
                if (strstr(label, "fan") || strstr(label, "Fan")) {
                    type = 1;
                    mul = 1.0;
                }
                if (strstr(label, "temp") || strstr(label, "Temp")) {
                    type = 0;
                    mul = 1000.0;
                }
                if (type == -1) {
                    type = 3;
                    mul = 1000.0;
                }

                array = &sensor_array[type];
                if (MAX_SENSORS <= array->n) {
                    snmp_log(LOG_ERR, "too many sensors. ignoring %s\n", label);
                    break;
                }
                strncpy(array->sensor[array->n].name, label, MAX_NAME);
                array->sensor[array->n].value = (int) (val * mul);
                DEBUGMSGTL(("sensors","sensor %d, value %d\n",
                            array->sensor[array->n].name,
                            array->sensor[array->n].value));
                array->n++;
            }
	    if (label) {
		free(label);
		label = NULL;
	    }
        }
    }
#endif /*else solaris2 */
    timestamp = t;
}
