/************************************************************
 * $Id$
 *
 * A simple application that uses various container types
 * to store and retrieve data.
 *
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/library/container.h>
#include <string.h>

/*
 * forward declare functions we will use.
 */
static int data_cmp(const void *lhs, const void *rhs);
static int data_print(void *data_ptr, void *arg);
static void test_container( netsnmp_container *container );

/************************************************************
 */
int main(int argc, char ** argv)
{
    /*
     * define an array of container types we will test.
     */
    const char * types[] = { "ssll_container", "binary_array" };
    int size = sizeof(types)/sizeof(char *);
    int i;
    netsnmp_container *container;

    /*
     * Initialize the container library
     */
    netsnmp_container_init_list();
    netsnmp_container_ssll_init();

    /*
     * loop through and get a container and test it.
     */
    for(i = 0; i < size; ++i) {
        /*
         * find the container
         */
        printf("testing %s containers\n", types[i]);
        container = netsnmp_container_find(types[i]);
        if(NULL == container) {
            fprintf(stderr, "Couldn't find a %s container.\n", types[i]);
            exit(1);
        }

        /*
         * set up our data comparison routine (see below)
         */
        container->compare = data_cmp;
        
        /*
         * insert some data, print contents and delete container
         */
        test_container( container );
    }

    return (0);
} /* main() */

/************************************************************
 *
 * this routine takes a pointer to a container, and will
 * manipulate the container. The idea here is that this
 * routine doesn't care what kind of container is used.
 * The output should be the same for every container type.
 */
static void
test_container( netsnmp_container *container )
{
    /*
     * define some simple data
     */
    static const char * data[] = { "Sunday", "Monday", "Tuesday", "Wednesday",
                             "Thursday", "Friday", "Saturday" };
    static int data_len = sizeof(data)/sizeof(char*);
    char * ip;
    int i;

    /*
     * insert data
     */
    for(i = 0; i < data_len; ++i)
        CONTAINER_INSERT(container, strdup(data[i]));

    /*
     * go through list
     */
    ip = CONTAINER_FIRST(container);
    printf("Find first = %s\n",ip);
    while( ip ) {
        ip = CONTAINER_NEXT(container,ip);
        printf("Find next = %s\n",ip);
    }

    /*
     * find a particular item
     */
    ip = CONTAINER_FIND(container, data[2]);
    printf("Find %s = %s\n", data[2], ip);

    /*
     * print (and free while were at it) contents
     */
    CONTAINER_FOR_EACH(container, (netsnmp_container_obj_func *)data_print,
                       NULL);

    /*
     * release container
     */
    CONTAINER_FREE(container);
}


/************************************************************
 * compare container data.
 *
 * This compare callback is used for comparisons between two
 * items in the container. A void pointer parameter is
 * provided for the left and right hand side of the comparison.
 * Cast these pointers to your data type and perform the
 * comparison.
 *
 * Return:
 *   -1 if lhs < rhs,
 *    0 if lhs == rhs
 *    1 if lhs > rhs.
 */
static int
data_cmp(const void *lhs, const void *rhs)
{
    /*
     * In our simple example, our container data
     * is character strings, so we can use strncmp
     * to do the work.
     */
    const char *context_l = (const char *) lhs;
    const char *context_r = (const char *) rhs;

    return strcmp(context_l, context_r);
}

/************************************************************
 * print a data item.
 *
 * this function is passed to the FOR_EACH routine, and will
 * be called for each item in the array.
 *
 * data_ptr points to the actual data.
 * arg is the 3rd parameter from the CONTAINER_FOR_EACH call.
 */
static int
data_print(void *data_ptr, void *arg)
{
    char *data = (char *)data_ptr;

    printf("%s\n", data);
    free(data);
}
    
