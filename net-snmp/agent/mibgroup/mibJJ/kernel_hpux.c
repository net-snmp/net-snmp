#include <sys/unistd.h>
#include <fcntl.h>
#include <sys/mib.h>
#include <sys/ioctl.h>

static int fd = -1;

long hpux_read_stat   (char * data, int size, int grp_id)
{
    int len;
    struct nmparms nmparms;

	/*
	 * Open the management socket
	 *   (if not already open)
	 */

    if ( fd == -1 ) {
	fd = open("/dev/netman", O_RDONLY);
	if ( fd == -1 ) {
	    perror("open");
	    return -1;
	}
    }

    len = size;
    nmparms.objid  = grp_id;
    nmparms.buffer = data;
    nmparms.len    = &len;

    if ( ioctl( fd, NMIOGET, &nmparms ) == -1 ) {
	perror("ioctl");
	close( fd );
	return -1;
    }
    return 0;
}
