#ifndef NOTIFICATION_LOG_H
#define NOTIFICATION_LOG_H
#include "agent_handler.h"

/*
 * function declarations 
 */
void init_notification_log(void);
NodeHandler     nlmLogTable_handler;

/*
 * column number definitions for table nlmLogTable 
 */
#define COLUMN_NLMLOGINDEX		1
#define COLUMN_NLMLOGTIME		2
#define COLUMN_NLMLOGDATEANDTIME		3
#define COLUMN_NLMLOGENGINEID		4
#define COLUMN_NLMLOGENGINETADDRESS		5
#define COLUMN_NLMLOGENGINETDOMAIN		6
#define COLUMN_NLMLOGCONTEXTENGINEID		7
#define COLUMN_NLMLOGCONTEXTNAME		8
#define COLUMN_NLMLOGNOTIFICATIONID		9

#endif /* NOTIFICATION_LOG_H */
