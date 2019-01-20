#ifndef WINSERVICE_H
#define WINSERVICE_H

/* Windows Service related function declarations. */

#ifdef __cplusplus
extern          "C" {
#elif 0
}
#endif                          /*  */

/*
 * Define Constants for Register, De-register , Run As service or Console mode
 */
#define REGISTER_SERVICE 0
#define UN_REGISTER_SERVICE 1
#define RUN_AS_SERVICE 2
#define RUN_AS_CONSOLE 3


/*
 * Error levels returned when registering or unregistering the service
 */
#define SERVICE_ERROR_NONE 0
#define SERVICE_ERROR_SCM_OPEN 1        /* Can not open SCM */
#define SERVICE_ERROR_CREATE_SERVICE 2  /* Can not create service */
#define SERVICE_ERROR_CREATE_REGISTRY_ENTRIES 3 /* Can not create registry entries */
#define SERVICE_ERROR_OPEN_SERVICE 4    /* Can not open service (service does not exist) */

/*
 * Define Message catalog ID
 * MessageId: DISPLAY_MSG
 * MessageText:  %1.
 */
#define DISPLAY_MSG                      0x00000064L

/*
 * Hint Value to SCM to wait before sending successive commands to service
 */
#define SCM_WAIT_INTERVAL 7000

/*
 * Define Generic String Size, to hold Error or Information
 */
#define MAX_STR_SIZE  1024

/*
 * Delcare Global variables, which are visible to other modules
 */
extern BOOL     g_fRunningAsService;

/*
 * Input parameter structure to thread
 */
typedef struct _InputParams {
    DWORD           Argc;
    char          **Argv;
} InputParams;

/*
 * Define Service Related functions
 */

/*
 * To register application as windows service with SCM
 */
int             RegisterService(const char *lpszServiceName,
                                const char *lpszServiceDisplayName,
                                const char *lpszServiceDescription,
                                InputParams *StartUpArg, int quiet);

/*
 * To unregister service
 */
int             UnregisterService(const char *lpszServiceName, int quiet);

/*
 * To parse command line for startup option
 */
int             ParseCmdLineForServiceOption(int argc, char *argv[],
                                             int *quiet);

/*
 * To write to windows event log
 */
void            WriteToEventLog(WORD wType, const char *pszFormat, ...);

/*
 * To display generic windows error
 */
void            DisplayError(const char *pszTitle, int quite);

/*
 * Service Main function,  Which will spawn a thread, and calls the
 * Service run part
 */
void WINAPI     ServiceMain(DWORD argc, char *argv[]);

/*
 * To start Service
 */

BOOL            RunAsService(int (*ServiceFunction)(int, char **));

/*
 * Call back function to process SCM Requests
 */
void WINAPI     ControlHandler(DWORD dwControl);

/*
 * To Stop the service
 */
void            ProcessServiceStop(void);

/*
 * To Pause service
 */
void            ProcessServicePause(void);

/*
 * To Continue paused service
 */
void            ProcessServiceContinue(void);

/*
 * To send Current Service status to SCM when INTERROGATE command is sent
 */
void            ProcessServiceInterrogate(void);

/*
 * To allocate and Set security descriptor
 */
BOOL            SetSimpleSecurityAttributes(SECURITY_ATTRIBUTES
                                            *pSecurityAttr);

/*
 * To free Security Descriptor
 */
void            FreeSecurityAttributes(SECURITY_ATTRIBUTES
                                       *pSecurityAttr);

/*
 * TheadFunction - To spawan as thread - Invokes registered service function
 */
unsigned WINAPI ThreadFunction(void *lpParam);

/*
 * Service STOP function registration with this framewrok
 * * this function must be invoked before calling RunAsService
 */
void            RegisterStopFunction(void (*StopFunc)(void));

#if 0
{
#elif defined(__cplusplus)
}
#endif                          /*  */
#endif                          /* WINSERVICE_H */
