/*
 * Windows Service related function definitions
 * By Raju Krishnappa(raju_krishnappa@yahoo.com)
 *
 */

#ifdef WIN32

#include <windows.h>
#include <tchar.h>

#include <stdio.h>		/* sprintf */
#include <process.h>		/* beginthreadex  */

#include <net-snmp/library/winservice.h>

#ifdef mingw32 /* MinGW doesn't fully support exception handling. */

#define TRY if(1)
#define LEAVE goto labelFIN
#define FINALLY do { \
labelFIN: \
} while(0); if(1)

#else

#define TRY __try
#define LEAVE __leave
#define FINALLY __finally

#endif /* mingw32 */

    /*
     * External global variables used here
     */

    /*
     * Application Name 
     * This should be declared by the application, which wants to register as
     * windows service
     */
extern LPTSTR g_szAppName;

    /*
     * Declare global variable
     */

    /*
     * Flag to indicate whether process is running as Service 
     */
BOOL g_fRunningAsService = FALSE;

    /*
     * Variable to maintain Current Service status 
     */
static SERVICE_STATUS ServiceStatus;

    /*
     * Service Handle 
     */
static SERVICE_STATUS_HANDLE hServiceStatus = 0L;

    /*
     * Service Table Entry 
     */
SERVICE_TABLE_ENTRY ServiceTableEntry[] = {
  {NULL, ServiceMain},		/* Service Main function */
  {NULL, NULL}
};

    /*
     * Handle to Thread, to implement Pause, Resume and Stop functions
     */
static HANDLE hServiceThread = NULL;	/* Thread Handle */

    /*
     * Holds calling partys Function Entry point, that should start
     * when entering service mode
     */
static INT (*ServiceEntryPoint) (INT Argc, LPTSTR Argv[]) = 0L;

    /*
     * To hold Stop Function address, to be called when STOP request
     * received from the SCM
     */
static VOID (*StopFunction) (VOID) = 0L;

    /*
     * To register as Windows Service with SCM(Service Control Manager)
     * Input - Service Name, Service Display Name,Service Description and
     * Service startup arguments
     */
VOID
RegisterService (LPCTSTR lpszServiceName, LPCTSTR lpszServiceDisplayName,
		 LPCTSTR lpszServiceDescription,
		 InputParams * StartUpArg) /* Startup argument to the service */
{
  TCHAR szServicePath[MAX_PATH];	/* To hold module File name */
  TCHAR MsgErrorString[MAX_STR_SIZE];	/* Message or Error string */
  TCHAR szServiceCommand[MAX_PATH + 9];	/* Command to execute */
  SC_HANDLE hSCManager = NULL;
  SC_HANDLE hService = NULL;
  TCHAR szRegAppLogKey[] =
    "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\";
  TCHAR szRegKey[512];
  HKEY hKey = NULL;		/* Key to registry entry */
  HKEY hParamKey = NULL;	/* To store startup parameters */
  DWORD dwData;			/* Type of logging supported */
  DWORD i, j;			/* Loop variables */
  GetModuleFileName (NULL, szServicePath, MAX_PATH);
  TRY
  {

    /*
     * Open Service Control Manager handle 
     */
    hSCManager = OpenSCManager (NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hSCManager == NULL)
      {
	DisplayError (_T ("Can't open SCM"));
	LEAVE;
      }

    /*
     * Generate the Command to be executed by SCM 
     */
    _stprintf (szServiceCommand, "%s %s", szServicePath, _T ("-service"));

    /*
     * Create the Desired service 
     */
    hService = CreateService (hSCManager, lpszServiceName, lpszServiceDisplayName,
			SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
			SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, szServiceCommand,
			      NULL,	/* load-order group */
			      NULL,	/* group member tag */
			      NULL,	/* dependencies */
			      NULL,	/* account */
			      NULL);	/* password */
    if (hService == NULL)
      {
	_stprintf (MsgErrorString, "%s %s",
		   _T ("Can't Create Service"), lpszServiceDisplayName);
	DisplayError (MsgErrorString);
	LEAVE;
      }

    /*
     * Create registry entries for EventLog 
     */
    /*
     * Create registry Application event log key 
     */
    _tcscpy (szRegKey, szRegAppLogKey);
    _tcscat (szRegKey, lpszServiceName);

    /*
     * Create registry key 
     */
    if (RegCreateKey (HKEY_LOCAL_MACHINE, szRegKey, &hKey) != ERROR_SUCCESS)
      {
	_stprintf (MsgErrorString, "%s %s",
		   _T ("Unable to create registry entries"), lpszServiceDisplayName);
	DisplayError (MsgErrorString);
	LEAVE;
      }

    /*
     * Add Event ID message file name to the 'EventMessageFile' subkey 
     */
    RegSetValueEx (hKey, "EventMessageFile", 0, REG_EXPAND_SZ,
		   (CONST BYTE *) szServicePath,
		   _tcslen (szServicePath) + sizeof (TCHAR));

    /*
     * Set the supported types flags. 
     */
    dwData = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
    RegSetValueEx (hKey, "TypesSupported", 0, REG_DWORD,
		   (CONST BYTE *) & dwData, sizeof (DWORD));

    /*
     * Close Registry key 
     */
    RegCloseKey (hKey);

    /*
     * Set Service Description String  and save startup parameters if present
     */
    if (lpszServiceDescription != NULL || StartUpArg->Argc > 2)
      {
	/*
	 * Create Registry Key path 
	 */
	_tcscpy (szRegKey, _T ("SYSTEM\\CurrentControlSet\\Services\\"));
	_tcscat (szRegKey, g_szAppName);
	hKey = NULL;

	/*
	 * Open Registry key using Create and Set access. 
	 */
	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, szRegKey, 0, KEY_WRITE,
			  &hKey) != ERROR_SUCCESS)
	  {
	    _stprintf (MsgErrorString, "%s %s",
		       _T ("Unable to create registry entries"),
		       lpszServiceDisplayName);
	    DisplayError (MsgErrorString);
	    LEAVE;
	  }

	/*
	 * Create description subkey and the set value 
	 */
	if (lpszServiceDescription != NULL)
	  {
	    if (RegSetValueEx (hKey, "Description", 0, REG_SZ,
			       (CONST BYTE *) lpszServiceDescription,
			       _tcslen (lpszServiceDescription) +
			       sizeof (TCHAR)) != ERROR_SUCCESS)
	      {
		_stprintf (MsgErrorString, "%s %s",
			   _T ("Unable to create registry entries"),
			   lpszServiceDisplayName);
		DisplayError (MsgErrorString);
		LEAVE;
	      };
	  }

	/*
	 * Save startup arguments if they are present 
	 */
	if (StartUpArg->Argc > 2)
	  {
	    /*
	     * Create Subkey parameters 
	     */
	    if (RegCreateKeyEx
		(hKey, "Parameters", 0, NULL,
		 REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL,
		 &hParamKey, NULL) != ERROR_SUCCESS)
	      {
		_stprintf (MsgErrorString, "%s %s",
			   _T ("Unable to create registry entries"),
			   lpszServiceDisplayName);
		DisplayError (MsgErrorString);
		LEAVE;
	      }

	    /*
	     * Save parameters 
	     */

	    /*
	     * Loop through arguments 
	     */
	    for (i = 2, j = 1; i < StartUpArg->Argc; i++, j++)
	      {
		_stprintf (szRegKey, "%s%d", _T ("Param"), j);

		/*
		 * Create registry key 
		 */
		if (RegSetValueEx
		    (hParamKey, szRegKey, 0, REG_SZ,
		     (CONST BYTE *) StartUpArg->Argv[i],
		     _tcslen (StartUpArg->Argv[i]) +
		     sizeof (TCHAR)) != ERROR_SUCCESS)
		  {
		    _stprintf (MsgErrorString, "%s %s",
			       _T ("Unable to create registry entries"),
			       lpszServiceDisplayName);
		    DisplayError (MsgErrorString);
		    LEAVE;
		  };
	      }
	  }

	/*
	 * Everything is set, delete hKey 
	 */
	RegCloseKey (hParamKey);
	RegCloseKey (hKey);
      }

    /*
     * Ready to Log messages 
     */

    /*
     * Successfully registered as service 
     */
    _stprintf (MsgErrorString, "%s %s", lpszServiceName,
	       _T ("- Successfully registered as Service"));

    /*
     * Log message to eventlog 
     */
    WriteToEventLog (EVENTLOG_INFORMATION_TYPE, MsgErrorString);
  }

  FINALLY
  {
    if (hSCManager)
      CloseServiceHandle (hSCManager);
    if (hService)
      CloseServiceHandle (hService);
    if (hKey)
      RegCloseKey (hKey);
    if (hParamKey)
      RegCloseKey (hParamKey);
  }
}

    /*
     * Unregister the service with the  Windows SCM 
     * Input - ServiceName
     */
VOID
UnregisterService (LPCSTR lpszServiceName)
{
  TCHAR MsgErrorString[MAX_STR_SIZE];	/* Message or Error string */
  SC_HANDLE hSCManager = NULL;	/* SCM handle */
  SC_HANDLE hService = NULL;	/* Service Handle */
  SERVICE_STATUS sStatus;
  TCHAR szRegAppLogKey[] =
    "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\";
  TCHAR szRegKey[512];
/*  HKEY hKey = NULL;		?* Key to registry entry */
  TRY
  {
    /*
     * Open Service Control Manager 
     */
    hSCManager = OpenSCManager (NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hSCManager == NULL)
      {
	MessageBox (NULL, _T ("Can't open SCM"), g_szAppName, MB_ICONHAND);
	LEAVE;
      }

    /*
     * Open registered service 
     */
    hService = OpenService (hSCManager, lpszServiceName, SERVICE_ALL_ACCESS);
    if (hService == NULL)
      {
	_stprintf (MsgErrorString, "%s %s", _T ("Can't open service"),
		   lpszServiceName);
	MessageBox (NULL, MsgErrorString, g_szAppName, MB_ICONHAND);
	LEAVE;
      }

    /*
     * Query service status 
     * If running stop before deleting 
     */
    if (QueryServiceStatus (hService, &sStatus))
      {
	if (sStatus.dwCurrentState == SERVICE_RUNNING
	    || sStatus.dwCurrentState == SERVICE_PAUSED)
	  {
	    ControlService (hService, SERVICE_CONTROL_STOP, &sStatus);
	  }
      };

    /*
     * Delete the service  
     */
    if (DeleteService (hService) == FALSE)
      {
	_stprintf (MsgErrorString, "%s %s", _T ("Can't delete service"),
		   lpszServiceName);

	/*
	 * Log message to eventlog 
	 */
	WriteToEventLog (EVENTLOG_INFORMATION_TYPE, MsgErrorString);
	LEAVE;
      }

    /*
     * Log "Service deleted successfully " message to eventlog
     */
    _stprintf (MsgErrorString, "%s %s", lpszServiceName, _T ("- Service deleted"));
    WriteToEventLog (EVENTLOG_INFORMATION_TYPE, MsgErrorString);

    /*
     * Delete registry entries for EventLog 
     */
    _tcscpy (szRegKey, szRegAppLogKey);
    _tcscat (szRegKey, lpszServiceName);
    RegDeleteKey (HKEY_LOCAL_MACHINE, szRegKey);
  }

  /*
   * Delete the handles 
   */
  FINALLY
  {
    if (hService)
      CloseServiceHandle (hService);
    if (hSCManager)
      CloseServiceHandle (hSCManager);
  }
}

    /*
     * To write message to Windows Event log
     * Input - Event Type, Message string
     */
VOID
WriteToEventLog (WORD wType, LPCTSTR pszFormat, ...)
{
  TCHAR szMessage[512];
  LPTSTR LogStr[1];
  va_list ArgList;
  HANDLE hEventSource = NULL;
  va_start (ArgList, pszFormat);
  _vstprintf (szMessage, pszFormat, ArgList);
  va_end (ArgList);
  LogStr[0] = szMessage;
  hEventSource = RegisterEventSource (NULL, g_szAppName);
  if (hEventSource == NULL)
    return;
  ReportEvent (hEventSource, wType, 0,
	       DISPLAY_MSG,	/* To Just output the text to event log */
	       NULL, 1, 0, LogStr, NULL);
  DeregisterEventSource (hEventSource);
  if (!g_fRunningAsService)
    {
      /*
       * We are running in command mode, output the string 
       */
      _putts (szMessage);
    }
}

    /*
     * Pre-process the second command-line argument from the user. 
     *     Service related options are:
     *     -register       - registers the service
     *     -unregister     - unregisters the service
     *     -service        - run as service
     *     other command-line arguments are ignored here.
     *
     * Return: Type indicating the option specified
     */
INT
ParseCmdLineForServiceOption (int argc, TCHAR * argv[])
{
  int nReturn = RUN_AS_CONSOLE;	/* Defualted to run as console */
  if (argc >= 2)
    {

      /*
       * second argument present 
       */
      if (lstrcmpi (_T ("-register"), argv[1]) == 0)
	{
	  nReturn = REGISTER_SERVICE;
	}

      else if (lstrcmpi (_T ("-unregister"), argv[1]) == 0)
	{
	  nReturn = UN_REGISTER_SERVICE;
	}

      else if (lstrcmpi (_T ("-service"), argv[1]) == 0)
	{
	  nReturn = RUN_AS_SERVICE;
	}
    }
  return nReturn;
}

    /*
     * To Display an error message describing the last system error
     * message, along with a title passed as a parameter.
     */
VOID
DisplayError (LPCTSTR pszTitle)
{
  LPVOID pErrorMsg;

  /*
   * Build Error String 
   */
  FormatMessage (FORMAT_MESSAGE_ALLOCATE_BUFFER |
		 FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError (),
		 MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
		 (LPTSTR) & pErrorMsg, 0, NULL);
  if (g_fRunningAsService != FALSE)
    {
      WriteToEventLog (EVENTLOG_ERROR_TYPE, pErrorMsg);
    }

  else
    {
      MessageBox (NULL, pErrorMsg, pszTitle, MB_ICONHAND);
    }
  LocalFree (pErrorMsg);
}

    /*
     *  To update current service status 
     *  Sends the current service status to the SCM. Also updates
     *  the global service status structure.
     */
static BOOL
UpdateServiceStatus (DWORD dwStatus, DWORD dwErrorCode, DWORD dwWaitHint)
{
  DWORD static dwCheckpoint = 1;
  DWORD dwControls = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE;
  if (g_fRunningAsService == FALSE)
    return FALSE;
  ZeroMemory (&ServiceStatus, sizeof (ServiceStatus));
  ServiceStatus.dwServiceType = SERVICE_WIN32;
  ServiceStatus.dwCurrentState = dwStatus;
  ServiceStatus.dwWaitHint = dwWaitHint;
  if (dwErrorCode)
    {
      ServiceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
      ServiceStatus.dwServiceSpecificExitCode = dwErrorCode;
    }

  /*
   * special cases that depend on the new state 
   */
  switch (dwStatus)
    {
    case SERVICE_START_PENDING:
      dwControls = 0;
      break;
    case SERVICE_RUNNING:
    case SERVICE_STOPPED:
      dwCheckpoint = 0;
      break;
    }
  ServiceStatus.dwCheckPoint = dwCheckpoint++;
  ServiceStatus.dwControlsAccepted = dwControls;
  return ReportCurrentServiceStatus ();
}

    /*
     * Reports current Service status to SCM
     */
static BOOL
ReportCurrentServiceStatus ()
{
  return SetServiceStatus (hServiceStatus, &ServiceStatus);
}

    /*
     * The ServiceMain function to start service.
     */
VOID WINAPI
ServiceMain (DWORD argc, LPTSTR argv[])
{
  SECURITY_ATTRIBUTES SecurityAttributes;
  DWORD dwThreadId;

  /*
   * Input Arguments to function startup 
   */
  DWORD ArgCount = 0;
  LPTSTR *ArgArray = NULL;
  TCHAR szRegKey[512];
  TCHAR szValue[128];
  DWORD nSize;
  HKEY hParamKey = NULL;	/* To read startup parameters */
  DWORD TotalParams = 0;
  DWORD i;
  InputParams ThreadInputParams;

  /*
   * Build the Input parameters to pass to worker thread 
   */

  /*
   * SCM sends Service Name as first arg, increment to point
   * arguments user specified while starting contorl agent
   */

  /*
   * Read registry parameter 
   */
  ArgCount = 1;

  /*
   * Create Registry Key path 
   */
  _stprintf (szRegKey, "%s%s\\%s",
	     _T ("SYSTEM\\CurrentControlSet\\Services\\"), g_szAppName,
	     "Parameters");
  if (RegOpenKeyEx
      (HKEY_LOCAL_MACHINE, szRegKey, 0, KEY_ALL_ACCESS, &hParamKey) == ERROR_SUCCESS)
    {

      /*
       * Read startup Configuration information 
       */
      /*
       * Find number of subkeys inside parameters 
       */
      if (RegQueryInfoKey (hParamKey, NULL, NULL, 0,
	   NULL, NULL, NULL, &TotalParams,
	   NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
	{
	  if (TotalParams != 0)
	    {
	      ArgCount += TotalParams;

	      /*
	       * Allocate memory to hold strings 
	       */
	      ArgArray = (LPTSTR *) malloc (sizeof (LPTSTR) * ArgCount);

	      /*
	       * Copy first argument 
	       */
	      ArgArray[0] = _tcsdup (argv[0]);
	      for (i = 1; i <= TotalParams; i++)
		{

		  /*
		   * Create Subkey value name 
		   */
		  _stprintf (szRegKey, "%s%d", "Param", i);

		  /*
		   * Set size 
		   */
		  nSize = 128;
		  RegQueryValueEx (hParamKey, szRegKey, 0, NULL,
				   (LPBYTE) & szValue, &nSize);
		  ArgArray[i] = _tcsdup (szValue);
		}
	    }
	}
      RegCloseKey (hParamKey);
    }
  if (ArgCount == 1)
    {

      /*
       * No statup agrs are given 
       */
      ThreadInputParams.Argc = argc;
      ThreadInputParams.Argv = argv;
    }

  else
    {
      ThreadInputParams.Argc = ArgCount;
      ThreadInputParams.Argv = ArgArray;
    }

  /*
   * Register Service Control Handler 
   */
  hServiceStatus = RegisterServiceCtrlHandler (g_szAppName, ControlHandler);
  if (hServiceStatus == 0)
    {
      WriteToEventLog (EVENTLOG_ERROR_TYPE,
		       _T ("RegisterServiceCtrlHandler failed"));
      return;
    }

  /*
   * Update the service status to START_PENDING 
   */
  UpdateServiceStatus (SERVICE_START_PENDING, NO_ERROR, SCM_WAIT_INTERVAL);

  /*
   * Spin of worker thread, which does majority of the work 
   */
  TRY
  {
    if (SetSimpleSecurityAttributes (&SecurityAttributes) == FALSE)
      {
	WriteToEventLog (EVENTLOG_ERROR_TYPE,
			 _T ("Couldn't init security attributes"));
	LEAVE;
      }
    hServiceThread =
      (void *) _beginthreadex (&SecurityAttributes, 0,
			       ThreadFunction,
			       (void *) &ThreadInputParams, 0, &dwThreadId);
    if (hServiceThread == NULL)
      {
	WriteToEventLog (EVENTLOG_ERROR_TYPE, _T ("Couldn't start worker thread"));
	LEAVE;
      }

    /*
     * Set Service Status to Running 
     */
    UpdateServiceStatus (SERVICE_RUNNING, NO_ERROR, SCM_WAIT_INTERVAL);

    /*
     * Wait for termination event and worker thread to
     * * spin down.
     */
    WaitForSingleObject (hServiceThread, INFINITE);
  }
  FINALLY
  {
    /*
     * Release resources 
     */
    UpdateServiceStatus (SERVICE_STOPPED, NO_ERROR, SCM_WAIT_INTERVAL);
    if (hServiceThread)
      CloseHandle (hServiceThread);
    FreeSecurityAttributes (&SecurityAttributes);

    /*
     * Delete allocated argument list 
     */
    if (ArgCount > 1 && ArgArray != NULL)
      {
	/*
	 * Delete all strings 
	 */
	for (i = 0; i < ArgCount; i++)
	  {
	    free (ArgArray[i]);
	  }
	free (ArgArray);
      }
  }
}

    /*
     * Function to start as Windows service
     * The calling party should specify their entry point as input parameter
     * Returns TRUE if the Service is started successfully
     */
BOOL
RunAsService (INT (*ServiceFunction) (INT, LPTSTR *))
{

  /*
   * Set the ServiceEntryPoint 
   */
  ServiceEntryPoint = ServiceFunction;

  /*
   * By default, mark as Running as a service 
   */
  g_fRunningAsService = TRUE;

  /*
   * Initialize ServiceTableEntry table 
   */
  ServiceTableEntry[0].lpServiceName = g_szAppName;	/* Application Name */

  /*
   * Call SCM via StartServiceCtrlDispatcher to run as Service 
   * * If the function returns TRUE we are running as Service, 
   */
  if (StartServiceCtrlDispatcher (ServiceTableEntry) == FALSE)
    {
      g_fRunningAsService = FALSE;

      /*
       * Some other error has occurred. 
       */
      WriteToEventLog (EVENTLOG_ERROR_TYPE,
		       _T ("Couldn't start service - %s"), g_szAppName);
    }
  return g_fRunningAsService;
}

    /*
     * Service control handler function
     * Responds to SCM commands/requests
     * This service handles 4 commands
     * - interrogate, pause, continue and stop.
     */
VOID WINAPI
ControlHandler (DWORD dwControl)
{
  switch (dwControl)
    {
    case SERVICE_CONTROL_INTERROGATE:
      ProcessServiceInterrogate ();
      break;

    case SERVICE_CONTROL_PAUSE:
      ProcessServicePause ();
      break;

    case SERVICE_CONTROL_CONTINUE:
      ProcessServiceContinue ();
      break;

    case SERVICE_CONTROL_STOP:
      ProcessServiceStop ();
      break;
    }
}

    /*
     * To stop the service.
     * If a stop function was registered, invoke it,
     * otherwise terminate the worker thread.
     * After stopping, Service status is set to STOP in 
     * main loop
     */
VOID
ProcessServiceStop (VOID)
{
  UpdateServiceStatus (SERVICE_STOP_PENDING, NO_ERROR, SCM_WAIT_INTERVAL);

  if (StopFunction != NULL)
    {
      (*StopFunction) ();
    }

  else
    {
      TerminateThread (hServiceThread, 0);
    }
}

    /*
     * Returns the current state of the service to the SCM.
     */
VOID
ProcessServiceInterrogate (VOID)
{
  ReportCurrentServiceStatus ();
}

    /*
     * To Create a security descriptor with a NULL ACL, which
     * allows unlimited access. Returns a SECURITY_ATTRIBUTES
     * structure that contains the security descriptor.
     * The structure contains a dynamically allocated security
     * descriptor that must be freed either manually, or by
     * calling FreeSecurityAttributes 
     */
BOOL
SetSimpleSecurityAttributes (SECURITY_ATTRIBUTES * pSecurityAttr)
{
  BOOL fReturn = FALSE;
  SECURITY_DESCRIPTOR *pSecurityDesc = NULL;

  /*
   * If an invalid address is passed as a parameter, return
   * FALSE right away. 
   */
  if (!pSecurityAttr)
    return FALSE;
  pSecurityDesc =
    (SECURITY_DESCRIPTOR *) LocalAlloc (LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
  if (!pSecurityDesc)
    return FALSE;
  fReturn =
    InitializeSecurityDescriptor (pSecurityDesc, SECURITY_DESCRIPTOR_REVISION);
  if (fReturn != FALSE)
    {
      fReturn = SetSecurityDescriptorDacl (pSecurityDesc, TRUE, NULL, FALSE);
    }
  if (fReturn != FALSE)
    {
      pSecurityAttr->nLength = sizeof (SECURITY_ATTRIBUTES);
      pSecurityAttr->lpSecurityDescriptor = pSecurityDesc;
      pSecurityAttr->bInheritHandle = TRUE;
    }

  else
    {
      /*
       * Couldn't initialize or set security descriptor. 
       */
      LocalFree (pSecurityDesc);
    }
  return fReturn;
}

    /*
     * This function Frees the security descriptor, if any was created.
     */
VOID
FreeSecurityAttributes (SECURITY_ATTRIBUTES * pSecurityAttr)
{
  if (pSecurityAttr && pSecurityAttr->lpSecurityDescriptor)
    LocalFree (pSecurityAttr->lpSecurityDescriptor);
}

    /*
     * This function runs in the worker thread
     * until an exit is forced, or until the SCM issues the STOP command.
     * Invokes registered service function
     * Returns when called registered function returns
     *
     * Input:
     *   lpParam contains argc and argv, pass to service main function 
     */
DWORD WINAPI
ThreadFunction (LPVOID lpParam)
{
  InputParams * pInputArg = (InputParams *) lpParam;
  return (*ServiceEntryPoint) (pInputArg->Argc, pInputArg->Argv);
}

    /*
     * This function is called to register an application-specific function
     *   which is invoked when the SCM stops the worker thread.
     */
VOID
RegisterStopFunction (VOID (*StopFunc) (VOID))
{
  StopFunction = StopFunc;
}

    /*
     * SCM pause command invokes this function
     * If the service is not running, this function does nothing.
     * Otherwise, suspend the worker thread and update the status.
     */
VOID
ProcessServicePause (VOID)
{
  if (ServiceStatus.dwCurrentState == SERVICE_RUNNING)
    {
      UpdateServiceStatus (SERVICE_PAUSE_PENDING, NO_ERROR, SCM_WAIT_INTERVAL);

      if (SuspendThread (hServiceThread) != -1)
	{
	  UpdateServiceStatus (SERVICE_PAUSED, NO_ERROR, SCM_WAIT_INTERVAL);
	}
    }
}

    /*
     * SCM resume command invokes this function
     * If the service is not paused, this function does nothing.
     * Otherwise, resume the worker thread and update the status.
     */
VOID
ProcessServiceContinue (VOID)
{
  if (ServiceStatus.dwCurrentState == SERVICE_PAUSED)
    {
      UpdateServiceStatus (SERVICE_CONTINUE_PENDING, NO_ERROR, SCM_WAIT_INTERVAL);

      if (ResumeThread (hServiceThread) != -1)
	{
	  UpdateServiceStatus (SERVICE_RUNNING, NO_ERROR, SCM_WAIT_INTERVAL);
	}
    }
}

#endif /* WIN32 */

