/*
	killthread (c) Luis González Fernández 
	A command line tool that can kill rebel threads.
	luisgf@luisgf.es - https://www.luisgf.es
*/

#include "killthread.h"


int _tmain(int argc, _TCHAR* argv[])
{
	ARGUMENTS params = { 0 };					// Parsed program arguments
	
	/*
	** Detect UAC Status	
	*/
	if (!IsElevated()) {
		wprintf(L"This program need to be run elevated. Please run as Admininistrator\r\n");
		return 1;
	}

	/*
	 Enabling privs
	*/
	if (!SetPrivilege(SE_DEBUG_NAME, TRUE)) {
		wprintf(L"Error enabling SeDebugPrivilege\r\n");
		return 1;
	}
		
	if (!ParseProgramArguments(&params, argc, argv)) {
		return 1;
	}

	if (!params.noBanner)
		wprintf(L">>> killthread v0.1 by Luis G.F<<< \r\n");

	if (params.tidlist) {
		ListAllProcess();
		return 0;
	}

	HANDLE th = OpenThread(THREAD_TERMINATE, FALSE, params.dwTid);
	if (!th) {
		wprintf(L"Error opening Tid(%d) handle.\r\n", params.dwTid);
		return 1;
	}
	
	BOOL rc = TerminateThread(th, -1);
	if (!rc) {
		wprintf(L"Error killing Tid %d\r\n", params.dwTid);
	}
	else {
		wprintf(L"Tid %d Killed!\r\n", params.dwTid);
	}
	CloseHandle(th);

	return 0;
}

BOOL SetPrivilege (
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
	)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!OpenProcessToken(
		GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES,
		&hToken))
	{
		return FALSE;
	}

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.
	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		CloseHandle(hToken);
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		printf("The token does not have the specified privilege. \n");
		CloseHandle(CloseHandle);
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}

BOOL IsElevated()
{
	TOKEN_ELEVATION_TYPE ptet;
	HRESULT hResult = E_ACCESSDENIED; 
	HANDLE hToken = NULL;

	if (!OpenProcessToken(
			GetCurrentProcess(),
			TOKEN_QUERY,
			&hToken))
	{
		return FALSE;
	}

	DWORD dwReturnLength = 0;

	if (GetTokenInformation(
			hToken,
			TokenElevationType,
			&ptet,
			sizeof(ptet),
			&dwReturnLength))
	{
		if (ptet == TOKEN_ELEVATION_TYPE::TokenElevationTypeFull)
			hResult = S_OK;
	}

	CloseHandle(hToken);

	if (hResult != E_ACCESSDENIED)
		return TRUE;
	else
		return FALSE;		
}

BOOL ListAllProcess()
{
	DWORD aProcesses[4096], cbNeeded, cProcesses;
	unsigned int i;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return 1;
	}

	// Calculate how many process identifiers were returned.
	cProcesses = cbNeeded / sizeof(DWORD);

	// Print the name and process identifier for each process.

	for (i = 0; i < cProcesses; i++)
	{
		if (aProcesses[i] != 0)
		{
			PrintProcessNameAndID(aProcesses[i]);
		}
	}
	return 0;
}

VOID PrintProcessNameAndID(DWORD processID)
{
	TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

	// Get a handle to the process.

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID);

	// Get the process name.

	if (NULL != hProcess)
	{
		HMODULE hMod;
		DWORD cbNeeded;

		if (EnumProcessModulesEx(hProcess, &hMod, sizeof(hMod),
			&cbNeeded, LIST_MODULES_ALL))
		{
			GetModuleBaseName(hProcess, hMod, szProcessName,
				sizeof(szProcessName) / sizeof(TCHAR));			
		}
	}

	// Print the process name and identifier.
	wprintf(TEXT("%s  (PID: %u)\n"), szProcessName, processID);
	ListProcessThreads(processID);
		
	// Release the handle to the process.

	CloseHandle(hProcess);
}

BOOL ListProcessThreads(DWORD dwOwnerPID)
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	// Take a snapshot of all running threads  
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);

	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32);

	// Retrieve information about the first thread,
	// and exit if unsuccessful
	if (!Thread32First(hThreadSnap, &te32))
	{
		CloseHandle(hThreadSnap);     // Must clean up the snapshot object!
		return(FALSE);
	}
	else {
		wprintf(L"TID(s): ");
	}

	// Now walk the thread list of the system,
	// and display information about each thread
	// associated with the specified process
	do
	{
		if (te32.th32OwnerProcessID == dwOwnerPID)
		{
			wprintf(L"%lu ", te32.th32ThreadID);
		}
	} while (Thread32Next(hThreadSnap, &te32));

	wprintf(L"\n");

	//  Don't forget to clean up the snapshot object.
	CloseHandle(hThreadSnap);
	return(TRUE);
}

BOOL ParseProgramArguments(PARGUMENTS pParams, DWORD args, _TCHAR **argv) {
	LPCTSTR param = NULL;

	if (args < 2) {
		wprintf(L"Too few arguments. Use /? to get the help.\n");
		return FALSE;
	}

	pParams->tidlist = FALSE;
	pParams->noBanner = FALSE;
	
	// Skip argv[0], that is the path to the program executable.
	for (DWORD i = 1; i < args; i++){
		param = argv[i];
		if (param[0] != L'/' && param[0] != L'-') {
			wprintf(L"Wrong parameter: %s\n", param);
			return FALSE;
		}

		param++;

		if (!_wcsnicmp(param, L"?", 1)) {
			Usage(argv[0]);
			exit(0);
		}

		if (!_wcsnicmp(param, L"list", 4)) {			
			pParams->tidlist = TRUE;
		}
		if (!_wcsnicmp(param, L"nobanner", 8)) {
			pParams->noBanner = TRUE;
		}
		if (!_wcsnicmp(param, L"tid:", 4)) {
			LPCTSTR tid = (LPTSTR)(param += 4);
			pParams->dwTid = wcstol(tid, NULL, 10);
		}
		
		// Add next parameters parsing here...		
	}

	if (!pParams->tidlist && !pParams->dwTid) {
		wprintf(L"Tid (/tid) parameter missing or incorrect.\n");
		return FALSE;
	}	

	return TRUE;
}

VOID Usage(LPCTSTR ProgName) {
	wprintf(L"Usage: %s /tid:TID \n\n", ProgName);
	wprintf(L"Parameters:\n");
	wprintf(L"/?\t\t Show this help\n");
	wprintf(L"/tid\t\t Specify the TID number to kill. Example /tid:1234\n");
	wprintf(L"/list\t\t List all process and thread identifiers");	
	wprintf(L"/nobanner\t\t Hide program banner at startup");
	wprintf(L"\n\n");
	exit(0);
}
