#include "stdafx.h"

/*
Estructuras
*/

typedef struct ProgArgumentss {
	BOOL tidlist;
	BOOL noBanner;
	DWORD dwTid;
} ARGUMENTS, *PARGUMENTS;

/*
Zona de prototipado
*/

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);	
BOOL IsElevated();
BOOL ListProcessThreads(DWORD dwOwnerPID);
VOID PrintProcessNameAndID(DWORD processID);
BOOL ListAllProcess();
VOID Usage(LPCTSTR ProgName);
BOOL ParseProgramArguments(PARGUMENTS pParams, DWORD args, _TCHAR **argv);

