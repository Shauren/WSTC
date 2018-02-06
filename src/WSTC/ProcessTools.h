#ifndef ProcessTools_h__
#define ProcessTools_h__

#include <Windows.h>

typedef struct FileVersionInfo_
{
    WORD FileMajorPart;
    WORD FileMinorPart;
    WORD FileBuildPart;
    WORD FilePrivatePart;
} FileVersionInfo;

HANDLE __stdcall ProcessTools_GetHandleByName(char const* name, DWORD_PTR* baseAddress, DWORD* threadId, DWORD build, BOOL log);
HANDLE __stdcall ProcessTools_GetHandleByPID(DWORD pid, DWORD_PTR* baseAddress, DWORD* threadId, DWORD build, BOOL log);

#endif // ProcessTools_h__
