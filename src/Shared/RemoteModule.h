#ifndef RemoteModule_h__
#define RemoteModule_h__

#include <Windows.h>

typedef struct RemoteModule_* RemoteModule;

RemoteModule WINAPI RemoteModule_GetModuleHandle(HANDLE process, LPCSTR moduleName);
void* WINAPI RemoteModule_RebaseAddress(RemoteModule module, void* address);
FARPROC WINAPI RemoteModule_GetProcAddress(RemoteModule module, LPCSTR procName);
void WINAPI RemoteModule_Free(RemoteModule module);

#endif // RemoteModule_h__
