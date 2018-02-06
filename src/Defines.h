#ifndef Defines_h__
#define Defines_h__

#include <Windows.h>
#include <winternl.h>
#include "Output.h"

#pragma region TypeDefinitions

// Function pointer type definitions
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* pNtSetInformationThread)(HANDLE, THREADINFOCLASS, PVOID, ULONG);
typedef NTSTATUS(NTAPI* pNtClose)(HANDLE);
typedef BOOL(WINAPI* pVirtualProtectEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef LPVOID(WINAPI* pVirtualAllocEx)(HANDLE hProcess,LPVOID lpAddress,SIZE_T dwSize,DWORD flAllocationType, DWORD flProtect);
typedef BOOL(WINAPI* pWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
typedef BOOL(WINAPI* pReadProcessMemory)(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
typedef int(WINAPI* pMessageBoxExA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType, WORD wLanguageId);

// Cross-module calling
typedef HANDLE(__stdcall* GetHandleByNameFn)(char const* name, DWORD_PTR* baseAddress, DWORD* threadId, DWORD build, BOOL log);
typedef HANDLE(__stdcall* GetHandleByPIDFn)(DWORD pid, DWORD_PTR* baseAddress, DWORD* threadId, DWORD build, BOOL log);
typedef void(__cdecl* PrepareToInjectFn)(void* start, DWORD_PTR length, ...);
typedef HANDLE(__cdecl* WriteCodeToProcessFn)(HANDLE process, LPCVOID code, DWORD_PTR length);
typedef HANDLE(__cdecl* WriteDataToProcessFn)(HANDLE wowProcess, LPCVOID data, size_t size);
typedef void(__cdecl* AttachHookFn)(HANDLE process, HANDLE to, DWORD_PTR from, DWORD_PTR baseAddr, SIZE_T padding);
typedef char const*(__stdcall* GetStringFn)(int id);

typedef struct InitializeModuleData_
{
    GetHandleByNameFn pGetHandleByName;
    GetHandleByPIDFn pGetHandleByPID;
    PrepareToInjectFn pPrepareToInject;
    WriteCodeToProcessFn pWriteCodeToProcess;
    WriteDataToProcessFn pWriteDataToProcess;
    AttachHookFn pAttachHook;
    GetStringFn pGetString;
} InitializeModuleData;

typedef char const*(__cdecl* GetSnifferVersionFn)(void);
typedef void(__cdecl* InitializeModuleFn)(InitializeModuleData* initializeModuleData);
typedef LONG(__cdecl* SnifferMainFn)(DWORD code, DWORD_PTR loc, char const* overrideProcessName, DWORD overridePID);

#pragma endregion

#define WSTC_VERSION_NUMBER 0x0107
#define WSTC_VERSION_STRING "1.7"

#define ClientVersion           "7.2.5"
#define ClientBuild             24742       // 7.2.5

#ifdef _M_IX86

#define DumpPacketReplacement   0xDEADC0DE
#define InjectedDataAddress     0xDEADDA7A
#define DisconnectHandlerRplc   0xDEAD00DC

#else

#define DumpPacketReplacement   0xDEADC0DEDEADC0DE
#define InjectedDataAddress     0xDEADDA7ADEADDA7A
#define DisconnectHandlerRplc   0xDEAD00DCDEAD00DC

#endif

#define CMSG_LOG_DISCONNECT     0x3769      // 7.2.5
#define SMSG_AUTH_CHALLENGE     0x3048      // 7.2.5

#ifdef DEBUGGING_SNIFFER
#define STATUS_PRINT(...) DebugPrint(__VA_ARGS__)
#define CONSOLE_PRINT(...) DebugPrint(__VA_ARGS__)
#else
#define STATUS_PRINT(...) (void)sizeof(int)
#define CONSOLE_PRINT(...) ConsolePrint(__VA_ARGS__)
#endif

#endif // Defines_h__
