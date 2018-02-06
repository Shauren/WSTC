#pragma region Includes

#include "ProcessTools.h"
#include "Defines.h"
#include "Replacement.h"
#include "Strings.h"
#include "DynamicLibrary.h"
#include "sniffer_version.h"
#include <Windows.h>
#include <Shlwapi.h>
#include <shellapi.h>
#include <winternl.h>
#include <winnt.h>

#pragma endregion

#define WINAPI_CALL(type, dynamicLibrary, func, moduleNameId, funcNameId, ...) \
    (dynamicLibrary) = DynamicLibrary_Load(DYNAMIC_LIBRARY_FILE, StringManager_GetString((moduleNameId)), 0);\
    if ((dynamicLibrary) != NULL) \
    { \
        (func) = DynamicLibary_GetProcAddress((dynamicLibrary), StringManager_GetString((funcNameId)));\
        ((type)func)(__VA_ARGS__);\
        DynamicLibrary_Free((dynamicLibrary));\
        dynamicLibrary = NULL;\
    }

#define WINAPI_CALL_ASSIGN(type, dynamicLibrary, func, moduleNameId, funcNameId, var, ...) \
    (dynamicLibrary) = DynamicLibrary_Load(DYNAMIC_LIBRARY_FILE, StringManager_GetString((moduleNameId)), 0);\
    if ((dynamicLibrary) != NULL) \
    { \
        (func) = DynamicLibary_GetProcAddress((dynamicLibrary), StringManager_GetString((funcNameId)));\
        (var) = ((type)func)(__VA_ARGS__);\
        DynamicLibrary_Free((dynamicLibrary));\
        dynamicLibrary = NULL;\
    }

#pragma region Structures

#pragma pack(push, 1)

// Helper structure to write jump instructions
typedef struct JumpPatch32_
{
    BYTE instr;
    DWORD offset;
    BYTE pad[5];
    SIZE_T size;
} JumpPatch32;

void JumpPatch32_Init(JumpPatch32* patch, DWORD addr, SIZE_T padSize)
{
    int i;

    patch->instr = 0xE8;
    patch->offset = addr;
    patch->size = 5 + padSize;
    for (i = 0; i < sizeof(patch->pad); ++i)
        patch->pad[i] = 0x90;
}

typedef struct JumpPatch64_
{
    BYTE instr;
    BYTE jumpType;
    LONG pointerOffset;
    BYTE pad[6];
    __declspec(align(8))
    DWORD64 destination;
    SIZE_T size;
} JumpPatch64;

void JumpPatch64_Init(JumpPatch64* patch, DWORD64 absoluteDest, LONG destPointerOffset, SIZE_T padSize)
{
    int i;

    patch->instr = 0xFF;
    patch->jumpType = 0x15;
    patch->pointerOffset = destPointerOffset;
    patch->destination = absoluteDest;
    patch->size = 6 + padSize;
    for (i = 0; i < sizeof(patch->pad); ++i)
        patch->pad[i] = 0x90;
}

#pragma pack(pop)

#pragma endregion

void __cdecl ShutdownExceptor(void);
void __cdecl InitExceptor(char const* buffer, DWORD bufferSize);

char const* OverrideProcessName = NULL;
DWORD OverridePID = 0;
DynamicLibrary Injecter;
SnifferMainFn DllSnifferMain;
GetSnifferVersionFn GetSnifferModuleVersion;

char const* GetSnifferVersion(void)
{
    return SNIFFER_VERSION_STRING;
}

LONG WINAPI SnifferMain(PEXCEPTION_POINTERS pExceptionInfo)
{
    LONG ret;

    ret = EXCEPTION_EXECUTE_HANDLER;

    STATUS_PRINT("> Checking sniffer and key versions...\n");
    if (lstrcmpA(GetSnifferModuleVersion(), GetSnifferVersion()))
    {
        STATUS_PRINT("    ");
        ConsolePrint(StringManager_GetString(STR_SNIFFER_VERSION_MISMATCH));
        ConsolePrint(StringManager_GetString(STR_SNIFFER_VERSION), GetSnifferVersion());
        ConsolePrint(StringManager_GetString(STR_KEY_VERSION), GetSnifferModuleVersion());
        STATUS_PRINT("    Status: Fail!\n\n");
        return EXCEPTION_EXECUTE_HANDLER;
    }

    STATUS_PRINT("    Status: Success!\n\n");

#if defined(_M_IX86)
#define IP Eip
#else
#define IP Rip
#endif

    if (DllSnifferMain && pExceptionInfo)
        ret = DllSnifferMain(pExceptionInfo->ExceptionRecord->ExceptionCode, pExceptionInfo->ContextRecord->IP, OverrideProcessName, OverridePID);

    STATUS_PRINT("    Status: %s!\n\n", ret == EXCEPTION_CONTINUE_EXECUTION ? "Success" : "Fail");

    // Memory finalization
    STATUS_PRINT("Unloading sniffer loader...\n");
    ShutdownExceptor();

    return EXCEPTION_EXECUTE_HANDLER;
}

LPTOP_LEVEL_EXCEPTION_FILTER PreviousFilter;

char** ParseCommandLineArgs(int* argc)
{
    LPWSTR* argv;
    int arg, totalSize, remainingSize;
    char* args;
    char* argDataStart;

    argv = CommandLineToArgvW(GetCommandLineW(), argc);
    totalSize = *argc * sizeof(char*);
    for (arg = 0; arg < *argc; ++arg)
        totalSize += lstrlenW(argv[arg]) + 1;

    remainingSize = totalSize - *argc * sizeof(char*);
    args = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, totalSize);
    if (args != NULL)
    {
        argDataStart = args + *argc * sizeof(char*);
        for (arg = 0; arg < *argc; ++arg)
        {
            ((char**)args)[arg] = argDataStart;
            argDataStart += WideCharToMultiByte(CP_ACP, 0, argv[arg], -1, argDataStart, remainingSize, NULL, NULL);
            remainingSize = totalSize + (int)(args - argDataStart);
        }
    }

    LocalFree(argv);
    return (char**)args;
}

// Command line argument handler
BOOL HandleArgs(void)
{
    int argc;
    char** argv;
    int arg;
    BOOL result;

    argv = ParseCommandLineArgs(&argc);
    if (argv == NULL)
        return FALSE;

    result = TRUE;

    for (arg = 1; arg < argc; ++arg)
    {
        if (lstrlenA(argv[arg]) < 2 || argv[arg][0] != '-')
            return FALSE;

        switch (argv[arg][1])
        {
            case 'n':
                if (++arg >= argc)
                {
                    result = FALSE;
                    break;
                }
                OverrideProcessName = StrDupA(argv[arg]);
                CONSOLE_PRINT("-n %s ...\n", OverrideProcessName);
                break;
            case 'p':
                if (++arg >= argc)
                {
                    result = FALSE;
                    break;
                }
                OverridePID = StrToIntA(argv[arg]);
                CONSOLE_PRINT("-p %d ...\n", OverridePID);
                break;
        }
    }

    HeapFree(GetProcessHeap(), 0, argv);

    return result;
}

#pragma region ProcessMemoryManipulation

// This function scans for supplied patterns in given memory block
// and replaces that new info
void __cdecl PrepareToInject(void* start, DWORD_PTR length, ...)
{
    DynamicLibrary library;
    FARPROC func;
    DWORD oldProtect;

    WINAPI_CALL(pVirtualProtectEx, library, func, STR_KERNEL32, STR_VIRTUAL_PROTECT_EX, GetCurrentProcess(), start, length, PAGE_EXECUTE_READWRITE, &oldProtect);
    for (BYTE* ptr = (BYTE*)start; ptr < (BYTE*)start + length; ++ptr)
    {
        va_list args;
        va_start(args, length);
        Replacement* replace = va_arg(args, Replacement*);
        while (replace)
        {
            if (*(DWORD_PTR*)ptr == replace->What)
            {
                if (replace->Rebase)
                    *(DWORD_PTR*)ptr += replace->With;
                else
                    *(DWORD_PTR*)ptr = replace->With;
            }

            replace = va_arg(args, Replacement*);
        }

        va_end(args);
    }

    WINAPI_CALL(pVirtualProtectEx, library, func, STR_KERNEL32, STR_VIRTUAL_PROTECT_EX, GetCurrentProcess(), start, length, oldProtect, &oldProtect);
}

// Allocates an executable memory block in target process with permissions PAGE_EXECUTE_READWRITE and writes specified code to it
HANDLE __cdecl WriteCodeToProcess(HANDLE process, LPCVOID code, DWORD_PTR length)
{
    DynamicLibrary library;
    FARPROC func;
    DWORD oldProtect;
    LPVOID ptr;

    library = NULL;
    func = NULL;
    ptr = NULL;

    WINAPI_CALL_ASSIGN(pVirtualAllocEx, library, func, STR_KERNEL32, STR_VIRTUAL_ALLOC_EX, ptr, process, NULL, length, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WINAPI_CALL(pWriteProcessMemory, library, func, STR_KERNEL32, STR_WRITE_PROCESS_MEMORY, process, ptr, code, length, NULL);
    WINAPI_CALL(pVirtualProtectEx, library, func, STR_KERNEL32, STR_VIRTUAL_PROTECT_EX, process, ptr, length, PAGE_EXECUTE_READ, &oldProtect);
    return ptr;
}

// Allocates memory block in target process with permissions PAGE_READWRITE and writes specified data to it
HANDLE __cdecl WriteDataToProcess(HANDLE wowProcess, LPCVOID data, size_t size)
{
    DynamicLibrary library;
    FARPROC func;
    LPVOID injectedData;

    library = NULL;
    func = NULL;
    injectedData = NULL;

    WINAPI_CALL_ASSIGN(pVirtualAllocEx, library, func, STR_KERNEL32, STR_VIRTUAL_ALLOC_EX, injectedData, wowProcess, NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    WINAPI_CALL(pWriteProcessMemory, library, func, STR_KERNEL32, STR_WRITE_PROCESS_MEMORY, wowProcess, injectedData, data, size, NULL);
    return injectedData;
}

#ifdef _M_IX86

// Replaces code in target process at specific address with a jump to provided address
void __cdecl AttachHook(HANDLE process, HANDLE to, DWORD_PTR from, DWORD_PTR baseAddr, SIZE_T padding)
{
    DWORD oldProtect;
    JumpPatch32 ptch;
    DynamicLibrary library;
    FARPROC func;

    JumpPatch32_Init(&ptch, (DWORD)((DWORD_PTR)to - from - baseAddr) - 5, padding);
    WINAPI_CALL(pVirtualProtectEx, library, func, STR_KERNEL32, STR_VIRTUAL_PROTECT_EX, process, (LPVOID)(from + baseAddr), ptch.size, PAGE_EXECUTE_READWRITE, &oldProtect);
    WINAPI_CALL(pWriteProcessMemory, library, func, STR_KERNEL32, STR_WRITE_PROCESS_MEMORY, process, (LPVOID)(from + baseAddr), &ptch, ptch.size, NULL);
    WINAPI_CALL(pVirtualProtectEx, library, func, STR_KERNEL32, STR_VIRTUAL_PROTECT_EX, process, (LPVOID)(from + baseAddr), ptch.size, oldProtect, &oldProtect);
}

#else

static LONG FindPointerOffset(HANDLE process, DWORD_PTR searchStart)
{
    static DWORD64 const pattern = 0xCCCCCCCCCCCCCCCC;
    DynamicLibrary library;
    FARPROC func;
    DWORD64 itr;
    LONG offset = 0;
    SIZE_T bytesRead;
    BOOL rpmResult;

    for (;;)
    {
        rpmResult = FALSE;
        itr = 0;
        WINAPI_CALL_ASSIGN(pReadProcessMemory, library, func, STR_KERNEL32, STR_READ_PROCESS_MEMORY, rpmResult, process, (LPCVOID)(searchStart + offset), &itr, sizeof(itr), &bytesRead);
        if (!rpmResult)
            return 0;

        if (itr == pattern)
            return offset - 6;

        rpmResult = FALSE;
        WINAPI_CALL_ASSIGN(pReadProcessMemory, library, func, STR_KERNEL32, STR_READ_PROCESS_MEMORY, rpmResult, process, (LPCVOID)(searchStart - offset), &itr, sizeof(itr), &bytesRead);
        if (!rpmResult)
            return 0;

        if (itr == pattern)
            return -(offset + 6);

        ++offset;
    }
}

// Replaces code in target process at specific address with a jump to provided address
void __cdecl AttachHook(HANDLE process, HANDLE to, DWORD_PTR from, DWORD_PTR baseAddr, SIZE_T padding)
{
    DWORD oldProtect;
    JumpPatch64 ptch;
    DWORD_PTR address;
    DynamicLibrary library;
    FARPROC func;

    JumpPatch64_Init(&ptch, (DWORD64)to, FindPointerOffset(process, from + baseAddr), padding);

    // write instruction
    address = (DWORD_PTR)(from + baseAddr);
    WINAPI_CALL(pVirtualProtectEx, library, func, STR_KERNEL32, STR_VIRTUAL_PROTECT_EX, process, (LPVOID)address, ptch.size, PAGE_EXECUTE_READWRITE, &oldProtect);
    WINAPI_CALL(pWriteProcessMemory, library, func, STR_KERNEL32, STR_WRITE_PROCESS_MEMORY, process, (LPVOID)address, &ptch, ptch.size, NULL);
    WINAPI_CALL(pVirtualProtectEx, library, func, STR_KERNEL32, STR_VIRTUAL_PROTECT_EX, process, (LPVOID)address, ptch.size, oldProtect, &oldProtect);

    // write dest address
    address += ptch.pointerOffset + 6;
    WINAPI_CALL(pVirtualProtectEx, library, func, STR_KERNEL32, STR_VIRTUAL_PROTECT_EX, process, (LPVOID)address, sizeof(ptch.destination), PAGE_EXECUTE_READWRITE, &oldProtect);
    WINAPI_CALL(pWriteProcessMemory, library, func, STR_KERNEL32, STR_WRITE_PROCESS_MEMORY, process, (LPVOID)address, &ptch.destination, sizeof(ptch.destination), NULL);
    WINAPI_CALL(pVirtualProtectEx, library, func, STR_KERNEL32, STR_VIRTUAL_PROTECT_EX, process, (LPVOID)address, sizeof(ptch.destination), oldProtect, &oldProtect);
}

#endif

#pragma endregion

TEB* teb;

UINT EntryPointImpl(void)
{
    PreviousFilter = SetUnhandledExceptionFilter(&SnifferMain);
    teb = NtCurrentTeb();

    HandleArgs();

    InitExceptor("Injecter.dll", 0);

    EXCEPTION_POINTERS ptrs;
    EXCEPTION_RECORD excRec;
    CONTEXT ctx;
    excRec.ExceptionCode = STATUS_ACCESS_VIOLATION;

#if defined(_M_IX86)
    ctx.Eip = 0;
#else
    ctx.Rip = 0;
#endif

    ptrs.ExceptionRecord = &excRec;
    ptrs.ContextRecord = &ctx;
    SnifferMain(&ptrs);
    return 0;
}

int WINAPI EntryPoint(void)
{
    ExitProcess(EntryPointImpl());
}

void __cdecl ShutdownExceptor(void)
{
    STATUS_PRINT("> FinalizeLoader\n");
    STATUS_PRINT("    Freeing memory...\n");
    DynamicLibrary_Free(Injecter);
}

void __cdecl InitExceptor(char const* buffer, DWORD bufferSize)
{
    InitializeModuleData initializeModuleData;
    InitializeModuleFn initMod;
    GetSnifferVersionFn version;
    SnifferMainFn mainFunc;

    STATUS_PRINT("Loading sniffer...\n");
    if ((Injecter = DynamicLibrary_Load(DYNAMIC_LIBRARY_FILE, buffer, bufferSize)) != NULL)
    {
        STATUS_PRINT("> InitializeModule...\n");
        if ((initMod = DynamicLibrary_GetProcAddressT(InitializeModuleFn, Injecter, StringManager_GetString(STR_INIT_MODULE))) != NULL)
        {
            STATUS_PRINT("    Found at 0x%p\n", initMod);
            initializeModuleData.pGetHandleByName = &ProcessTools_GetHandleByName;
            initializeModuleData.pGetHandleByPID = &ProcessTools_GetHandleByPID;
            initializeModuleData.pPrepareToInject = &PrepareToInject;
            initializeModuleData.pWriteCodeToProcess = &WriteCodeToProcess;
            initializeModuleData.pWriteDataToProcess = &WriteDataToProcess;
            initializeModuleData.pAttachHook = &AttachHook;
            initializeModuleData.pGetString = &StringManager_GetString;
            initMod(&initializeModuleData);
        }
        else
            STATUS_PRINT("    Status: Fail!\n\n");

        STATUS_PRINT("> GetSnifferVersion...\n");
        if ((version = DynamicLibrary_GetProcAddressT(GetSnifferVersionFn, Injecter, StringManager_GetString(STR_GET_SNIFFER_VERSION))) != NULL)
        {
            STATUS_PRINT("    Found at 0x%p\n", version);
            GetSnifferModuleVersion = version;
            STATUS_PRINT("    Status: Success!\n\n");
        }
        else
            STATUS_PRINT("    Status: Fail!\n\n");

        STATUS_PRINT("> SnifferMain...\n");
        if ((mainFunc = DynamicLibrary_GetProcAddressT(SnifferMainFn, Injecter, StringManager_GetString(STR_SNIFFER_MAIN))) != NULL)
        {
            STATUS_PRINT("    Found at 0x%p\n", mainFunc);
            DllSnifferMain = mainFunc;
            STATUS_PRINT("    Status: Success!\n\n");
        }
        else
            STATUS_PRINT("    Status: Fail!\n\n");
    }
    else
        STATUS_PRINT("Critical error loading injection library!!!\n\n");
}
