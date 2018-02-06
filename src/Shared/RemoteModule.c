
#include "RemoteModule.h"
#include <Psapi.h>
#include <TlHelp32.h>

struct RemoteModule_
{
    HMODULE Handle;
    BYTE* SelfBaseAddress;
    BYTE* RemoteBaseAddress;
};

RemoteModule WINAPI RemoteModule_GetModuleHandle(HANDLE process, LPCSTR moduleName)
{
    DWORD processId;
    HANDLE moduleSnapshot;
    MODULEENTRY32 module;
    MODULEINFO selfModule;
    RemoteModule remoteModule;

    processId = GetProcessId(process);
    moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);
    module.dwSize = sizeof(MODULEENTRY32);
    remoteModule = (RemoteModule)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(struct RemoteModule_));

    if (Module32First(moduleSnapshot, &module))
    {
        do
        {
            if (!lstrcmpiA(module.szModule, moduleName))
            {
                remoteModule->Handle = LoadLibraryExA(module.szExePath, NULL, DONT_RESOLVE_DLL_REFERENCES);
                if (remoteModule->Handle != NULL && GetModuleInformation(GetCurrentProcess(), remoteModule->Handle, &selfModule, sizeof(MODULEINFO)))
                    remoteModule->SelfBaseAddress = selfModule.lpBaseOfDll;

                remoteModule->RemoteBaseAddress = module.modBaseAddr;
                break;
            }

        } while (Module32Next(moduleSnapshot, &module));
    }

    CloseHandle(moduleSnapshot);

    if (remoteModule->Handle == NULL || remoteModule->SelfBaseAddress == 0 || remoteModule->RemoteBaseAddress == 0)
    {
        RemoteModule_Free(remoteModule);
        return NULL;
    }

    return remoteModule;
}

static void* RemoteModule_RebaseAddressInternal(RemoteModule module, void* address)
{
    return (BYTE*)address - module->SelfBaseAddress + module->RemoteBaseAddress;
}

void* WINAPI RemoteModule_RebaseAddress(RemoteModule module, void* address)
{
    if (module == NULL)
        return NULL;

    return RemoteModule_RebaseAddressInternal(module, address);
}

FARPROC WINAPI RemoteModule_GetProcAddress(RemoteModule module, LPCSTR procName)
{
    FARPROC procAddress;

    if (module == NULL)
        return NULL;

    procAddress = GetProcAddress(module->Handle, procName);
    if (procAddress == NULL)
        return NULL;

    return RemoteModule_RebaseAddressInternal(module, procAddress);
}

void WINAPI RemoteModule_Free(RemoteModule module)
{
    if (module == NULL)
        return;

    if (module->Handle != NULL)
        FreeLibrary(module->Handle);

    HeapFree(GetProcessHeap(), 0, module);
}
