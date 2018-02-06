
#include "ProcessTools.h"
#include "Output.h"
#include <winternl.h>
#include <TlHelp32.h>

extern TEB* teb;

static void FileVersionInfo_Init(FileVersionInfo* fileVersionInfo, DWORD ms, DWORD ls)
{
    fileVersionInfo->FileMajorPart = HIWORD(ms);
    fileVersionInfo->FileMinorPart = LOWORD(ms);
    fileVersionInfo->FileBuildPart = HIWORD(ls);
    fileVersionInfo->FilePrivatePart = LOWORD(ls);
}

static void ProcessTools_GetFileVersion(char const* path, FileVersionInfo* info)
{
    DWORD size;
    BYTE* buffer;
    VS_FIXEDFILEINFO* fileInfo;
    UINT fileInfoSize;

    size = GetFileVersionInfoSizeA(path, NULL);
    if (!size)
    {
        ConsolePrint("Error in GetFileVersionInfoSize: %d\n", GetLastError());
        return;
    }

    buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (buffer == NULL)
        goto cleanup;

    if (!GetFileVersionInfoA(path, 0, size, buffer))
    {
        ConsolePrint("Error in GetFileVersionInfo: %d\n", GetLastError());
        goto cleanup;
    }

    if (!VerQueryValueA(buffer, "\\", (LPVOID*)&fileInfo, &fileInfoSize))
    {
        ConsolePrint("Error in VerQueryValue: %d\n", GetLastError());
        goto cleanup;
    }

    FileVersionInfo_Init(info, fileInfo->dwFileVersionMS, fileInfo->dwFileVersionLS);

cleanup:
    if (buffer != NULL)
        HeapFree(GetProcessHeap(), 0, buffer);
}

static HANDLE ProcessTools_OpenProcess(DWORD pid, DWORD_PTR* baseAddress, DWORD* threadId, DWORD build)
{
    HANDLE process;
    MODULEENTRY32 module;
    HANDLE moduleSnapshot;
    FileVersionInfo info;

    process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
    if (process != NULL)
    {
        if (baseAddress || build)
        {
            module.dwSize = sizeof(MODULEENTRY32);

            moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
            if (Module32First(moduleSnapshot, &module))
            {
                if (baseAddress)
                    *baseAddress = (DWORD_PTR)module.modBaseAddr;

                if (build)
                {
                    ProcessTools_GetFileVersion(module.szExePath, &info);
                    if (info.FilePrivatePart != build)
                    {
                        CloseHandle(moduleSnapshot);
                        CloseHandle(process);
                        return INVALID_HANDLE_VALUE;
                    }
                }
            }

            CloseHandle(moduleSnapshot);
        }

        if (threadId)
            ReadProcessMemory(process, (LPCVOID)teb->Reserved1[9], threadId, 4, NULL);

        return process;
    }

    return INVALID_HANDLE_VALUE;
}

HANDLE __stdcall ProcessTools_GetHandleByName(char const* name, DWORD_PTR* baseAddress, DWORD* threadId, DWORD build, BOOL log)
{
    PROCESSENTRY32 entry;
    HANDLE snapshot;
    HANDLE process;

    entry.dwSize = sizeof(PROCESSENTRY32);
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    process = INVALID_HANDLE_VALUE;

    if (!Process32First(snapshot, &entry))
    {
        CloseHandle(snapshot);
        if (log)
            ConsolePrint("Cannot find any process in system!\n");
        return INVALID_HANDLE_VALUE;
    }

    do
    {
        if (!lstrcmpiA(entry.szExeFile, name))
        {
            process = ProcessTools_OpenProcess(entry.th32ProcessID, baseAddress, threadId, build);
            if (process)
                break;
        }
    } while (Process32Next(snapshot, &entry));

    CloseHandle(snapshot);

    if (process == INVALID_HANDLE_VALUE)
    {
        if (log)
            ConsolePrint("Process with name %s not running.\n", name);
        return INVALID_HANDLE_VALUE;
    }

    return process;
}

HANDLE __stdcall ProcessTools_GetHandleByPID(DWORD pid, DWORD_PTR* baseAddress, DWORD* threadId, DWORD build, BOOL log)
{
    HANDLE process;

    process = ProcessTools_OpenProcess(pid, baseAddress, threadId, build);

    if (process == INVALID_HANDLE_VALUE)
    {
        if (log)
            ConsolePrint("Process with PID %u not running.\n", pid);
        return INVALID_HANDLE_VALUE;
    }

    return process;
}
