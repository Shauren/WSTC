
#include "Strings.h"

char const StringData[MAX_STRINGS][MAX_ENCODED_STRING_LEN] =
{
    "ntdll.dll",
    "InitializeModule",
    "GetSnifferVersion",
    "SnifferMain",
    "Sniffer and key version mismatch!\n",
    "WSTC.exe version: %s\n",
    "key file version: %s\n",
    "kernel32.dll",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "VirtualProtectEx",
    "ReadProcessMemory"
};

char const* WINAPI StringManager_GetString(int id)
{
    if (id < 0 || id >= MAX_STRINGS)
        return NULL;

    return StringData[id];
}
