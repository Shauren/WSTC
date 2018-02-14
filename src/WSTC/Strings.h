#ifndef Strings_h__
#define Strings_h__

#include <Windows.h>

// ntdll.dll
#define STR_NTDL                            0

// InitializeModule
#define STR_INIT_MODULE                     1

// GetSnifferVersion
#define STR_GET_SNIFFER_VERSION             2

// SnifferMain
#define STR_SNIFFER_MAIN                    3

// Sniffer and key version mismatch!\n
#define STR_SNIFFER_VERSION_MISMATCH        4

// WSTC.exe version: %s\n
#define STR_SNIFFER_VERSION                 5

// key file version: %s\n
#define STR_KEY_VERSION                     6

// kernel32.dll
#define STR_KERNEL32                        7

// VirtualAllocEx
#define STR_VIRTUAL_ALLOC_EX                8

// WriteProcessMemory
#define STR_WRITE_PROCESS_MEMORY            9

// VirtualProtextEx
#define STR_VIRTUAL_PROTECT_EX              10

// ReadProcessMemory
#define STR_READ_PROCESS_MEMORY             11

#define MAX_STRINGS                         12

#define MAX_ENCODED_STRING_LEN 40

#ifdef __cplusplus
extern "C" {
#endif

char const* WINAPI StringManager_GetString(int id);

#ifdef __cplusplus
}
#endif

#endif // Strings_h__
