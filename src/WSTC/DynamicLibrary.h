#ifndef DynamicLibrary_h__
#define DynamicLibrary_h__

#include <Windows.h>

typedef enum DynamicLibraryType_
{
    DYNAMIC_LIBRARY_FILE = 0,
} DynamicLibraryType;

typedef struct DynamicLibrary_* DynamicLibrary;

DynamicLibrary WINAPI DynamicLibrary_Load(DynamicLibraryType type, char const* buffer, DWORD bufferSize);
void WINAPI DynamicLibrary_Free(DynamicLibrary library);
FARPROC WINAPI DynamicLibary_GetProcAddress(DynamicLibrary library, char const* name);

#define DynamicLibrary_GetProcAddressT(type, library, name) ((type)DynamicLibary_GetProcAddress(library, name))

#endif // DynamicLibrary_h__
