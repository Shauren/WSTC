
#include "DynamicLibrary.h"

typedef union DynamicLibraryHandle_
{
    HMODULE File;
} DynamicLibraryHandle;

struct DynamicLibrary_
{
    DynamicLibraryHandle Handle;
    DynamicLibraryType Type;
};

DynamicLibrary WINAPI DynamicLibrary_Load(DynamicLibraryType type, char const* buffer, DWORD bufferSize)
{
    DynamicLibraryHandle handle;
    DynamicLibrary library;

    switch (type)
    {
        case DYNAMIC_LIBRARY_FILE:
            handle.File = LoadLibraryA(buffer);
            if (handle.File == NULL)
                return NULL;
            break;
        default:
            UNREFERENCED_PARAMETER(bufferSize);
            return NULL;
    }

    library = (DynamicLibrary)HeapAlloc(GetProcessHeap(), 0, sizeof(struct DynamicLibrary_));
    if (library == NULL)
        return NULL;

    library->Handle = handle;
    library->Type = type;
    return library;
}

void WINAPI DynamicLibrary_Free(DynamicLibrary library)
{
    if (library == NULL)
        return;

    switch (library->Type)
    {
        case DYNAMIC_LIBRARY_FILE:
            if (library->Handle.File != NULL)
            {
                FreeLibrary(library->Handle.File);
                library->Handle.File = NULL;
            }
            break;
        default:
            break;
    }

    HeapFree(GetProcessHeap(), 0, library);
}

FARPROC WINAPI DynamicLibary_GetProcAddress(DynamicLibrary library, char const* name)
{
    if (library == NULL)
        return NULL;

    switch (library->Type)
    {
        case DYNAMIC_LIBRARY_FILE:
            if (library->Handle.File != NULL)
                return GetProcAddress(library->Handle.File, name);
            break;
        default:
            break;
    }

    return NULL;
}
