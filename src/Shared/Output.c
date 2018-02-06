
#include "Output.h"

#define MAX_PRINT_STRING_LEN 1024

void WINAPIV ConsolePrint(char const* format, ...)
{
    va_list args;
    char buffer[MAX_PRINT_STRING_LEN];

    va_start(args, format);
    int length = wvsprintfA(buffer, format, args);
    va_end(args);

    DWORD lpNumberOfBytesWritten = 0;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buffer, length, &lpNumberOfBytesWritten, NULL);
}

void WINAPIV ErrorPrint(char const* format, ...)
{
    va_list args;
    char buffer[MAX_PRINT_STRING_LEN];

    va_start(args, format);
    int length = wvsprintfA(buffer, format, args);
    va_end(args);

    DWORD lpNumberOfBytesWritten = 0;
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), buffer, length, &lpNumberOfBytesWritten, NULL);
}

void WINAPIV DebugPrint(char const* format, ...)
{
    va_list args;
    char buffer[MAX_PRINT_STRING_LEN];

    va_start(args, format);
    int length = wvsprintfA(buffer, format, args);
    va_end(args);

    DWORD lpNumberOfBytesWritten = 0;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buffer, length, &lpNumberOfBytesWritten, NULL);
    OutputDebugStringA(buffer);
}
