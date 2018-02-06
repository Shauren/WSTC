#ifndef InjectedData_h__
#define InjectedData_h__

#include <Windows.h>

#pragma region FunctionPrototypes

typedef HANDLE(WINAPI* pCreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
typedef BOOL(WINAPI* pWriteFile)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
typedef void(WINAPI* pCloseHandle)(HANDLE hObject);
typedef DWORD(WINAPI* pGetTickCount)(void);
typedef void(WINAPI* pSleep)(DWORD dwMilliseconds);
typedef DWORD(WINAPI* pSetFilePointer)(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);
typedef void(WINAPI* pGetLocalTime)(LPSYSTEMTIME lpSystemTime);
typedef void(WINAPI* pGetSystemTimeAsFileTime)(LPFILETIME lpSystemTimeAsFileTime);
typedef int(WINAPIV* pWsprintfA)(LPTSTR lpOut, LPCTSTR lpFmt, ...);

typedef void(__cdecl* pConsolePrintf)(char*, ...);
typedef void*(__cdecl* pConnection)(void);
typedef BYTE*(__fastcall* pGetSessionKey)(void* connection, DWORD dummy);
#pragma endregion

#pragma region OffsetDefinitions

#ifdef _M_IX86

#define OriginalCodeSMSG                0x8B0BB70F  // 7.2.5
#define HookAddrSMSG                    0x2E5B69    // 7.2.5 NetClient::OneMessageReady - movzx ecx, word ptr [ebx] - after isInitialized check
#define HookAddrCMSG                    0x2E5EC9    // 7.2.5 NetClient::Send - and [REG+var_4], 0 - before CDataStore::GetDataInSitu
#define HookAddrCMSG2                   0x2E60BB    // 7.2.5 NetClient::SendOnConnection - mov [ebp+var_C], 4 - after CDataStore::GetDataInSitu
#define HookAddrDisconnect              0x2E587E    // 7.2.5 NetClient::HandleDisconnect - replace call ConsolePrintf

// Offsets to various functions in the client
#define ClientLocaleIdxOffset           0xE0EB48    // 7.2.5 address of locale index, see Script_GetLocale s_currentIsoLocale
#define ClientLocaleStrOffset           0xABF4B0    // 7.2.5 address of locale string table, see Script_GetLocale _g_WOW_LocaleStrings
#define ConsolePrintf_Offset            0x0A9C5B    // 7.2.5 ConsolePrintf
#define Connection_Offset               0x6EEEB5    // 7.2.5 ClientServices::Connection
#define GetSessionKey_Offset            0x2E57CF    // 7.2.5 NetClient::GetSessionKey

#else

#define OriginalCodeSMSG                0x0EB70F44  // 7.2.5 x64
#define HookAddrSMSG                    0x44DEAF    // 7.2.5 x64 NetClient::OneMessageReady - movzx r9d, word ptr [rsi]
#define HookAddrCMSG                    0x44E2C4    // 7.2.5 x64 NetClient::Send - mov rcx, rdi - before call to CDataStore::GetDataInSitu
#define HookAddrCMSG2                   0x44E56A    // 7.2.5 x64 NetClient::SendOnConnection - mov [rbp+var_C], 4 - after CDataStore::GetDataInSitu
#define HookAddrDisconnect              0x44D930    // 7.2.5 x64 NetClient::HandleDisconnect - on the mov before ConsolePrintf

// Offsets to various functions in the client
#define ClientLocaleIdxOffset           0x16D4880   // 7.2.5 x64 address of locale index, see Script_GetLocale s_currentIsoLocale
#define ClientLocaleStrOffset           0x10A2E00   // 7.2.5 x64 address of locale string table, see Script_GetLocale _g_WOW_LocaleStrings
#define ConsolePrintf_Offset            0x0C1720    // 7.2.5 x64 ConsolePrintf
#define Connection_Offset               0xB2F0C0    // 7.2.5 x64 ClientServices::Connection
#define GetSessionKey_Offset            0x44D7E0    // 7.2.5 x64 NetClient::GetSessionKey

#pragma endregion

#endif

#pragma pack(push, 1)

// Structure injected to game client for convenient access of functions used within
// as well as passing data to file writing functions (header, error messages)
typedef struct InjectedData_
{
    volatile DWORD LockFlags;
    HANDLE SniffFile;
    char FileNameFormat[64];
    char CreateFileFailedMsg[32];
    char FileHeader[256];
    DWORD FileHeaderLength;
    BOOL WrittenSessionKey;

    // Fill these during injection
    DWORD Build;
    DWORD* LocaleIndex;
    char** LocaleStrings;

    // WINAPI
    pCreateFileA CreateFileA_;
    pWriteFile WriteFile_;
    pCloseHandle CloseHandle_;
    pGetTickCount GetTickCount_;
    pSleep Sleep_;
    pSetFilePointer SetFilePointer_;
    pGetLocalTime GetLocalTime_;
    pGetSystemTimeAsFileTime GetSystemTimeAsFileTime_;
    pWsprintfA wsprintfA_;

    // CLIENT
    pConsolePrintf ConsolePrintf;
    pConnection Connection_;
    pGetSessionKey GetSessionKey_;
} InjectedData;

void InjectedData_Init(InjectedData* data, SYSTEMTIME const* t, DWORD_PTR baseAddr, char const* machine);

#pragma pack(pop)

#endif // InjectedData_h__
