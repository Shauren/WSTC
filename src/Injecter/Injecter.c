
#include "Defines.h"
#include "InjectedData.h"
#include "RemoteModule.h"
#include "Replacement.h"
#include <Windows.h>
#include <DbgHelp.h>
#include "sniffer_version.h"

#define offsetof(s,m) ((DWORD_PTR)&(((s*)0)->m))

#pragma pack(push, 1)

// File header for captured packets
typedef struct PKT_Header_
{
    char Signature[3];
    unsigned short FormatVersion;
    unsigned char SnifferId;
    unsigned int Build;
    char Locale[4];
    unsigned char SessionKey[40];
    DWORD SniffStartUnixtime;
    unsigned int SniffStartTicks;
    unsigned int OptionalDataSize;
} PKT_Header;

typedef struct PKT_OptionalHeader_
{
    BYTE Sep;
    WORD SnifferVersion;
    FILETIME SniffStartFiletime;
} PKT_OptionalHeader;

// Structure appended to every captured packet when writing to file
typedef struct PKT_PacketHeader_
{
    char Direction[4];
    unsigned int ConnectionId;
    unsigned int ArrivalTicks;
    unsigned int OptionalDataSize;
    unsigned int Length;
    unsigned int Opcode;
} PKT_PacketHeader;

#pragma pack(pop)

enum SniffLockFlags
{
    LOCK_FLAG_DURING_WRITE  = 0x01,
};

GetHandleByNameFn WSTC_GetHandleByName;
GetHandleByPIDFn WSTC_GetHandleByPID;
PrepareToInjectFn WSTC_PrepareToInject;
WriteCodeToProcessFn WSTC_WriteCodeToProcess;
WriteDataToProcessFn WSTC_WriteDataToProcess;
AttachHookFn WSTC_AttachHook;
GetStringFn WSTC_GetString;

#pragma region InjectedCode

extern void SMSG_Hook(void);
extern void CMSG_Hook(void);        // Send2
extern void CMSG_Hook2(void);       // NetClient::SendOnConnection
extern void Disconnect_Hook(void);  // NetClient::HandleDisconnect

extern void SMSG_Hook_End(void);
extern void CMSG_Hook_End(void);
extern void CMSG_Hook2_End(void);
extern void Disconnect_Hook_End(void);

// Packet dumping function
void __stdcall DumpPacket(void* content, int opcode, int size, int direction, int connectionId)
{
    InjectedData* volatile data;
    DWORD tickCount;
    char fileName[64];
    SYSTEMTIME timeInfo;
    PKT_Header fileHeader;
    PKT_OptionalHeader optionalHeader;
    PKT_PacketHeader packetHeader;
    DWORD lpNumberOfBytesWritten;

    data = (InjectedData*)InjectedDataAddress;

    // VERY primitive locking to prevent concurrent writes
    if (data->LockFlags & LOCK_FLAG_DURING_WRITE)
    {
        do
            (*(data->Sleep_))(1);
        while (data->LockFlags & LOCK_FLAG_DURING_WRITE);
    }

    data->LockFlags |= LOCK_FLAG_DURING_WRITE;
    tickCount = (*(data->GetTickCount_))();

    if (!data->SniffFile || data->SniffFile == INVALID_HANDLE_VALUE)
    {
        // Don't create a new sniff file just for this opcode
        // It is sent at least twice when disconnecting
        if (opcode == CMSG_LOG_DISCONNECT)
        {
            data->LockFlags &= ~LOCK_FLAG_DURING_WRITE;
            return;
        }

        (*(data->GetLocalTime_))(&timeInfo);

        (*(data->wsprintfA_))(fileName, data->FileNameFormat, data->Build, timeInfo.wYear, timeInfo.wMonth, timeInfo.wDay, timeInfo.wHour, timeInfo.wMinute, timeInfo.wSecond, tickCount);
        data->SniffFile = (*(data->CreateFileA_))(fileName, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

        if (!data->SniffFile || data->SniffFile == INVALID_HANDLE_VALUE)
        {
            data->ConsolePrintf(data->CreateFileFailedMsg, fileName);
            data->LockFlags &= ~LOCK_FLAG_DURING_WRITE;
            return;
        }

        fileHeader.Build = data->Build;
        *(DWORD*)&fileHeader.Locale = *(DWORD*)data->LocaleStrings[*data->LocaleIndex];
        fileHeader.FormatVersion = 0x0301;
        fileHeader.Signature[0] = 'P';
        fileHeader.Signature[1] = 'K';
        fileHeader.Signature[2] = 'T';
        fileHeader.SnifferId = 'S';
        fileHeader.SniffStartUnixtime = 0;
        fileHeader.SniffStartTicks = tickCount;
        optionalHeader.Sep = 0xFF;
        optionalHeader.SnifferVersion = WSTC_VERSION_NUMBER;
        (*(data->GetSystemTimeAsFileTime_))(&optionalHeader.SniffStartFiletime);
        fileHeader.OptionalDataSize = sizeof(PKT_OptionalHeader) + data->FileHeaderLength;
        (*(data->WriteFile_))(data->SniffFile, &fileHeader, sizeof(PKT_Header), &lpNumberOfBytesWritten, NULL);
        (*(data->WriteFile_))(data->SniffFile, &optionalHeader, sizeof(PKT_OptionalHeader), &lpNumberOfBytesWritten, NULL);
        (*(data->WriteFile_))(data->SniffFile, data->FileHeader, data->FileHeaderLength, &lpNumberOfBytesWritten, NULL);
    }

    if (!data->WrittenSessionKey && opcode != SMSG_AUTH_CHALLENGE)
    {
        data->WrittenSessionKey = TRUE;

        DWORD cur = (*(data->SetFilePointer_))(data->SniffFile, 0, NULL, FILE_CURRENT);
        (*(data->SetFilePointer_))(data->SniffFile, offsetof(PKT_Header, SessionKey), NULL, FILE_BEGIN);
        (*(data->WriteFile_))(data->SniffFile, data->GetSessionKey_(data->Connection_(), 0), 40, &lpNumberOfBytesWritten, NULL);
        (*(data->SetFilePointer_))(data->SniffFile, cur, NULL, FILE_BEGIN);
    }

    packetHeader.Direction[0] = 'S';
    if (direction)
        packetHeader.Direction[0] = 'C';

    packetHeader.Direction[1] = 'M';
    packetHeader.Direction[2] = 'S';
    packetHeader.Direction[3] = 'G';

    packetHeader.ArrivalTicks = tickCount;
    packetHeader.ConnectionId = connectionId;
    packetHeader.OptionalDataSize = 0;
    packetHeader.Length = size + 4;
    packetHeader.Opcode = opcode;

    (*(data->WriteFile_))(data->SniffFile, &packetHeader, sizeof(PKT_PacketHeader), &lpNumberOfBytesWritten, NULL);
    (*(data->WriteFile_))(data->SniffFile, content, size, &lpNumberOfBytesWritten, NULL);

    data->LockFlags &= ~LOCK_FLAG_DURING_WRITE;
}

void __stdcall DumpPacket_End(void)
{
    DumpPacket(NULL, 0, 0, 0, 0);
}

// This function handles connection closing for wow.exe
// Closes file with packet dump.
void __cdecl DisconnectHandler(void)
{
    InjectedData* volatile data = (InjectedData*)InjectedDataAddress;

    while (data->LockFlags & LOCK_FLAG_DURING_WRITE)
        (*(data->Sleep_))(1);

    data->LockFlags |= LOCK_FLAG_DURING_WRITE;

    if (data->SniffFile && data->SniffFile != INVALID_HANDLE_VALUE)
    {
        (*(data->CloseHandle_))(data->SniffFile);
        data->SniffFile = INVALID_HANDLE_VALUE;
    }

    data->LockFlags &= ~LOCK_FLAG_DURING_WRITE;
}

void __cdecl DisconnectHandler_End(void)
{
    DisconnectHandler();
    CONSOLE_PRINT("DisconnectHandler_End called, END OF THE WORLD.");
}

// InjectedCode
#pragma endregion

enum FunctionIds
{
    Function_SMSG_Hook          = 0,
    Function_CMSG_Hook          = 1,
    Function_CMSG_Hook2         = 2,
    Function_DumpPacket         = 3,
    Function_Disconnect_Hook    = 4,
    Function_DisconnectHandler  = 5,

    Function_Max
};

void* Functions[Function_Max] =
{
    &SMSG_Hook,
    &CMSG_Hook,
    &CMSG_Hook2,
    &DumpPacket,
    &Disconnect_Hook,
    &DisconnectHandler,
};

/* Convenient macro that calculates size of function code in bytes
   Requires linker option /ORDER, as well as defining function
   with the same name, ending with _End right after function we are trying to find size of

   NOTE: Multiple uses require different marker function content to prevent the linker from only creating one
         and replacing references to them with the new one
*/
#define GetFunctionSize(function) (DWORD_PTR)function##_End - (DWORD_PTR)function

DWORD_PTR FunctionLengths[Function_Max];

__declspec(dllexport)
char const* __cdecl GetSnifferVersion(void)
{
    return SNIFFER_VERSION_STRING;
}

__declspec(dllexport)
void __cdecl InitializeModule(InitializeModuleData* initializeModuleData)
{
    WSTC_GetHandleByName = initializeModuleData->pGetHandleByName;
    STATUS_PRINT("    GetHandleByName: 0x%p\n", WSTC_GetHandleByName);
    WSTC_GetHandleByPID = initializeModuleData->pGetHandleByPID;
    STATUS_PRINT("    GetHandleByPID: 0x%p\n", WSTC_GetHandleByPID);
    WSTC_PrepareToInject = initializeModuleData->pPrepareToInject;
    STATUS_PRINT("    PrepareToInject: 0x%p\n", WSTC_PrepareToInject);
    WSTC_WriteCodeToProcess = initializeModuleData->pWriteCodeToProcess;
    STATUS_PRINT("    WriteCodeToProcess: 0x%p\n", WSTC_WriteCodeToProcess);
    WSTC_WriteDataToProcess = initializeModuleData->pWriteDataToProcess;
    STATUS_PRINT("    WriteDataToProcess: 0x%p\n", WSTC_WriteDataToProcess);
    WSTC_AttachHook = initializeModuleData->pAttachHook;
    STATUS_PRINT("    AttachHook: 0x%p\n", WSTC_AttachHook);
    WSTC_GetString = initializeModuleData->pGetString;
    STATUS_PRINT("    GetString: 0x%p\n", WSTC_GetString);
    STATUS_PRINT("    Status: Success!\n\n");
}

static void __cdecl InitializeHooks(void)
{
    STATUS_PRINT("> InitializeHooks...\n");
    STATUS_PRINT("    DumpPacket: 0x%p\n", Functions[Function_DumpPacket]);
    STATUS_PRINT("    SMSG_Hook: 0x%p\n", Functions[Function_SMSG_Hook]);
    STATUS_PRINT("    CMSG_Hook: 0x%p\n", Functions[Function_CMSG_Hook]);
    STATUS_PRINT("    CMSG_Hook2: 0x%p\n", Functions[Function_CMSG_Hook2]);
    STATUS_PRINT("    DisconnectHandler: 0x%p\n", Functions[Function_DisconnectHandler]);
    STATUS_PRINT("    Disconnect_Hook: 0x%p\n", Functions[Function_Disconnect_Hook]);
    STATUS_PRINT("    Status: Success!\n\n");
}

static void __cdecl InitializeLengths(void)
{
    STATUS_PRINT("> InitializeLengths...\n");
    FunctionLengths[Function_DumpPacket] = GetFunctionSize(DumpPacket);
    STATUS_PRINT("    DumpPacketLength: %u\n", FunctionLengths[Function_DumpPacket]);
    FunctionLengths[Function_SMSG_Hook] = GetFunctionSize(SMSG_Hook);
    STATUS_PRINT("    SmsgHookLength: %u\n", FunctionLengths[Function_SMSG_Hook]);
    FunctionLengths[Function_CMSG_Hook] = GetFunctionSize(CMSG_Hook);
    STATUS_PRINT("    CmsgHookLength: %u\n", FunctionLengths[Function_CMSG_Hook]);
    FunctionLengths[Function_CMSG_Hook2] = GetFunctionSize(CMSG_Hook2);
    STATUS_PRINT("    Cmsg2HookLength: %u\n", FunctionLengths[Function_CMSG_Hook2]);
    FunctionLengths[Function_DisconnectHandler] = GetFunctionSize(DisconnectHandler);
    STATUS_PRINT("    DisconnectHandlerLength: %u\n", FunctionLengths[Function_DisconnectHandler]);
    FunctionLengths[Function_Disconnect_Hook] = GetFunctionSize(Disconnect_Hook);
    STATUS_PRINT("    DisconnectHookLength: %u\n", FunctionLengths[Function_Disconnect_Hook]);
    STATUS_PRINT("    Status: Success!\n\n");
}

void UnixTimeToFileTime(DWORD unixtime, FILETIME* fileTime)
{
    // Note that LONGLONG is a 64-bit value
    LONGLONG ll;

    ll = Int32x32To64(unixtime, 10000000) + 116444736000000000;
    fileTime->dwLowDateTime = (DWORD)ll;
    fileTime->dwHighDateTime = ll >> 32;
}

__declspec(dllexport)
LONG __cdecl SnifferMain(DWORD code, DWORD_PTR loc, char const* overrideProcessName, DWORD overridePID)
{
    DWORD_PTR baseAddr;
    DWORD build;
    char const* processName;
    HANDLE wowProcess;
    InjectedData data;
    HANDLE injectedData;
    HANDLE dumpPacketClient;
    HANDLE smsgHook;
    HANDLE cmsgHook;    // NetClient::Send2
    HANDLE cmsgHook2;   // NetClient::SendOnConnection
    HANDLE disconnectHandler;
    HANDLE disconnectHook;
    FILETIME fileTime;
    SYSTEMTIME systemTime;
    char const* machine;
    PIMAGE_NT_HEADERS hdr;
    DWORD_PTR funcLength;
    Replacement replacement;
    RemoteModule kernel32;
    RemoteModule user32;

    InitializeLengths();
    InitializeHooks();

    STATUS_PRINT("> Injecting sniffer...\n");
    STATUS_PRINT("    Checking code: 0x%X\n", code);
    if (code != STATUS_ACCESS_VIOLATION)
        return EXCEPTION_EXECUTE_HANDLER;

    STATUS_PRINT("    Checking location: 0x%X... ", loc);
    if (loc != 0)
    {
        CONSOLE_PRINT("Fail!\n");
        return EXCEPTION_EXECUTE_HANDLER;
    }
    STATUS_PRINT("Success!\n");

    STATUS_PRINT("    ");
#ifdef _M_IX86
    CONSOLE_PRINT("Opening Wow process build %u... ", ClientBuild);
#else
    CONSOLE_PRINT("Opening Wow-64 process build %u... ", ClientBuild);
#endif

    baseAddr = 0;
    build = 0;
    if (overridePID)
    {
        wowProcess = WSTC_GetHandleByPID(overridePID, &baseAddr, NULL, ClientBuild, FALSE);
    }
    else
    {
        processName = overrideProcessName;
        if (!processName)
        {
#ifdef _M_IX86
            processName = "Wow.exe";
#else
            processName = "Wow-64.exe";
#endif
        }

        wowProcess = WSTC_GetHandleByName(processName, &baseAddr, NULL, ClientBuild, FALSE);
    }

    if (wowProcess == INVALID_HANDLE_VALUE)
    {
        CONSOLE_PRINT("not running!\n");
        return EXCEPTION_EXECUTE_HANDLER;
    }
    STATUS_PRINT("Success! Program base: 0x%p", baseAddr);
    CONSOLE_PRINT("\n");

    // Checks if this program was already ran by comparing code in place that is replaced with a jump (incoming packet handler)
    STATUS_PRINT("    ");
    CONSOLE_PRINT("Checking sniffer status... ");
    unsigned instructions = 0;
    if (!ReadProcessMemory(wowProcess, (LPCVOID)(baseAddr + HookAddrSMSG), &instructions, 4, NULL))
    {
        CloseHandle(wowProcess);
        CONSOLE_PRINT("Unable to check!.\n");
        return EXCEPTION_EXECUTE_HANDLER;
    }

    if (instructions != OriginalCodeSMSG) // original code
    {
        CloseHandle(wowProcess);
        STATUS_PRINT("Expected 0x%X found 0x%X. ", OriginalCodeSMSG, instructions);
        CONSOLE_PRINT("Already running.\n");
        return EXCEPTION_EXECUTE_HANDLER;
    }

    STATUS_PRINT("Not running - ok.");
    CONSOLE_PRINT("\n");

    GetSystemTime(&systemTime);
    machine = "unknown";

    // Obtains program linking time (self) for nice console messages
    if ((hdr = ImageNtHeader(GetModuleHandle(NULL))) != NULL)
    {
        UnixTimeToFileTime(hdr->FileHeader.TimeDateStamp, &fileTime);
        FileTimeToSystemTime(&fileTime, &systemTime);
        switch (hdr->FileHeader.Machine)
        {
            case IMAGE_FILE_MACHINE_I386:
                machine = "x86";
                break;
            case IMAGE_FILE_MACHINE_AMD64:
                machine = "x64";
                break;
        }
    }

    kernel32 = RemoteModule_GetModuleHandle(wowProcess, "kernel32.dll");
    if (kernel32 == NULL)
    {
        CloseHandle(wowProcess);
        STATUS_PRINT("Failed to locate kernel32.dll module in target process! ");
        CONSOLE_PRINT("Failed to initialize.\n");
        return EXCEPTION_EXECUTE_HANDLER;
    }

    user32 = RemoteModule_GetModuleHandle(wowProcess, "user32.dll");
    if (kernel32 == NULL)
    {
        CloseHandle(wowProcess);
        RemoteModule_Free(kernel32);
        STATUS_PRINT("Failed to locate user32.dll module in target process! ");
        CONSOLE_PRINT("Failed to initialize.\n");
        return EXCEPTION_EXECUTE_HANDLER;
    }

    /* Initializes and writes data structure to process memory containing:
     *  Pseudo mutex to prevent concurrent packet writes to file (simple integer)
     *  Handle to current file that packets are written to
     *  Constant string used to format packet dump file names
     *  String for error message printed in game console if creating packet dump file fails
     *  Custom header text written to packet dump file
     *  Pointers to game build and locale version
     *  Function pointers used during dumping a packet
     */
    STATUS_PRINT("    Initializing data...\n");
    InjectedData_Init(&data, &systemTime, baseAddr, machine);

    data.CreateFileA_ = (pCreateFileA)RemoteModule_GetProcAddress(kernel32, "CreateFileA");
    data.WriteFile_ = (pWriteFile)RemoteModule_GetProcAddress(kernel32, "WriteFile");
    data.CloseHandle_ = (pCloseHandle)RemoteModule_GetProcAddress(kernel32, "CloseHandle");
    data.GetTickCount_ = (pGetTickCount)RemoteModule_GetProcAddress(kernel32, "GetTickCount");
    data.Sleep_ = (pSleep)RemoteModule_GetProcAddress(kernel32, "Sleep");
    data.SetFilePointer_ = (pSetFilePointer)RemoteModule_GetProcAddress(kernel32, "SetFilePointer");
    data.GetLocalTime_ = (pGetLocalTime)RemoteModule_GetProcAddress(kernel32, "GetLocalTime");
    data.GetSystemTimeAsFileTime_ = (pGetSystemTimeAsFileTime)RemoteModule_GetProcAddress(kernel32, "GetSystemTimeAsFileTime");
    data.wsprintfA_ = (pWsprintfA)RemoteModule_GetProcAddress(user32, "wsprintfA");

    STATUS_PRINT("    Storing data...\n");
    injectedData = WSTC_WriteDataToProcess(wowProcess, &data, sizeof(InjectedData));

    /* Writes packet dumping function to client memory
       Dependencies: Address of InjectedData structure in target process' memory
     */
    STATUS_PRINT("    Creating packet saver...\n");
    {
        funcLength = FunctionLengths[Function_DumpPacket];
        Replacement_Init(&replacement, InjectedDataAddress, (DWORD_PTR)injectedData, FALSE);

        WSTC_PrepareToInject(Functions[Function_DumpPacket], funcLength, &replacement, NULL);

        dumpPacketClient = WSTC_WriteCodeToProcess(wowProcess, Functions[Function_DumpPacket], funcLength);
    }

    /* Writes a small function preparing call parameters for S->C packet dumping function
        Dependencies: Address of packet dumping function
        Base address of game process
        */
    STATUS_PRINT("    Creating server packet hook...\n");
    {
        funcLength = FunctionLengths[Function_SMSG_Hook];
        Replacement_Init(&replacement, DumpPacketReplacement, (DWORD_PTR)dumpPacketClient, FALSE);

        WSTC_PrepareToInject(Functions[Function_SMSG_Hook], funcLength, &replacement, NULL);

        smsgHook = WSTC_WriteCodeToProcess(wowProcess, Functions[Function_SMSG_Hook], funcLength);
    }

    /* Writes a small function preparing call parameters for C->S (1) packet dumping function
        Dependencies: Address of packet dumping function
        Base address of game process
        */
    STATUS_PRINT("    Creating client packet hook...\n");
    {
        funcLength = FunctionLengths[Function_CMSG_Hook];
        Replacement_Init(&replacement, DumpPacketReplacement, (DWORD_PTR)dumpPacketClient, FALSE);

        WSTC_PrepareToInject(Functions[Function_CMSG_Hook], funcLength, &replacement, NULL);

        cmsgHook = WSTC_WriteCodeToProcess(wowProcess, Functions[Function_CMSG_Hook], funcLength);
    }

    /* Writes a small function preparing call parameters for C->S (2) packet dumping function
        Dependencies: Address of packet dumping function
        Base address of game process
        */
    STATUS_PRINT("    Creating client packet hook (2)...\n");
    {
        funcLength = FunctionLengths[Function_CMSG_Hook2];
        Replacement_Init(&replacement, DumpPacketReplacement, (DWORD_PTR)dumpPacketClient, FALSE);

        WSTC_PrepareToInject(Functions[Function_CMSG_Hook2], funcLength, &replacement, NULL);

        cmsgHook2 = WSTC_WriteCodeToProcess(wowProcess, Functions[Function_CMSG_Hook2], funcLength);
    }

    /* Writes a function to close packet dump file when disconnecting from the server
        Dependencies: Address of InjectedData structure in target process' memory
        */
    STATUS_PRINT("    Creating disconnection handler...\n");
    {
        funcLength = FunctionLengths[Function_DisconnectHandler];
        Replacement_Init(&replacement, InjectedDataAddress, (DWORD_PTR)injectedData, FALSE);

        WSTC_PrepareToInject(Functions[Function_DisconnectHandler], funcLength, &replacement, NULL);

        disconnectHandler = WSTC_WriteCodeToProcess(wowProcess, Functions[Function_DisconnectHandler], funcLength);
    }

    /* Writes a small function preparing call parameters for function closing dump file when disconnecting
        Dependencies: Address of function handling disconnection
        Base address of game process
        */
    STATUS_PRINT("    Creating disconnection hook...\n");
    {
        funcLength = FunctionLengths[Function_Disconnect_Hook];
        Replacement_Init(&replacement, DisconnectHandlerRplc, (DWORD_PTR)disconnectHandler, FALSE);

        WSTC_PrepareToInject(Functions[Function_Disconnect_Hook], funcLength, &replacement, NULL);

        disconnectHook = WSTC_WriteCodeToProcess(wowProcess, Functions[Function_Disconnect_Hook], funcLength);
    }

    // Writing JMP instructions to functions preparing parameters in client's code segment
    STATUS_PRINT("    Attaching packet hooks... ");

#ifdef _M_IX86

    WSTC_AttachHook(wowProcess, smsgHook, HookAddrSMSG, baseAddr, 0);
    WSTC_AttachHook(wowProcess, cmsgHook, HookAddrCMSG, baseAddr, 2);
    WSTC_AttachHook(wowProcess, cmsgHook2, HookAddrCMSG2, baseAddr, 2);
    WSTC_AttachHook(wowProcess, disconnectHook, HookAddrDisconnect, baseAddr, 0);

#else

    WSTC_AttachHook(wowProcess, smsgHook, HookAddrSMSG, baseAddr, 6);
    WSTC_AttachHook(wowProcess, cmsgHook, HookAddrCMSG, baseAddr, 0);
    WSTC_AttachHook(wowProcess, cmsgHook2, HookAddrCMSG2, baseAddr, 2);
    WSTC_AttachHook(wowProcess, disconnectHook, HookAddrDisconnect, baseAddr, 4);

#endif
    STATUS_PRINT("Success!\n");

    STATUS_PRINT("    Sniffer successfully loaded.\n");
    ConsolePrint("\n");
    CloseHandle(wowProcess);
    RemoteModule_Free(kernel32);
    RemoteModule_Free(user32);
    ConsolePrint("Welcome to WSTC Sniffer (%s, Version %s, Built %02hu/%02hu/%04hu %02hu:%02hu:%02hu (UTC))\n", machine, WSTC_VERSION_STRING, systemTime.wDay, systemTime.wMonth, systemTime.wYear, systemTime.wHour, systemTime.wMinute, systemTime.wSecond);
    ConsolePrint("Created by Shauren <shauren.trinity@gmail.com>\n");
    ConsolePrint("This sniffer is for World of Warcraft Client Build %u.\n", ClientBuild);
    ConsolePrint("Sniffer attached. No errors detected.\n");
    ConsolePrint("Remember to share sniffed data!\n");

    return EXCEPTION_CONTINUE_EXECUTION;
}

BOOL WINAPI DllMain(HANDLE hDllHandle, DWORD dwReason, LPVOID lpreserved)
{
    UNREFERENCED_PARAMETER(hDllHandle);
    UNREFERENCED_PARAMETER(dwReason);
    UNREFERENCED_PARAMETER(lpreserved);
    return TRUE;
}
