#ifndef Replacement_h__
#define Replacement_h__

#include <Windows.h>

#pragma pack(push, 1)

// Helper structure for address replacements when injecting
typedef struct Replacement_
{
    DWORD_PTR What;
    DWORD_PTR With;
    BOOL Rebase;
} Replacement;

#pragma pack(pop)

#ifdef __cplusplus
extern "C" {
#endif

void WINAPI Replacement_Init(Replacement* replacement, DWORD_PTR what, DWORD_PTR with, BOOL rebase);

#ifdef __cplusplus
}
#endif

#endif // Replacement_h__
