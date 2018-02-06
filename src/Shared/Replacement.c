
#include "Replacement.h"

void WINAPI Replacement_Init(Replacement* replacement, DWORD_PTR what, DWORD_PTR with, BOOL rebase)
{
    replacement->What = what;
    replacement->With = with;
    replacement->Rebase = rebase;
}
