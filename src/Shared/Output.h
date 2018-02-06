#ifndef Output_h__
#define Output_h__

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

void WINAPIV ConsolePrint(char const* format, ...);
void WINAPIV ErrorPrint(char const* format, ...);
void WINAPIV DebugPrint(char const* format, ...);

#ifdef __cplusplus
}
#endif

#endif // Output_h__
