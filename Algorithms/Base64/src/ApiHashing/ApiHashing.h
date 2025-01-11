#ifndef BASE64_APIHASHING_H
#define BASE64_APIHASHING_H
#include <windows.h>

DWORD getHashFromString(char *string);
PDWORD getFunctionAddressByHash(char *library, DWORD hash);

#endif //BASE64_APIHASHING_H
