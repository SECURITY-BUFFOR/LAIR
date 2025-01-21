#ifndef AES256_APIHASHING_H
#define AES256_APIHASHING_H
#include <windows.h>

DWORD getHashFromString(char *string);
PDWORD getFunctionAddressByHash(char *library, DWORD hash);

#endif //AES256_APIHASHING_H
