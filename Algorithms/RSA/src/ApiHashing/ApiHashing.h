#ifndef RSA_APIHASHING_H
#define RSA_APIHASHING_H
#include <windows.h>

DWORD getHashFromString(char *string);
PDWORD getFunctionAddressByHash(char *library, DWORD hash);

#endif //RSA_APIHASHING_H
