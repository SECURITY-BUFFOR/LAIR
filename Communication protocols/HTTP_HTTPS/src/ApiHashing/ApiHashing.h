#ifndef HTTP_TRANSPORT_APIHASHING_H
#define HTTP_TRANSPORT_APIHASHING_H
#include <windows.h>

DWORD getHashFromString(char *string);
PDWORD getFunctionAddressByHash(char *library, DWORD hash);

#endif //HTTP_TRANSPORT_APIHASHING_H
