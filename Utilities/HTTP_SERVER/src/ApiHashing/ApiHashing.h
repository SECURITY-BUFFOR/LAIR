#ifndef HTTP_SERVER_API_HASHING_H
#define HTTP_SERVER_API_HASHING_H

#include <windows.h>

DWORD getHashFromString(char *string);
PDWORD getFunctionAddressByHash(char *library, DWORD hash);

#endif //HTTP_SERVER_API_HASHING_H
