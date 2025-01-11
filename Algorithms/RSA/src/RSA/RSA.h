#ifndef RSA_RSA_H
#define RSA_RSA_H
#include <windows.h>
#include "../defines.h"

void GenerateRSAKeyPair(BCRYPT_KEY_HANDLE *hKey, BYTE **publicKey, DWORD *publicKeyLength, BYTE **privateKey, DWORD *privateKeyLength);

#endif //RSA_RSA_H
