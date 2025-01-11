#include <stdio.h>
#include "src/defines.h"
#include "src/ApiHashing/ApiHashing.h"
#include "src/RSA//RSA.h"

void init_hashing() {
    PDWORD functionAddress = NULL;

    // BCRYPT32
    functionAddress = getFunctionAddressByHash((char *) "bcrypt", BCRYPTOPENALGORITHMPROVIDER);
    _BCryptOpenAlgorithmProvider = (_BCRYPTOPENALGORITHMPROVIDER) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "bcrypt", BCRYPTGENERATEKEYPAIR);
    _BCryptGenerateKeyPair = (_BCRYPTGENERATEKEYPAIR) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "bcrypt", BCRYPTFINALIZEKEYPAIR);
    _BCryptFinalizeKeyPair = (_BCRYPTFINALIZEKEYPAIR) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "bcrypt", BCRYPTEXPORTKEY);
    _BCryptExportKey = (_BCRYPTEXPORTKEY) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "bcrypt", BCRYPTCLOSEALGORITHMPROVIDER);
    _BCryptCloseAlgorithmProvider = (_BCRYPTCLOSEALGORITHMPROVIDER) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "bcrypt", BCRYPTDESTROYKEY);
    _BCryptDestroyKey = (_BCRYPTDESTROYKEY) functionAddress;

}
int main(void) {
    init_hashing();
    BCRYPT_KEY_HANDLE hKey = NULL;
    BYTE *publicKey = NULL;
    DWORD publicKeyLength = 0;
    BYTE *privateKey = NULL;
    DWORD privateKeyLength = 0;

    // Generate RSA Key Pair
    GenerateRSAKeyPair(&hKey, &publicKey, &publicKeyLength, &privateKey, &privateKeyLength);

    // Print the length of the keys (for demonstration purposes)
    printf("Public Key Length: %lu bytes\n", publicKeyLength);
    printf("Private Key Length: %lu bytes\n", privateKeyLength);

    printf("Public Key:\n");
    for (DWORD i = 0; i < publicKeyLength; ++i) {
        printf("%02X", publicKey[i]);
    }
    printf("\n");

    printf("Private Key:\n");
    for (DWORD i = 0; i < privateKeyLength; ++i) {
        printf("%02X", privateKey[i]);
    }
    printf("\n");

    // Clean up allocated memory
    free(publicKey);
    free(privateKey);

    // Close the key handle
    if (hKey) {
        _BCryptDestroyKey(hKey);
    }

    return 0;
}