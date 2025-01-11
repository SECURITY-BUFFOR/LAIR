#include "RSA.h"
#include <stdio.h>
#include <stdlib.h>

void HandleError2(const char* msg, NTSTATUS status) {
    printf("%s (0x%x)\n", msg, status);
    exit(1);
}

void GenerateRSAKeyPair(BCRYPT_KEY_HANDLE *hKey, BYTE **publicKey, DWORD *publicKeyLength, BYTE **privateKey, DWORD *privateKeyLength) {
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    NTSTATUS status;

    // Open an algorithm handle
    status = _BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!_BCRYPT_SUCCESS(status)) {
        HandleError2("BCryptOpenAlgorithmProvider failed", status);
    }

    // Generate the key pair
    status = _BCryptGenerateKeyPair(hAlgorithm, hKey, 2048, 0);
    if (!_BCRYPT_SUCCESS(status)) {
        HandleError2("BCryptGenerateKeyPair failed", status);
    }

    // Finalize the key pair
    status = _BCryptFinalizeKeyPair(*hKey, 0);
    if (!_BCRYPT_SUCCESS(status)) {
        HandleError2("BCryptFinalizeKeyPair failed", status);
    }

    // Export the public key
    status = _BCryptExportKey(*hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, publicKeyLength, 0);
    if (!_BCRYPT_SUCCESS(status)) {
        HandleError2("BCryptExportKey (public) failed", status);
    }
    *publicKey = (BYTE*)malloc(*publicKeyLength);
    if (!*publicKey) {
        HandleError2("Memory allocation failed", status);
    }
    status = _BCryptExportKey(*hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, *publicKey, *publicKeyLength, publicKeyLength, 0);
    if (!_BCRYPT_SUCCESS(status)) {
        HandleError2("BCryptExportKey (public) failed", status);
    }

    // Export the private key
    status = _BCryptExportKey(*hKey, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, NULL, 0, privateKeyLength, 0);
    if (!_BCRYPT_SUCCESS(status)) {
        HandleError2("BCryptExportKey (private) failed", status);
    }
    *privateKey = (BYTE*)malloc(*privateKeyLength);
    if (!*privateKey) {
        HandleError2("Memory allocation failed", status);
    }
    status = _BCryptExportKey(*hKey, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, *privateKey, *privateKeyLength, privateKeyLength, 0);
    if (!_BCRYPT_SUCCESS(status)) {
        HandleError2("BCryptExportKey (private) failed", status);
    }

    // Clean up
    _BCryptCloseAlgorithmProvider(hAlgorithm, 0);
}
