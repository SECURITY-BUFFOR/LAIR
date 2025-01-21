#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include "src/defines.h"
#include "src/ApiHashing/ApiHashing.h"

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32

char *aes256_encrypt(const char *input, const unsigned char *key, size_t *output_len) {
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbKeyObject = 0, cbData = 0, cbCipherText = 0;
    PBYTE pbKeyObject = NULL;
    PBYTE pbCipherText = NULL;
    PBYTE pbIV = NULL;
    NTSTATUS status;
    char *output = NULL;

    // Open an algorithm handle
    status = _BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Failed to open algorithm provider: 0x%x\n", status);
        return NULL;
    }

    // Set the chaining mode to CBC
    status = _BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Failed to set chaining mode: 0x%x\n", status);
        goto cleanup;
    }

    // Calculate the size of the key object
    status = _BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(cbKeyObject), &cbData, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Failed to get object length: 0x%x\n", status);
        goto cleanup;
    }

    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (!pbKeyObject) {
        fprintf(stderr, "Memory allocation failed for key object\n");
        goto cleanup;
    }

    // Generate the key
    status = _BCryptGenerateSymmetricKey(hAlgorithm, &hKey, pbKeyObject, cbKeyObject, (PUCHAR)key, AES_KEY_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Failed to generate symmetric key: 0x%x\n", status);
        goto cleanup;
    }

    // Allocate IV (initialization vector)
    pbIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, AES_BLOCK_SIZE);
    if (!pbIV) {
        fprintf(stderr, "Memory allocation failed for IV\n");
        goto cleanup;
    }
    ZeroMemory(pbIV, AES_BLOCK_SIZE);

    // Calculate the required buffer size for ciphertext
    status = _BCryptEncrypt(hKey, (PUCHAR)input, (ULONG)strlen(input), NULL, pbIV, AES_BLOCK_SIZE, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Failed to calculate ciphertext size: 0x%x\n", status);
        goto cleanup;
    }

    pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
    if (!pbCipherText) {
        fprintf(stderr, "Memory allocation failed for ciphertext\n");
        goto cleanup;
    }

    // Perform the encryption
    status = _BCryptEncrypt(hKey, (PUCHAR)input, (ULONG)strlen(input), NULL, pbIV, AES_BLOCK_SIZE, pbCipherText, cbCipherText, &cbData, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Encryption failed: 0x%x\n", status);
        goto cleanup;
    }

    // Allocate output buffer and copy ciphertext
    output = (char *)HeapAlloc(GetProcessHeap(), 0, cbData);
    if (!output) {
        fprintf(stderr, "Memory allocation failed for output\n");
        goto cleanup;
    }
    memcpy(output, pbCipherText, cbData);
    *output_len = cbData;

    cleanup:
    if (hAlgorithm) _BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (hKey) _BCryptDestroyKey(hKey);
    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (pbCipherText) HeapFree(GetProcessHeap(), 0, pbCipherText);
    if (pbIV) HeapFree(GetProcessHeap(), 0, pbIV);

    return output;
}

char *aes256_decrypt(const char *input, size_t input_len, const unsigned char *key, size_t *output_len) {
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbKeyObject = 0, cbData = 0, cbPlainText = 0;
    PBYTE pbKeyObject = NULL;
    PBYTE pbPlainText = NULL;
    PBYTE pbIV = NULL;
    NTSTATUS status;
    char *output = NULL;

    // Open an algorithm handle
    status = _BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Failed to open algorithm provider: 0x%x\n", status);
        return NULL;
    }

    // Set the chaining mode to CBC
    status = _BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Failed to set chaining mode: 0x%x\n", status);
        goto cleanup;
    }

    // Calculate the size of the key object
    status = _BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(cbKeyObject), &cbData, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Failed to get object length: 0x%x\n", status);
        goto cleanup;
    }

    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (!pbKeyObject) {
        fprintf(stderr, "Memory allocation failed for key object\n");
        goto cleanup;
    }

    // Generate the key
    status = _BCryptGenerateSymmetricKey(hAlgorithm, &hKey, pbKeyObject, cbKeyObject, (PUCHAR)key, AES_KEY_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Failed to generate symmetric key: 0x%x\n", status);
        goto cleanup;
    }

    // Allocate IV (initialization vector)
    pbIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, AES_BLOCK_SIZE);
    if (!pbIV) {
        fprintf(stderr, "Memory allocation failed for IV\n");
        goto cleanup;
    }
    ZeroMemory(pbIV, AES_BLOCK_SIZE);

    // Calculate the required buffer size for plaintext
    status = _BCryptDecrypt(hKey, (PUCHAR)input, (ULONG)input_len, NULL, pbIV, AES_BLOCK_SIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Failed to calculate plaintext size: 0x%x\n", status);
        goto cleanup;
    }

    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (!pbPlainText) {
        fprintf(stderr, "Memory allocation failed for plaintext\n");
        goto cleanup;
    }

    // Perform the decryption
    status = _BCryptDecrypt(hKey, (PUCHAR)input, (ULONG)input_len, NULL, pbIV, AES_BLOCK_SIZE, pbPlainText, cbPlainText, &cbData, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Decryption failed: 0x%x\n", status);
        goto cleanup;
    }

    // Allocate output buffer and copy plaintext
    output = (char *)HeapAlloc(GetProcessHeap(), 0, cbData + 1); // Add 1 for null terminator
    if (!output) {
        fprintf(stderr, "Memory allocation failed for output\n");
        goto cleanup;
    }
    memcpy(output, pbPlainText, cbData);
    output[cbData] = '\0'; // Null-terminate the string
    *output_len = cbData;

    cleanup:
    if (hAlgorithm) _BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (hKey) _BCryptDestroyKey(hKey);
    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (pbPlainText) HeapFree(GetProcessHeap(), 0, pbPlainText);
    if (pbIV) HeapFree(GetProcessHeap(), 0, pbIV);

    return output;
}

void init_hashing() {
    PDWORD functionAddress = NULL;

    functionAddress = getFunctionAddressByHash((char *) "bcrypt", BCRYPTOPENALGORITHMPROVIDER);
    _BCryptOpenAlgorithmProvider = (_BCRYPTOPENALGORITHMPROVIDER) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "bcrypt", BCRYPTCLOSEALGORITHMPROVIDER);
    _BCryptCloseAlgorithmProvider = (_BCRYPTCLOSEALGORITHMPROVIDER) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "bcrypt", BCRYPTENCRYPT);
    _BCryptEncrypt = (_BCRYPTENCRYPT) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "bcrypt", BCRYPTDECRYPT);
    _BCryptDecrypt = (_BCRYPTDECRYPT) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "bcrypt", BCRYPTDESTROYKEY);
    _BCryptDestroyKey = (_BCRYPTDESTROYKEY) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "bcrypt", BCRYPTGENERATESYMMETRICKEY);
    _BCryptGenerateSymmetricKey = (_BCRYPTGENERATESYMMETRICKEY) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "bcrypt", BCRYPTSETPROPERTY);
    _BCryptSetProperty = (_BCRYPTSETPROPERTY) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "bcrypt", BCRYPTGETPROPERTY);
    _BCryptGetProperty = (_BCRYPTGETPROPERTY) functionAddress;


}

int main() {
    init_hashing();
    const char *plaintext = "This is a test string.";
    unsigned char key[AES_KEY_SIZE] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    size_t encrypted_len;
    char *encrypted = aes256_encrypt(plaintext, key, &encrypted_len);

    if (encrypted) {
        printf("Encrypted data:\n");
        for (size_t i = 0; i < encrypted_len; i++) {
            printf("%02x", (unsigned char)encrypted[i]);
        }
        printf("\n");

        size_t decrypted_len;
        char *decrypted = aes256_decrypt(encrypted, encrypted_len, key, &decrypted_len);

        if (decrypted) {
            printf("Decrypted data: %s\n", decrypted);
            HeapFree(GetProcessHeap(), 0, decrypted);
        } else {
            printf("Decryption failed.\n");
        }

        HeapFree(GetProcessHeap(), 0, encrypted);
    } else {
        printf("Encryption failed.\n");
    }

    return 0;
}
