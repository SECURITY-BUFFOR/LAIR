#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

// FNV-1a 32-bit hash function
DWORD getFNV1aHash(const char *string) {
    size_t len = strlen(string);
    DWORD hash = 0x811c9dc5;  // FNV-1a 32-bit hash initial value

    for (size_t i = 0; i < len; i++) {
        hash ^= (unsigned char)string[i];
        hash *= 0x01000193;  // FNV-1a 32-bit prime
    }

    return hash;
}

int main() {
    FILE *file = fopen("functions.txt", "r");
    if (file == NULL) {
        perror("Error opening functions.txt file");
        return 1;
    }

    char functionName[256];

    while (fgets(functionName, sizeof(functionName), file) != NULL) {
        // Remove trailing newline character, if present
        size_t len = strlen(functionName);
        if (len > 0 && functionName[len - 1] == '\n') {
            functionName[len - 1] = '\0';
        }

        printf("Hash for %s: 0x%08x\n", functionName, getFNV1aHash(functionName));
    }

    fclose(file);
    return 0;
}
