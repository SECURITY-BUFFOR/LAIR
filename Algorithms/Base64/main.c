#include <stdio.h>
#include "src/defines.h"
#include "src/ApiHashing/ApiHashing.h"
#include "src/Base64/Base64.h"

void init_hashing() {
    PDWORD functionAddress = NULL;

    // CRYPT32
    functionAddress = getFunctionAddressByHash((char *) "crypt32", CRYPTBINARYTOSTRINGA);
    _CryptBinaryToStringA = (_CRYPTBINARYTOSTRINGA) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "crypt32", CRYPTSTRINGTOBINARYA);
    _CryptStringToBinaryA = (_CRYPTSTRINGTOBINARYA) functionAddress;

}

int main(void) {
    init_hashing();

    char *base64, *decoded, *text = "Hello World!";

    Base64Encode(text, &base64);
    printf("Encoded: %s\n", base64);
    Base64Decode(base64, &decoded);
    printf("Decoded: %s\n", decoded);

    return 0;
}