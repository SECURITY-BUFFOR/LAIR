#ifndef BASE64_H
#define BASE64_H

#include <Windows.h>

BOOL Base64Encode(const char* text, char** base64);
BOOL Base64Decode(const char* base64Input, char** outputText);

#endif //BASE64_H
