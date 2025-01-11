#ifndef BASE64_DEFINES_H
#define BASE64_DEFINES_H

#include <windows.h>

// CRYPT32
#define CRYPTSTRINGTOBINARYA 0x6c40a739
#define CRYPTBINARYTOSTRINGA 0x76ef2489

// CRYPT32
typedef BOOL (WINAPI *_CRYPTBINARYTOSTRINGA)(const BYTE *pbBinary, DWORD cbBinary, DWORD dwFlags, LPSTR pszString, DWORD *pcchString);
typedef BOOL (WINAPI *_CRYPTSTRINGTOBINARYA)(LPCSTR pszString, DWORD cchString, DWORD dwFlags, BYTE *pbBinary, DWORD *pcbBinary, DWORD *pdwSkip, DWORD *pdwFlags);


// CRYPT32
extern _CRYPTSTRINGTOBINARYA _CryptStringToBinaryA;
extern _CRYPTBINARYTOSTRINGA _CryptBinaryToStringA;


#endif //BASE64_DEFINES_H
