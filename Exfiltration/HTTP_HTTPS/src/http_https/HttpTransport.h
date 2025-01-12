#ifndef HTTPTRANSPORT_H
#define HTTPTRANSPORT_H

#include <windows.h>
#include "../defines.h"
#include <stdio.h>

typedef struct {
    DWORD statusCode;
    char* responseText;
} HttpResponse;

HttpResponse SendGet(const char* url, const char* urlpath, const char* headers, BOOL ssl);

HttpResponse SendPost(const char* url, const char* urlpath, const char* headers, const char* body, BOOL ssl);
#endif //HTTPTRANSPORT_H
