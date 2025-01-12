#include <stdlib.h>
#include <stdio.h>
#include "HttpTransport.h"

HttpResponse SendHttpRequest(const char* url, const char* urlpath, const char* post_data, const char* headers, BOOL ssl, BOOL is_post) {
    HttpResponse response;
    response.statusCode = 0;
    response.responseText = NULL;

    HINTERNET hSession = _WinHttpOpen(L"Client App/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        printf("WinHttpOpen failed\n");
        response.statusCode = GetLastError();
        return response;
    }

    URL_COMPONENTS urlComp;
    memset(&urlComp, 0, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    WCHAR hostname[256];
    WCHAR path[1024];
    urlComp.lpszHostName = hostname;
    urlComp.dwHostNameLength = sizeof(hostname) / sizeof(WCHAR);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = sizeof(path) / sizeof(WCHAR);

    int urlLength = _MultiByteToWideChar(0, 0, url, -1, NULL, 0);
    WCHAR* wideUrl = (WCHAR*)malloc(urlLength * sizeof(WCHAR));
    _MultiByteToWideChar(0, 0, url, -1, wideUrl, urlLength);

    if (!_WinHttpCrackUrl(wideUrl, (DWORD)wcslen(wideUrl), 0, &urlComp)) {
        printf("WinHttpCrackUrl failed\n");
        free(wideUrl);
        _WinHttpCloseHandle(hSession);
        response.statusCode = GetLastError();
        return response;
    }
    free(wideUrl);

    HINTERNET hConnect = _WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (!hConnect) {
        printf("WinHttpConnect failed\n");
        _WinHttpCloseHandle(hSession);
        response.statusCode = GetLastError();
        return response;
    }

    int urlpathLength = _MultiByteToWideChar(0, 0, urlpath, -1, NULL, 0);
    WCHAR* wideUrlPath = (WCHAR*)malloc(urlpathLength * sizeof(WCHAR));
    _MultiByteToWideChar(0, 0, urlpath, -1, wideUrlPath, urlpathLength);

    LPCWSTR pwszVerb = is_post ? L"POST" : L"GET";
    HINTERNET hRequest = _WinHttpOpenRequest(hConnect, pwszVerb, wideUrlPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, ssl ? WINHTTP_FLAG_SECURE : 0);
    free(wideUrlPath);
    if (!hRequest) {
        printf("WinHttpOpenRequest failed, %d\n", GetLastError());
        _WinHttpCloseHandle(hConnect);
        _WinHttpCloseHandle(hSession);
        response.statusCode = GetLastError();
        return response;
    }

    int headersLength = _MultiByteToWideChar(0, 0, headers, -1, NULL, 0);
    WCHAR* wideHeaders = (WCHAR*)malloc(headersLength * sizeof(WCHAR));
    _MultiByteToWideChar(0, 0, headers, -1, wideHeaders, headersLength);


    BOOL bResults;
    if (is_post) {
        bResults = _WinHttpSendRequest(hRequest, wideHeaders, 0, (LPVOID)post_data, (DWORD)strlen(post_data), (DWORD)strlen(post_data), 0);
    } else {
        bResults = _WinHttpSendRequest(hRequest, wideHeaders, 0, NULL, 0, 0, 0);
    }

    if (!bResults) {
        printf("WinHttpSendRequest failed, %lu\n", GetLastError());
        _WinHttpCloseHandle(hRequest);
        _WinHttpCloseHandle(hConnect);
        _WinHttpCloseHandle(hSession);
        response.statusCode = GetLastError();
        return response;
    }

    bResults = _WinHttpReceiveResponse(hRequest, NULL);
    if (!bResults) {
        printf("WinHttpReceiveResponse failed\n");
        _WinHttpCloseHandle(hRequest);
        _WinHttpCloseHandle(hConnect);
        _WinHttpCloseHandle(hSession);
        response.statusCode = GetLastError();
        return response;
    }

    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    DWORD totalSize = 0;
    LPSTR responseText = (LPSTR)malloc(1);
    *responseText = '\0';

    do {
        if (!_WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            printf("WinHttpQueryDataAvailable failed\n");
            break;
        }

        pszOutBuffer = (LPSTR)malloc(dwSize + 1);
        if (!pszOutBuffer) {
            printf("Out of memory\n");
            break;
        }

        ZeroMemory(pszOutBuffer, dwSize + 1);

        if (!_WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {
            printf("WinHttpReadData failed\n");
            free(pszOutBuffer);
            break;
        }

        totalSize += dwDownloaded;
        responseText = (LPSTR)realloc(responseText, totalSize + 1);
        strcat(responseText, pszOutBuffer);
        free(pszOutBuffer);

    } while (dwSize > 0);

    _WinHttpCloseHandle(hRequest);
    _WinHttpCloseHandle(hConnect);
    _WinHttpCloseHandle(hSession);

    response.statusCode = 200;
    response.responseText = responseText;
    return response;
}

HttpResponse SendGet(const char* url, const char* urlpath, const char* headers, BOOL ssl) {
    return SendHttpRequest(url, urlpath, NULL, headers, ssl, FALSE);
}

HttpResponse SendPost(const char* url, const char* urlpath, const char* headers, const char* body, BOOL ssl) {
    return SendHttpRequest(url, urlpath, body, headers, ssl, TRUE);
}