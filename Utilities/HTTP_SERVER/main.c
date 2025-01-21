#include "src/ApiHashing/ApiHashing.h"
#include "src/defines.h"
#include <stdio.h>

#define BUFFER_SIZE 4096

void init_hashing() {
    PDWORD functionAddress = NULL;

    // HTTPAPI
    functionAddress = getFunctionAddressByHash((char *) "httpapi", HTTPINITIALIZE);
    _HttpInitialize = (_HTTPINITIALIZE) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "httpapi", HTTPTERMINATE);
    _HttpTerminate = (_HTTPTERMINATE) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "httpapi", HTTPCREATEHTTPHANDLE);
    _HttpCreateHttpHandle = (_HTTPCREATEHTTPHANDLE) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "httpapi", HTTPADDURL);
    _HttpAddUrl = (_HTTPADDURL) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "httpapi", HTTPREMOVEURL);
    _HttpRemoveUrl = (_HTTPREMOVEURL) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "httpapi", HTTPRECEIVEHTTPREQUEST);
    _HttpReceiveHttpRequest = (_HTTPRECEIVEHTTPREQUEST) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "httpapi", HTTPSENDHTTPRESPONSE);
    _HttpSendHttpResponse = (_HTTPSENDHTTPRESPONSE) functionAddress;

    // KERNEL32
}

void run_http_server() {
    ULONG result;
    HTTPAPI_VERSION httpVersion = HTTPAPI_VERSION_1; // Use HTTPAPI_VERSION_1
    HANDLE requestQueue = NULL;
    HTTP_REQUEST* request;
    HTTP_RESPONSE response;
    ULONG bytesReceived;
    BOOL running = TRUE;

    // Initialize HTTP Server API
    result = _HttpInitialize(httpVersion, HTTP_INITIALIZE_SERVER, NULL);
    if (result != NO_ERROR) {
        printf("HttpInitialize failed: %lu\n", result);
        return;
    }

    // Create HTTP Request Queue
    result = _HttpCreateHttpHandle(&requestQueue, 0);
    if (result != NO_ERROR) {
        printf("HttpCreateHttpHandle failed: %lu\n", result);
        _HttpTerminate(HTTP_INITIALIZE_SERVER, NULL);
        return;
    }

    // Add URL to the request queue
    result = _HttpAddUrl(requestQueue, L"http://localhost:8080/", NULL);
    if (result != NO_ERROR) {
        printf("HttpAddUrl failed: %lu\n", result);
        CloseHandle(requestQueue);
        _HttpTerminate(HTTP_INITIALIZE_SERVER, NULL);
        return;
    }

    printf("Listening on http://localhost:8080/\n");

    // Allocate memory for HTTP request
    request = (HTTP_REQUEST*)malloc(BUFFER_SIZE);
    if (!request) {
        printf("Memory allocation failed\n");
        _HttpRemoveUrl(requestQueue, L"http://localhost:8080/");
        CloseHandle(requestQueue);
        _HttpTerminate(HTTP_INITIALIZE_SERVER, NULL);
        return;
    }

    // Listen for incoming requests
    while (running) {
        RtlZeroMemory(request, BUFFER_SIZE);

        // Receive an HTTP request
        result = _HttpReceiveHttpRequest(requestQueue, 0, 0, request, BUFFER_SIZE, &bytesReceived, NULL);
        if (result == NO_ERROR) {
            printf("Received request for: %ws\n", request->CookedUrl.pFullUrl);

            // Prepare HTTP response
            RtlZeroMemory(&response, sizeof(HTTP_RESPONSE));
            response.StatusCode = 200;
            response.pReason = "OK";
            response.ReasonLength = (USHORT)strlen("OK");

            HTTP_DATA_CHUNK dataChunk;
            const char* responseBody = "Hello, World!";
            dataChunk.DataChunkType = HttpDataChunkFromMemory;
            dataChunk.FromMemory.pBuffer = (PVOID)responseBody;
            dataChunk.FromMemory.BufferLength = (ULONG)strlen(responseBody);

            response.EntityChunkCount = 1;
            response.pEntityChunks = &dataChunk;

            // Send HTTP response
            result = _HttpSendHttpResponse(requestQueue, request->RequestId, 0, &response, NULL, NULL, NULL, 0, NULL, NULL);
            if (result != NO_ERROR) {
                printf("HttpSendHttpResponse failed: %lu\n", result);
            }
        } else {
            printf("HttpReceiveHttpRequest failed: %lu\n", result);
            if (result == ERROR_OPERATION_ABORTED) {
                printf("Server shutting down...\n");
                running = FALSE;
            }
        }
    }

    // Clean up resources
    free(request);
    _HttpRemoveUrl(requestQueue, L"http://localhost:8080/");
    CloseHandle(requestQueue);
    _HttpTerminate(HTTP_INITIALIZE_SERVER, NULL);

}

int main() {

    init_hashing();
    run_http_server();
    return 0;
}
