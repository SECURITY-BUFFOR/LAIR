#ifndef HTTP_SERVER_DEFINES_H
#define HTTP_SERVER_DEFINES_H

#include <http.h>

#pragma region HTTPAPI
#define HTTPINITIALIZE 0x3564326b
#define HTTPCREATEHTTPHANDLE 0xc307aa4b
#define HTTPTERMINATE 0xfb2144e4
#define HTTPADDURL 0xdb64264d
#define HTTPREMOVEURL 0xe6f59776
#define HTTPRECEIVEHTTPREQUEST 0xb53200c7
#define HTTPSENDHTTPRESPONSE 0x46787fcc
#define ERROR_OPERATION_ABORTED 995L


typedef ULONG (WINAPI *_HTTPINITIALIZE)(HTTPAPI_VERSION Version, ULONG Flags, PVOID pReserved);
typedef ULONG (WINAPI *_HTTPTERMINATE)(ULONG Flags, PVOID pReserved);
typedef ULONG (WINAPI *_HTTPCREATEHTTPHANDLE)(PHANDLE pReqQueueHandle, ULONG Options);
typedef ULONG (WINAPI *_HTTPADDURL)(HANDLE ReqQueueHandle, PCWSTR pUrlPrefix, PVOID pReserved);
typedef ULONG (WINAPI *_HTTPREMOVEURL)(HANDLE ReqQueueHandle, PCWSTR pUrlPrefix);
typedef ULONG (WINAPI *_HTTPRECEIVEHTTPREQUEST)(HANDLE ReqQueueHandle, HTTP_REQUEST_ID RequestId, ULONG Flags, PHTTP_REQUEST pRequestBuffer, ULONG RequestBufferLength, PULONG pBytesReceived, LPOVERLAPPED pOverlapped);
typedef ULONG (WINAPI *_HTTPSENDHTTPRESPONSE)(HANDLE ReqQueueHandle, HTTP_REQUEST_ID RequestId, ULONG Flags, PHTTP_RESPONSE pHttpResponse, PVOID pReserved1, PULONG pBytesSent, PVOID pReserved2, ULONG Reserved3, LPOVERLAPPED pOverlapped, PVOID pReserved4);

extern _HTTPINITIALIZE _HttpInitialize;
extern _HTTPTERMINATE _HttpTerminate;
extern _HTTPCREATEHTTPHANDLE _HttpCreateHttpHandle;
extern _HTTPADDURL _HttpAddUrl;
extern _HTTPREMOVEURL _HttpRemoveUrl;
extern _HTTPRECEIVEHTTPREQUEST _HttpReceiveHttpRequest;
extern _HTTPSENDHTTPRESPONSE _HttpSendHttpResponse;
#pragma endregion




#pragma endregion

#endif //HTTP_SERVER_DEFINES_H
