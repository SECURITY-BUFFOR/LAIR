#include <stdio.h>
#include "src/defines.h"
#include "src/http_https/HttpTransport.h"
#include "src/ApiHashing/ApiHashing.h"

void init_hashing() {
    PDWORD functionAddress = NULL;
    functionAddress = getFunctionAddressByHash((char *) "winhttp", WINHTTPOPEN);
    _WinHttpOpen = (_WINHTTPOPEN) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "winhttp", WINHTTPCONNECT);
    _WinHttpConnect = (_WINHTTPCONNECT) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "winhttp", WINHTTPOPENREQUEST);
    _WinHttpOpenRequest = (_WINHTTPOPENREQUEST) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "winhttp", WINHTTPSENDREQUEST);
    _WinHttpSendRequest = (_WINHTTPSENDREQUEST) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "winhttp", WINHTTPRECEIVERESPONSE);
    _WinHttpReceiveResponse = (_WINHTTPRECEIVERESPONSE) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "winhttp", WINHTTPQUERYDATAAVAILABLE);
    _WinHttpQueryDataAvailable = (_WINHTTPQUERYDATAAVAILABLE) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "winhttp", WINHTTPREADDATA);
    _WinHttpReadData = (_WINHTTPREADDATA) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "winhttp", WINHTTPCLOSEHANDLE);
    _WinHttpCloseHandle = (_WINHTTPCLOSEHANDLE) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "winhttp", WINHTTPCRACKURL);
    _WinHttpCrackUrl = (_WINHTTPCRACKURL) functionAddress;

    functionAddress = getFunctionAddressByHash((char *) "kernel32", MULTIBYTETOWIDECHAR);
    _MultiByteToWideChar = (_MULTIBYTETOWIDECHAR) functionAddress;

}

int main(void) {
    init_hashing();

    const char* url = "http://url:port"; // Replace with the desired IP address
    const char* urlpath = "/";
    const char* headers = "User-Agent: MyTestApp/1.0\r\nContent-Type: application/json\r\n";
    const char* postBody = "{\"data\":{\"key\":\"value\"}}";


    HttpResponse response = SendGet(url, urlpath, headers, FALSE);

    printf("GET Request:\n");
    printf("Status Code: %lu\n", response.statusCode);
    printf("Response Text: %s\n", response.responseText ? response.responseText : "NULL");



    printf("\nSending POST request...\n");
    HttpResponse postResponse = SendPost(url, urlpath, headers, postBody, FALSE);

    printf("POST Response:\n");
    printf("Status Code: %lu\n", postResponse.statusCode);
    printf("Response Text: %s\n", postResponse.responseText ? postResponse.responseText : "NULL");
    if (response.responseText) {
        free(response.responseText);
    }
    return 0;
}