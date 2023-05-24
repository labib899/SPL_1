#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H



#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <map>
#include <iterator>



using namespace std;


#define ff first
#define ss second



struct HttpHeaders 
{
    vector<pair<string,string>> headers;
};



struct HttpRequest 
{   
    // request line has three parts : method, URL, version
    string method;
    string url;
    string version;

    // header line
    HttpHeaders headers;

    // entity body
    string body;
};



struct HttpResponse 
{   
    // status line has three parts : version, status code, status message
    string version;
    string statusCode;
    string statusMessage;

    // header line
    HttpHeaders headers;

    // entity body
    string body;
};




// Function to parse HTTP headers
HttpHeaders parseHttpHeaders(const string& headers) 
{
    HttpHeaders httpHeaders;

    int headerPos = 0;
    while (headerPos < headers.size()) 
    {   
        // finding the end of the line
        int lineEndPos = headers.find("\r\n", headerPos);
        if (lineEndPos == -1) // -1 refers not found
        {
            break; // Invalid header format
        }

        string headerLine = headers.substr(headerPos, lineEndPos - headerPos);
        if (headerLine.empty()) 
        {
            break; // End of headers
        }

        // finding the colon for key and value
        int colonPos = headerLine.find(":");
        if (colonPos != -1) 
        {
            string key = headerLine.substr(0, colonPos);
            string value = headerLine.substr(colonPos + 1);

            // Remove leading/trailing whitespaces from header values
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            httpHeaders.headers.push_back(make_pair(key, value));
        }

        headerPos = lineEndPos + 2;
    }

    return httpHeaders;
}




// Function to parse HTTP request
HttpRequest parseHttpRequest(const string& httpRequest) 
{
    HttpRequest request;
    

    // Finding the request line
    int lineEndPos = httpRequest.find("\r\n");
    if (lineEndPos == -1) 
    {
        // Invalid HTTP request
        return request;
    }

    string requestLine = httpRequest.substr(0, lineEndPos);

    // Split the request line into method, URL, and version
    int methodPos = 0;
    int urlPos = requestLine.find(" ");
    if (urlPos != -1) 
    {
        request.method = requestLine.substr(methodPos, urlPos - methodPos);
        int versionPos = requestLine.find(" ", urlPos + 1);
        if (versionPos != string::npos) 
        {
            request.url = requestLine.substr(urlPos + 1, versionPos - urlPos - 1);
            request.version = requestLine.substr(versionPos + 1);
        }
    }

    // Find and extract headers
    int headersPos = lineEndPos + 2;
    int bodyPos = httpRequest.find("\r\n\r\n", headersPos);
    if (bodyPos != -1) 
    {
        string headers = httpRequest.substr(headersPos, bodyPos - headersPos);
        request.headers = parseHttpHeaders(headers);
        request.body = httpRequest.substr(bodyPos + 4);
    } 
    else 
    {
        string headers = httpRequest.substr(headersPos);
        request.headers = parseHttpHeaders(headers);
        request.body = "";
    }

    return request;
}




// Function to parse HTTP response
HttpResponse parseHttpResponse(const string& httpResponse) 
{
    HttpResponse response;
    

    // fnding the status line
    int lineEndPos = httpResponse.find("\r\n");
    if (lineEndPos == -1) 
    {
        // Invalid HTTP response
        return response;
    }

    string statusLine = httpResponse.substr(0, lineEndPos);

    // splitting the status line into version, status code, and status message
    int versionPos = 0;
    int statusCodePos = statusLine.find(" ");
    if (statusCodePos != -1) 
    {
        response.version = statusLine.substr(versionPos, statusCodePos - versionPos);
        int statusMessagePos = statusLine.find(" ", statusCodePos + 1);
        if (statusMessagePos != -1) 
        {
            response.statusCode = statusLine.substr(statusCodePos + 1, statusMessagePos - statusCodePos - 1);
            response.statusMessage = statusLine.substr(statusMessagePos + 1);
        }
    }

    // finding and extracting headers
    int headersPos = lineEndPos + 2;
    int bodyPos = httpResponse.find("\r\n\r\n", headersPos);
    if (bodyPos != -1) 
    {
        string headers = httpResponse.substr(headersPos, bodyPos - headersPos);
        response.headers = parseHttpHeaders(headers);
        response.body = httpResponse.substr(bodyPos + 4);
    } 
    else 
    {
        string headers = httpResponse.substr(headersPos);
        response.headers = parseHttpHeaders(headers);
        response.body = "";
    }

    return response;
}




void printHttpRequest(HttpRequest& request)
{   
    bool f=1;

    if(request.method.empty()) f=0;
    if(request.url.empty()) f=0;
    if(request.version.empty()) f=0;

    if(f==0) return;

    // printing the parsed request
    cout << "HTTP Request:" << endl;

    cout << "Method: " ;
    if(request.method.find("GET")) cout<<"GET"<<endl;
    else if(request.method.find("POST")) cout<<"POST"<<endl;
    else if(request.method.find("HEAD")) cout<<"HEAD"<<endl;
    else if(request.method.find("PUT")) cout<<"PUT"<<endl;
    else if(request.method.find("DELETE")) cout<<"DELETE"<<endl;

    cout << "URL: " << request.url << endl;
    cout << "Version: " << request.version << endl;
    //cout << "Headers:" << endl;
    for (const auto& header : request.headers.headers) 
    {
        cout << header.ff << ": " << header.ss << endl;
    }


    cout << "Body: " << endl;
    cout << request.body << endl;

    cout << endl;
}




void printHttpResponse(HttpResponse& response)
{   
    bool f=1;

    if(response.version.empty()) f=0;
    if(response.statusCode.empty()) f=0;
    if(response.statusMessage.empty()) f=0;

    if(f==0) return;

    // printing the parsed response
    cout << "HTTP Response:" << endl;

    cout << "Version: " ;

    int i=response.version.find("HTTP");
    if(i!=-1)
    {
        response.version.erase(0,i);
    }
    cout<<response.version<<endl;

    cout << "Status Code: " << response.statusCode << endl;
    cout << "Status Message: " << response.statusMessage << endl;
    //cout << "Headers:" << endl;
    for (const auto& header : response.headers.headers) 
    {
        cout << header.ff << ": " << header.ss << endl;
    }


    cout << "Body: " << endl;
    cout << response.body << endl;

    cout << endl;
}




#endif
