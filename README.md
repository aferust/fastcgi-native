# fastcgi-native

Communicate with your FastCGI server easily using sockets in dlang.
- require no dependencies. Uses sockets.
- you need neither a confusing helper such as spawn-fcgi nor FastCGI C API, which is ugly.
- prepare your parameters as an associative array and pass it to your request. Your request will be converted into a packet that FastCGI protocol understands. Then get your server's output response (usually an http response) as a string.
- I only tested it on Windows. I cannot see a reason for it not to work anywhere else that d sockets available.

## usage
```
import fastcgi;

void main(){

    auto client = new FastCGIClient("127.0.0.1", 9000, 3, false);
    string content = ""; // your optional form data


	auto params = ["GATEWAY_INTERFACE": "FastCGI/1.0",
              "REQUEST_METHOD": "POST",
              "SCRIPT_FILENAME": "C:/Users/user/Desktop/test/index.php",
              //"QUERY_STRING": "",
              //"REQUEST_URI": "/",
              //"DOCUMENT_ROOT": "/",
              //"SERVER_SOFTWARE": "php/fcgiclient",
              //"REMOTE_ADDR": "127.0.0.1",
              //"REMOTE_PORT": "3001",
              //"SERVER_ADDR": "127.0.0.1",
              //"SERVER_PORT": "8080",
              //"SERVER_NAME": "localhost",
              //"SERVER_PROTOCOL": "HTTP/1.1",
              //"CONTENT_TYPE": "text/x-www-form-urlencoded",
              "CONTENT_LENGTH": content.length.to!string
	];
    writeln(client.request(params, content));

}
```
