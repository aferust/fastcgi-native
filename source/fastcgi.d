module fastcgi;

import std.socket;
import std.conv;
import std.algorithm;
import std.range;
import std.experimental.logger;
import std.random;
import std.datetime;
import std.utf;
import std.typecons;

struct FastCGIHeader {
    ubyte _version;
    ubyte type;
    ushort requestId;
    ushort contentLength;
    ubyte paddingLength;
    ubyte reserved;
    string content;
}

final class FastCGIClient {
    private {
        static immutable FCGI_VERSION = 1;
        static immutable FCGI_ROLE_RESPONDER = 1;
        static immutable FCGI_ROLE_AUTHORIZER = 2;
        static immutable FCGI_ROLE_FILTER = 3;
        static immutable FCGI_TYPE_BEGIN = 1;
        static immutable FCGI_TYPE_ABORT = 2;
        static immutable FCGI_TYPE_END = 3;
        static immutable FCGI_TYPE_PARAMS = 4;
        static immutable FCGI_TYPE_STDIN = 5;
        static immutable FCGI_TYPE_STDOUT = 6;
        static immutable FCGI_TYPE_STDERR = 7;
        static immutable FCGI_TYPE_DATA = 8;
        static immutable FCGI_TYPE_GETVALUES = 9;
        static immutable FCGI_TYPE_GETVALUES_RESULT = 10;
        static immutable FCGI_TYPE_UNKOWNTYPE = 11;
        static immutable FCGI_HEADER_SIZE = 8;
    }

    enum FCGI_STATE_SEND = 1;
    enum FCGI_STATE_ERROR = 2;
    enum FCGI_STATE_SUCCESS = 3;

    private {
        string host;
        ushort port;
        Duration timeout;
        int keepalive;
        Socket sock;
        string[string][ushort] requests;
    }

    this(string host, ushort port, int timeout, bool keepalive) {
        this.host = host;
        this.port = port;
        this.timeout = seconds(timeout);
        this.keepalive = keepalive ? 1 : 0;
        this.sock = null;
    }

    bool connect() {
       this.sock = new Socket(AddressFamily.INET, SocketType.STREAM);
       
	   this.sock.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, this.timeout);
        try {
            this.sock.connect(new InternetAddress(this.host, this.port));
        } catch (SocketException msg) {
            error(msg.toString());
            return false;
        }
        return true;
    }

    bool ensureConnection() {
        if (!this.isConnected()) {
            if (!this.connect()) {
                error("Failed to establish connection!");
                return false;
            }
        }
        return true;
    }

    bool isConnected() {
        return this.sock !is null;
    }

    void closeConnection() {
        if (this.isConnected()) {
            this.sock.close();
            this.sock = null;
        }
    }

    ubyte[] encodeFastCGIRecord(ubyte fcgi_type, ubyte[] content, ushort requestid) {
        auto length = content.length;
        return [
            cast(ubyte) FCGI_VERSION,
            cast(ubyte) fcgi_type,
            cast(ubyte) ((requestid >> 8) & 0xFF),
            cast(ubyte) (requestid & 0xFF),
            cast(ubyte) ((length >> 8) & 0xFF),
            cast(ubyte) (length & 0xFF),
            cast(ubyte) 0,
            cast(ubyte) 0
        ] ~ content;
    }

    ubyte[] encodeNameValueParams(string name, string value) {
        auto nLen = name.length;
        auto vLen = value.length;
        ubyte[] record;
        if (nLen < 128) {
            record ~= cast(ubyte) nLen;
        } else {
            record ~= cast(ubyte) (((nLen >> 24) & 0xFF) | 0x80);
            record ~= cast(ubyte) ((nLen >> 16) & 0xFF);
            record ~= cast(ubyte) ((nLen >> 8) & 0xFF);
            record ~= cast(ubyte) (nLen & 0xFF);
        }
        if (vLen < 128) {
            record ~= cast(ubyte) vLen;
        } else {
            record ~= cast(ubyte) (((vLen >> 24) & 0xFF) | 0x80);
            record ~= cast(ubyte) ((vLen >> 16) & 0xFF);
            record ~= cast(ubyte) ((vLen >> 8) & 0xFF);
            record ~= cast(ubyte) (vLen & 0xFF);
        }
        return record ~ cast(ubyte[]) name.toUTF8 ~ cast(ubyte[]) value.toUTF8;
    }

    FastCGIHeader decodeFastCGIHeader(ubyte[] stream) {
        FastCGIHeader header;

        header._version = stream[0];
        header.type = stream[1];
        header.requestId = (cast(ushort) stream[2] << 8) | stream[3];
        header.contentLength = (cast(ushort) stream[4] << 8) | stream[5];
        header.paddingLength = stream[6];
        header.reserved = stream[7];

        return header;
    }

    Nullable!FastCGIHeader decodeFastCGIRecord() {
		Nullable!FastCGIHeader ret;
		
		ubyte[FCGI_HEADER_SIZE] headerBuff;
		auto headerLen = this.sock.receive(headerBuff[]);
		
		if (headerLen != FCGI_HEADER_SIZE) {
			return ret;
		}

		auto header = decodeFastCGIHeader(headerBuff[]);
		if (header.contentLength > 0) {
			ubyte[] buffer; buffer.length = header.contentLength;
			auto bytesRead = this.sock.receive(buffer);
			if (bytesRead != header.contentLength) {
				error("Failed to read the expected content length.");
				return ret;
			}
			header.content = cast(string)buffer;
		}

		if (header.paddingLength > 0) {
			auto dummyBuffer = new ubyte[](header.paddingLength);
			auto skipped = this.sock.receive(dummyBuffer);
		}

		return Nullable!FastCGIHeader(header);
	}


    string request(string[string] nameValuePairs, string post) {

        if (!this.ensureConnection()) {
            error("connect failure! please check your fasctcgi-server !!");
            return "";
        }

        auto requestId = cast(ushort) uniform(1, (1 << 16) - 1);
        this.requests[requestId] = ["state": FCGI_STATE_SEND.to!string, "response": ""];
        ubyte[] request;
        ubyte[] beginFCGIRecordContent = [
            cast(ubyte) 0,
            cast(ubyte) FCGI_ROLE_RESPONDER,
            cast(ubyte) this.keepalive,
            cast(ubyte) 0,
            cast(ubyte) 0,
            cast(ubyte) 0,
            cast(ubyte) 0,
            cast(ubyte) 0
        ];
        request ~= this.encodeFastCGIRecord(FCGI_TYPE_BEGIN, beginFCGIRecordContent, requestId);
        ubyte[] paramsRecord;
        if (!nameValuePairs.empty) {
            foreach (name, value; nameValuePairs) {
                paramsRecord ~= this.encodeNameValueParams(name, value);
            }
        }

        if (!paramsRecord.empty) {
            request ~= this.encodeFastCGIRecord(FCGI_TYPE_PARAMS, paramsRecord, requestId);
        }
        request ~= this.encodeFastCGIRecord(FCGI_TYPE_PARAMS, null, requestId);

        if (!post.empty) {
            request ~= this.encodeFastCGIRecord(FCGI_TYPE_STDIN.to!ubyte, cast(ubyte[])post.toUTF8, requestId);
        }
        request ~= this.encodeFastCGIRecord(FCGI_TYPE_STDIN, null, requestId);

        this.sock.send(request);
        this.requests[requestId]["state"] = FCGI_STATE_SEND.to!string;
        return this.waitForResponse(requestId);
    }

    string waitForResponse(ushort requestId) {
        while (true) {
            auto response = this.decodeFastCGIRecord();
            if (response.isNull) {
                break;
            }
            if (response.get.type == FCGI_TYPE_STDOUT || response.get.type == FCGI_TYPE_STDERR) {
                if (response.get.type == FCGI_TYPE_STDERR) {
                    this.requests[requestId]["state"] = FCGI_STATE_ERROR.to!string;
                }
                if (requestId == response.get.requestId) {
                    this.requests[requestId]["response"] ~= response.get.content;
                }
            }
            if (response.get.type == FCGI_STATE_SUCCESS) {
                // 
            }
        }
		this.closeConnection();
        return this.requests[requestId]["response"];
    }

    override string toString() {
        return "fastcgi connect host:" ~ this.host ~ " port:" ~ to!string(this.port);
    }
}