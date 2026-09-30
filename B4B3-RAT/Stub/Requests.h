/*
MIT License

Copyright (c) 2020 4B4DB4B3

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "common.h"

namespace Requests {
	std::string GetRequest(const char* url, const char* useragent, const char* path = "", const char* ContentType = "");

	// Like GetRequest but enforces cert pinning:
	// - allows self-signed certs (no OS trust chain needed)
	// - rejects any cert whose subject doesn't contain expectedCN
	// - rejects any CA-signed cert (blocks TLS-inspection proxies)
	std::string GetRequestPinned(const char* url, const char* useragent, const char* path, const char* expectedCN);

	// Multipart POST of a local file to path on the same server, with cert pinning.
	// Returns the server's response body (e.g. the saved filename), or "" on failure.
	std::string PostFilePinned(const char* url, const char* useragent, const char* path,
	                           const char* expectedCN, const char* localFilePath);

	// POST a raw JSON body to path on the server, with cert pinning.
	// Used by the telemetry module to send structured events.
	void PostJsonPinned(const char* url, const char* useragent, const char* path,
	                    const char* expectedCN, const char* json_body);
}