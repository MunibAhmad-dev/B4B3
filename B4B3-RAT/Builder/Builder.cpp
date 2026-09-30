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

#include "Builder.h"

// Magic marker — must match Stub/Manager.cpp exactly
static const char CFG_MAGIC[8] = { '\xB4', '\x4B', '\xD4', '\x3E', '\x7A', '\x91', '\xC3', '\xF8' };

// XOR key derived from first 1024 bytes of the stub binary — no static key in the binary.
// Algorithm must match DeriveXorKey in Stub/Manager.cpp exactly.
static void DeriveXorKey(const char* stubPath, uint8_t key[8]) {
	memset(key, 0, 8);
	std::ifstream f(stubPath, std::ifstream::binary);
	if (!f.is_open()) return;
	char buf[1024] = { 0 };
	f.read(buf, sizeof(buf));
	f.close();
	for (int i = 0; i < 1024; i++) {
		key[i % 8] ^= (uint8_t)buf[i];
		key[i % 8]  = (key[i % 8] << 3) | (key[i % 8] >> 5);
	}
}

static void XorConfig(char* data, size_t len, const uint8_t key[8]) {
	for (size_t i = 0; i < len; i++)
		data[i] ^= key[i % 8];
}

BOOL Builder::MakeFile(const char* stub, const char* output, Builder::Settings* s) {
	std::ifstream f_stub(stub, std::ifstream::binary);
	std::ofstream f_out(output, std::ofstream::binary);

	if (!f_stub.is_open() || !f_out.is_open())
		return FALSE;

	// Copy stub binary verbatim
	f_out << f_stub.rdbuf();
	f_stub.close();

	// XOR-encode the entire Settings struct — key derived from stub binary content
	char buf[sizeof(Builder::Settings)];
	memcpy(buf, s, sizeof(Builder::Settings));

	uint8_t xorKey[8];
	DeriveXorKey(stub, xorKey);   // stub = path to Stub.exe (pre-config, first 1024 bytes)
	XorConfig(buf, sizeof(Builder::Settings), xorKey);
	SecureZeroMemory(xorKey, sizeof(xorKey));

	// Append: [magic marker][XOR-encoded config]
	f_out.write(CFG_MAGIC, sizeof(CFG_MAGIC));
	f_out.write(buf, sizeof(Builder::Settings));

	SecureZeroMemory(buf, sizeof(buf));
	f_out.close();
	return TRUE;
}