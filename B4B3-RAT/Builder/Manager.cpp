#include "Manager.h"

std::string Manager::RandomStr(int len) {
	std::string tmp_s;
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	srand((unsigned)time(NULL));

	for (int i = 0; i < len; ++i)
		tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];

	return tmp_s;
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

	// Prepend IV so the stub's DecryptStr can recover it
	return std::string(reinterpret_cast<char*>(iv), sizeof(iv)) + ciphertext;
}