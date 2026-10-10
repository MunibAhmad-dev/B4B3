# Module 31 — Crypto Implementation Theory

## 1. AES (Advanced Encryption Standard)

### Overview

AES operates on 128-bit (16-byte) blocks. Key sizes are 128, 192, or 256 bits. The number of rounds depends on key size: 10 (AES-128), 12 (AES-192), 14 (AES-256). Each round (except the last) applies four transformations: SubBytes, ShiftRows, MixColumns, AddRoundKey.

### Internal State

AES treats the 16-byte block as a 4x4 matrix of bytes (state array), column-major order:

```
Plaintext bytes: [b0, b1, b2, ..., b15]

State matrix (columns):
  [ b0  b4  b8  b12 ]
  [ b1  b5  b9  b13 ]
  [ b2  b6  b10 b14 ]
  [ b3  b7  b11 b15 ]
```

### Key Expansion (Key Schedule)

AES-256 takes a 32-byte key and expands it into 15 round keys (each 16 bytes = 240 bytes total).

The algorithm produces 4-byte words W[i]:
- For i < Nk (8 for AES-256): W[i] = key bytes directly
- For i >= Nk:
  - temp = W[i-1]
  - If i % Nk == 0: temp = SubWord(RotWord(temp)) XOR Rcon[i/Nk]
  - If Nk > 6 and i % Nk == 4: temp = SubWord(temp)
  - W[i] = W[i - Nk] XOR temp

RotWord rotates a 4-byte word left by one byte: [a,b,c,d] -> [b,c,d,a].

SubWord applies the S-Box substitution to each byte.

Rcon values (round constants): Rcon[1..14] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]

### SubBytes

Each byte in the state is replaced using the AES S-Box — a non-linear substitution table derived from the multiplicative inverse in GF(2^8) followed by an affine transformation.

Example S-Box lookups (first few entries):
```
S[0x00] = 0x63
S[0x01] = 0x7C
S[0x02] = 0x77
S[0x53] = 0xED
S[0xFF] = 0x16
```

Byte-level example: state byte 0x53 -> SubBytes -> 0xED

### ShiftRows

Row 0: no shift
Row 1: cyclic left shift by 1
Row 2: cyclic left shift by 2
Row 3: cyclic left shift by 3

Example:
```
Before ShiftRows:
  [ d4  e0  b8  1e ]
  [ 27  bf  b4  41 ]
  [ 11  98  5d  52 ]
  [ ae  f1  e5  30 ]

After ShiftRows:
  [ d4  e0  b8  1e ]   (row 0: unchanged)
  [ bf  b4  41  27 ]   (row 1: shifted left 1)
  [ 5d  52  11  98 ]   (row 2: shifted left 2)
  [ 30  ae  f1  e5 ]   (row 3: shifted left 3)
```

### MixColumns

Each column is treated as a polynomial over GF(2^8) and multiplied by a fixed polynomial. This provides diffusion.

The transformation matrix (applied to each column [a0, a1, a2, a3]):
```
  [ 2 3 1 1 ]   [ a0 ]
  [ 1 2 3 1 ] x [ a1 ]
  [ 1 1 2 3 ]   [ a2 ]
  [ 3 1 1 2 ]   [ a3 ]
```

Multiplication is in GF(2^8) with the AES irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B).

xtime(b): left shift by 1, if high bit was set XOR with 0x1B.
- xtime(0x57) = 0xAE
- xtime(0xAE) = 0x47  (since 0xAE has high bit set: (0xAE<<1) = 0x15C, 0x15C XOR 0x1B = 0x147 & 0xFF = 0x47)

Multiply by 2: xtime(b)
Multiply by 3: xtime(b) XOR b

MixColumns example for column [0xd4, 0xbf, 0x5d, 0x30]:
```
new[0] = 2*0xd4 XOR 3*0xbf XOR 0x5d XOR 0x30
       = 0xa8   XOR 0x6f   XOR 0x5d XOR 0x30
       = 0x04
```

### AddRoundKey

XOR the state with the current round key (16 bytes). This is the only operation that uses the key material.

### AES Modes of Operation

#### ECB (Electronic Codebook)

Each block encrypted independently with the same key. **Never use for real data** — identical plaintext blocks produce identical ciphertext blocks, revealing patterns.

```
C[i] = AES_Encrypt(K, P[i])
```

#### CBC (Cipher Block Chaining)

Each plaintext block XORed with the previous ciphertext block before encryption. Requires a random IV for the first block. IV must be unpredictable and unique per message.

```
C[0] = AES_Encrypt(K, P[0] XOR IV)
C[i] = AES_Encrypt(K, P[i] XOR C[i-1])

Decrypt:
P[0] = AES_Decrypt(K, C[0]) XOR IV
P[i] = AES_Decrypt(K, C[i]) XOR C[i-1]
```

Padding: PKCS#7 — if block needs N bytes of padding, fill with byte value N.
- "Hello" (5 bytes) padded to 16 bytes: "Hello\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"

#### CTR (Counter Mode)

Turns AES into a stream cipher. Encrypt a counter value and XOR with plaintext. No padding needed. IV is called a nonce.

```
keystream[i] = AES_Encrypt(K, nonce || counter_i)
C[i] = P[i] XOR keystream[i]
```

CTR is parallelizable and allows random access. Nonce must never be reused with the same key.

---

## 2. ChaCha20 Stream Cipher (RFC 7539)

### Overview

ChaCha20 is a stream cipher designed by Daniel J. Bernstein. It is used in TLS 1.3, WireGuard, and many other protocols. It is faster than AES on platforms without hardware AES acceleration.

### Initial State (512-bit / 16 words)

The state is 16 32-bit words arranged as:

```
cccccccc  cccccccc  cccccccc  cccccccc    (constants "expa" "nd 3" "2-by" "te k")
kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk    (key bytes 0-15)
kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk    (key bytes 16-31)
bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn    (block counter, nonce bytes 0-3, 4-7, 8-11)
```

Constants (ASCII "expand 32-byte k"):
- state[0]  = 0x61707865
- state[1]  = 0x3320646e
- state[2]  = 0x79622d32
- state[3]  = 0x6b206574

### Quarter Round

The quarter round is the core mixing operation:

```cpp
void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = rotl(d, 16);
    c += d; b ^= c; b = rotl(b, 12);
    a += b; d ^= a; d = rotl(d, 8);
    c += d; b ^= c; b = rotl(b, 7);
}
```

Where rotl(x, n) is a 32-bit left rotation.

Example — QUARTERROUND(0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567):
```
a=0x11111111, b=0x01020304, c=0x9b8d6f43, d=0x01234567
Step 1: a += b  => a=0x12131415
        d ^= a  => d=0x13312172
        d = rotl(d,16) => d=0x21721331
Step 2: c += d  => c=0xBCFF9F74 (mod 2^32)
        b ^= c  => b=0xBDFD9C70 (mod 2^32)
        b = rotl(b,12) => b=0xC70BDFDB ... (continues)
```

### Block Function

The block function generates 64 bytes of keystream:

1. Initialize 16-word state from constant, key, counter, nonce
2. Copy state to working_state
3. Apply 20 rounds (10 column rounds + 10 diagonal rounds, alternating):
   - Column rounds: QR on (0,4,8,12), (1,5,9,13), (2,6,10,14), (3,7,11,15)
   - Diagonal rounds: QR on (0,5,10,15), (1,6,11,12), (2,7,8,13), (3,4,9,14)
4. Add original state to working_state (word-wise, mod 2^32)
5. Serialize to 64 bytes (little-endian)

### Encryption

For each 64-byte block of plaintext:
1. Generate keystream block with current counter
2. XOR plaintext block with keystream block
3. Increment counter (32-bit, wraps)

For the final partial block, only XOR as many bytes as needed.

Decryption is identical — XOR ciphertext with the same keystream.

### RFC 7539 Test Vector

Key (32 bytes): 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
                10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
Nonce (12 bytes): 00 00 00 09 00 00 00 4a 00 00 00 00
Counter: 1

First 4 output words: 0xe4e7f110  0x15593bd1  0x1fdd0f50  0xc47120a3

---

## 3. RSA-2048

### Key Generation

1. Generate two random 1024-bit primes p and q
2. Compute n = p * q  (2048-bit modulus)
3. Compute Euler's totient: phi(n) = (p-1)(q-1)
4. Choose public exponent e = 65537 (0x10001) — standard choice, prime, has few 1-bits
5. Compute private exponent: d = e^(-1) mod phi(n)  (extended Euclidean algorithm)
6. Public key: (n, e)  |  Private key: (n, d) or (p, q, d, dp, dq, qInv) for CRT

### PKCS#1 v1.5 Padding (for encryption)

For a message M of length mLen, with modulus length emLen = 256 bytes:

```
EM = 0x00 || 0x02 || PS || 0x00 || M
```

Where PS is a padding string of (emLen - mLen - 3) non-zero random bytes (minimum 8 bytes).

Encryption: C = EM^e mod n
Decryption: EM = C^d mod n, then strip padding.

Note: PKCS#1 v1.5 is vulnerable to padding oracle attacks (Bleichenbacher). For new code, prefer OAEP (PKCS#1 v2.1 / RFC 8017).

### Windows CNG for RSA

```cpp
// Generate RSA-2048 key pair
BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
BCryptGenerateKeyPair(hAlg, &hKey, 2048, 0);
BCryptFinalizeKeyPair(hKey, 0);

// Export public key (BCRYPT_RSAPUBLIC_BLOB format)
// Header: BCRYPT_RSAKEY_BLOB { Magic=BCRYPT_RSAPUBLIC_MAGIC, BitLength=2048,
//          cbPublicExp=4, cbModulus=256, cbPrime1=0, cbPrime2=0 }
// Followed by: PublicExponent bytes || Modulus bytes

// Encrypt with public key (PKCS1 padding)
BCryptEncrypt(hKey, plaintext, ptLen, &paddingInfo, NULL, 0,
              ciphertext, ctLen, &cbResult, BCRYPT_PAD_PKCS1);
```

---

## 4. Key Derivation: PBKDF2 and scrypt

### PBKDF2

Password-Based Key Derivation Function 2 (RFC 2898). Derives a key from a password and salt using many iterations of a pseudorandom function (typically HMAC-SHA256).

```
DK = T1 || T2 || ... || Tdklen/hlen
Ti = F(Password, Salt, Iterations, i)
F(P, S, c, i) = U1 XOR U2 XOR ... XOR Uc

U1 = PRF(P, S || INT(i))
U2 = PRF(P, U1)
...
Uc = PRF(P, U(c-1))
```

Parameters: password, salt (16+ bytes random), iteration count (>= 100,000 for security), output key length.

Windows CNG: `BCryptDeriveKeyPBKDF2(hPrf, password, pwLen, salt, saltLen, iterations, dk, dkLen, 0)`

### scrypt

Memory-hard key derivation (designed to be expensive in memory, not just CPU). Used in some cryptocurrencies and password storage. Parameters: N (CPU/memory cost), r (block size), p (parallelization).

scrypt is not natively in Windows CNG but is available via libsodium or custom implementation.

---

## 5. Windows CNG vs OpenSSL

### Windows CNG (BCrypt API)

- Built into Windows, no external dependencies
- FIPS 140-2 validated
- Provider model: algorithm providers can be replaced
- Key objects are opaque handles (not raw bytes)

Common functions:
```
BCryptOpenAlgorithmProvider(...)    // get algorithm handle
BCryptCloseAlgorithmProvider(...)   // release algorithm handle
BCryptGenerateSymmetricKey(...)     // import raw key bytes as key object
BCryptGenerateKeyPair(...)          // generate asymmetric key pair
BCryptFinalizeKeyPair(...)          // finalize asymmetric key
BCryptExportKey(...)                // export key to byte blob
BCryptImportKeyPair(...)            // import key from blob
BCryptEncrypt(...)                  // encrypt
BCryptDecrypt(...)                  // decrypt
BCryptGenRandom(...)                // generate random bytes
BCryptDeriveKeyPBKDF2(...)          // PBKDF2 key derivation
BCryptDestroyKey(...)               // free key handle
```

Typical AES-CBC key setup:
```cpp
BCRYPT_ALG_HANDLE hAlg;
BCRYPT_KEY_HANDLE hKey;
BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                  (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
// Key object size query
DWORD cbKeyObj, cbResult;
BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObj, sizeof(cbKeyObj), &cbResult, 0);
PBYTE pbKeyObj = new BYTE[cbKeyObj];
BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObj, cbKeyObj, keyBytes, keyLen, 0);
```

### OpenSSL (EVP API)

- Cross-platform, widely used
- Consistent API via EVP (envelope) layer
- More portable but requires linking against OpenSSL

Equivalent AES-CBC in OpenSSL:
```cpp
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, ptLen);
EVP_EncryptFinal_ex(ctx, ciphertext + len, &finalLen);
EVP_CIPHER_CTX_free(ctx);
```

### Comparison Table

| Feature               | Windows CNG              | OpenSSL (EVP)          |
|-----------------------|--------------------------|------------------------|
| Platform              | Windows only             | Cross-platform         |
| External dependency   | None (OS built-in)       | Must link libssl/libcrypto |
| FIPS 140-2            | Yes (built-in)           | Needs FIPS module      |
| Algorithm support     | Common algorithms        | Very broad             |
| Key format            | Opaque handles + BLOBs   | EVP_PKEY, raw buffers  |
| Typical use case      | Windows applications     | Portable/server apps   |
| AES hardware accel    | Yes (AES-NI)             | Yes (AES-NI)           |
| RSA key gen           | BCryptGenerateKeyPair    | RSA_generate_key_ex    |
| ChaCha20              | Not natively (Win 10+)   | EVP_chacha20()         |

---

## 6. Security Considerations

**IV Reuse**: Reusing an IV with the same key in CBC or CTR mode leaks plaintext. Always generate a fresh random IV per message with `BCryptGenRandom`.

**Padding Oracles**: In CBC mode, if decryption errors are distinguishable from padding errors, an attacker can decrypt ciphertext without the key. Mitigate by using authenticated encryption (AES-GCM) or constant-time padding validation.

**Key Storage**: Raw keys must not be stored in plaintext. Use Windows DPAPI, CNG key storage providers, or hardware security modules.

**RSA Key Size**: 2048-bit is the current minimum. 4096-bit is recommended for long-term use (beyond 2030).

**Nonce uniqueness (ChaCha20/CTR)**: The nonce-counter pair must never repeat. For ChaCha20, use a random 96-bit nonce per message; counter starts at 0 or 1.
