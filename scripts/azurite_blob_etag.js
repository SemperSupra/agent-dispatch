#!/usr/bin/env node
"use strict";
// Emulated Blob protocol ONLY. Fixed Azurite devstoreaccount1 account/key are public test constants.
// No Azure subscription, Graph identity, private data or external network client.
const crypto = require("node:crypto");
const http = require("node:http");
const assert = require("node:assert/strict");

const ACCOUNT = "devstoreaccount1";
const EMULATOR_KEY = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";
const ROOT = "http://127.0.0.1:10000/devstoreaccount1";
const CONTAINER = "/packet-qualification";
const BLOB = CONTAINER + "/artifact-v1.bin";
const VERSION = "2023-11-03";
const INITIAL = Buffer.from("public-synthetic-artifact-v1\n");
const UPDATED = Buffer.from("public-synthetic-artifact-v2\n");

function signed(method, pathname, body = Buffer.alloc(0), extra = {}) {
  assert.match(pathname, /^\/packet-qualification(?:\/artifact-v1\.bin)?(?:\?restype=container)?$/);
  assert.equal(typeof method, "string");
  const url = new URL(ROOT + pathname);
  const h = { "x-ms-date": new Date().toUTCString(), "x-ms-version": VERSION, ...extra };
  if (body.length) h["content-length"] = String(body.length);
  const contentType = h["content-type"] || "";
  const standardized = [
    method, "", "", body.length ? String(body.length) : "", "", contentType,
    "", "", h["if-match"] || "", h["if-none-match"] || "", "", ""
  ].join("\n");
  const canonicalHeaders = Object.keys(h)
    .filter(k => k.startsWith("x-ms-"))
    .sort()
    .map(k => k + ":" + String(h[k]).trim() + "\n").join("");
  let canonicalResource = "/" + ACCOUNT + url.pathname;
  const queryKeys = [...new Set(url.searchParams.keys())].sort();
  for (const k of queryKeys) {
    canonicalResource += "\n" + k.toLowerCase() + ":" +
      url.searchParams.getAll(k).sort().join(",");
  }
  const stringToSign = standardized + "\n" + canonicalHeaders + canonicalResource;
  const signature = crypto.createHmac("sha256", Buffer.from(EMULATOR_KEY, "base64"))
    .update(stringToSign).digest("base64");
  h.authorization = "SharedKey " + ACCOUNT + ":" + signature;
  return new Promise((resolve, reject) => {
    const req = http.request(url, {method, headers:h, timeout:5000}, res => {
      const chunks=[];
      let size=0;
      res.on("data", chunk => {
        size += chunk.length;
        if (size > 8192) { res.destroy(new Error("UNBOUNDED_RESPONSE")); return; }
        chunks.push(chunk);
      });
      res.on("end", () => resolve({
        status: res.statusCode, headers:res.headers,
        body:Buffer.concat(chunks)
      }));
      res.on("error", reject);
    });
    req.on("timeout", () => req.destroy(new Error("EMULATOR_TIMEOUT")));
    req.on("error", reject);
    req.end(body);
  });
}

function digest(payload) {
  return crypto.createHash("sha256").update(payload).digest("hex");
}

function check(result, expected, label) {
  assert.equal(result.status, expected, label + "_HTTP_STATUS");
}
function verifyPayload(result, expected, label) {
  check(result, 200, label);
  assert.equal(digest(result.body), digest(expected), label + "_SHA256");
  assert.deepEqual(result.body, expected, label + "_BYTES");
}

async function main() {
  const phase = process.argv[2];
  if (!["write", "recover"].includes(phase) || process.argv.length > 4)
    throw new Error("PHASE_NOT_ALLOWED");
  if (phase === "write") {
    check(await signed("PUT", CONTAINER + "?restype=container"), 201, "CREATE_CONTAINER");
    const wrote = await signed("PUT", BLOB, INITIAL, {
      "x-ms-blob-type":"BlockBlob", "content-type":"application/octet-stream", "if-none-match":"*"
    });
    check(wrote, 201, "CREATE_IF_ABSENT");
    const etag = wrote.headers.etag;
    assert.match(etag, /^"[^"]{1,128}"$/, "ETAG_FORMAT");
    verifyPayload(await signed("GET", BLOB), INITIAL, "FIRST_READ");
    const replay = await signed("PUT", BLOB, INITIAL, {
      "x-ms-blob-type":"BlockBlob", "content-type":"application/octet-stream", "if-none-match":"*"
    });
    check(replay, 412, "REPLAY_MUST_BE_BLOCKED");
    process.stdout.write(JSON.stringify({
      schema:"azurite-transport-phase/v1",phase,etag,
      sha256:digest(INITIAL), length:INITIAL.length,
      create_status:201,replay_status:replay.status, provider_access_verified:false
    }) + "\n");
  } else {
    const oldEtag = process.argv[3];
    assert.match(oldEtag, /^"[^"]{1,128}"$/, "UNTRUSTED_ETAG");
    verifyPayload(await signed("GET", BLOB), INITIAL, "RECOVER_AFTER_NEW_CLIENT");
    const stale = await signed("PUT", BLOB, UPDATED, {
      "x-ms-blob-type":"BlockBlob", "content-type":"application/octet-stream",
      "if-match":'"stale-etag"'
    });
    check(stale, 412, "STALE_ETAG_MUST_BE_BLOCKED");
    const updated = await signed("PUT", BLOB, UPDATED, {
      "x-ms-blob-type":"BlockBlob", "content-type":"application/octet-stream",
      "if-match":oldEtag
    });
    check(updated, 201, "CONDITIONAL_UPDATE");
    assert.match(updated.headers.etag, /^"[^"]{1,128}"$/, "NEW_ETAG_FORMAT");
    assert.notEqual(updated.headers.etag, oldEtag, "ETAG_MUST_CHANGE");
    verifyPayload(await signed("GET", BLOB), UPDATED, "UPDATE_RECOVER");
    const staleRead = await signed("GET", BLOB, Buffer.alloc(0), {"if-match":oldEtag});
    check(staleRead, 412, "STALE_READ_MUST_BE_BLOCKED");
    process.stdout.write(JSON.stringify({
      schema:"azurite-transport-phase/v1",phase,old_etag:oldEtag,
      etag:updated.headers.etag,sha256:digest(UPDATED),
      length:UPDATED.length,stale_write_status:stale.status,
      conditional_update_status:updated.status,stale_read_status:staleRead.status,
      recovered_from_new_process:true,provider_access_verified:false
    }) + "\n");
  }
}
main().catch(_err => {
  // Do not print request headers, emulator key, object addresses or response bodies.
  console.error("AZURITE_FIXTURE_BLOCKED");
  process.exitCode = 2;
});
