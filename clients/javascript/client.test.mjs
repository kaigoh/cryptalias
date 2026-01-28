import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { resolveAddress } from "./client.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dataPath = path.join(__dirname, "..", "testdata", "jws.json");
const data = JSON.parse(fs.readFileSync(dataPath, "utf8"));

function mockFetch(responses) {
  return async (url, opts = {}) => {
    const entry = responses.shift();
    if (!entry) throw new Error(`unexpected fetch: ${url}`);
    const { status = 200, body = "", headers = {} } = entry;
    return {
      ok: status >= 200 && status < 300,
      status,
      text: async () => body,
      json: async () => JSON.parse(body),
      headers,
    };
  };
}

test("resolveAddress verifies signature", async () => {
  const config = JSON.stringify({
    resolver: { resolver_endpoint: "https://resolver.example" },
    key: data.jwk,
  });
  const fetch = mockFetch([
    { body: config },
    { body: data.jws },
  ]);
  const origFetch = globalThis.fetch;
  globalThis.fetch = fetch;
  try {
    const address = await resolveAddress("xmr", "donations$example.com");
    assert.equal(address, data.payload.address);
  } finally {
    globalThis.fetch = origFetch;
  }
});
